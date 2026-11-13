// Package celldiff is a prototype of D9's structured cell diffs: the server
// snapshots the emulator's screen into a Frame, and Diff(prev, cur) encodes
// what a client holding prev must do to reach cur. The client applies it
// with Apply and never parses a terminal escape sequence.
//
// Wire format (all integers are unsigned varints, strings are length-prefixed):
//
//	frame   := op* opEnd
//	op      := 'Z' w h                    resize + clear (a full repaint follows)
//	         | 'U' n                      scroll the whole screen up n rows
//	         | 'D' id fg bg attr link     define style id (fg/bg as in emu.Color)
//	         | 'R' y x0 n run*            replace n columns of row y from x0
//	         | 'C' x y flags              cursor (flags bit0 visible)
//	         | 'T' title                  window title (already allow-listed)
//	         | 'M' modes                  bitset of input modes the client must mirror
//	run     := styleID count cell{count}
//	cell    := (len<<1 | wide) bytes      grapheme cluster; wide cells cover 2 columns
//
// Rows are compared by a cached 64-bit hash, so an unchanged row costs one
// comparison; scrolls are detected by matching row hashes at an offset.
// This is a spike: no versioning, no bounds on style-table growth beyond a
// reset, no OSC 52/8 event channel.
package celldiff

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/maphash"

	"mosey.spike/s2-terminal/emu"
)

type Style struct {
	Fg, Bg emu.Color
	Attr   emu.Attr
	Link   string
}

type Cell struct {
	Text  string
	Wide  bool
	Style uint32
}

// Frame is one screen state.
type Frame struct {
	W, H   int
	Rows   [][]Cell // H rows of W cells; the cell after a wide cell is a zero Cell
	hash   []uint64
	CurX   int
	CurY   int
	CurVis bool
	Title  string
	Modes  uint32
}

// Styles interns styles to small ids. Server and client each keep one.
type Styles struct {
	ids   map[Style]uint32
	byID  []Style
	fresh []uint32 // ids defined since the last Diff
}

const maxStyles = 1 << 16

func NewStyles() *Styles {
	s := &Styles{ids: map[Style]uint32{}}
	s.id(Style{})
	s.fresh = nil
	return s
}

func (s *Styles) id(st Style) uint32 {
	if id, ok := s.ids[st]; ok {
		return id
	}
	id := uint32(len(s.byID))
	s.ids[st] = id
	s.byID = append(s.byID, st)
	s.fresh = append(s.fresh, id)
	return id
}

// Full reports whether the table hit its cap; the caller then resets both
// ends with a full repaint (hostile style churn must not grow memory).
func (s *Styles) Full() bool { return len(s.byID) >= maxStyles }

var seed = maphash.MakeSeed()

// Snapshot reads e into a Frame (styles interned into st).
func Snapshot(e emu.Emulator, st *Styles, f *Frame) *Frame {
	w, h := e.Size()
	if f == nil || f.W != w || f.H != h {
		f = &Frame{W: w, H: h, Rows: make([][]Cell, h), hash: make([]uint64, h)}
		for y := range f.Rows {
			f.Rows[y] = make([]Cell, w)
		}
	}
	var mh maphash.Hash
	for y := 0; y < h; y++ {
		row := f.Rows[y]
		mh.SetSeed(seed)
		for x := 0; x < w; x++ {
			c := e.CellAt(x, y)
			if c.Width == 0 && x > 0 && row[x-1].Wide {
				row[x] = Cell{}
				_ = mh.WriteByte(0xff)
				continue
			}
			sid := st.id(Style{Fg: c.Fg, Bg: c.Bg, Attr: c.Attr, Link: c.Link})
			row[x] = Cell{Text: c.Text, Wide: c.Width == 2, Style: sid}
			_, _ = mh.WriteString(c.Text)
			var b [5]byte
			binary.LittleEndian.PutUint32(b[:], sid)
			if c.Width == 2 {
				b[4] = 1
			}
			_, _ = mh.Write(b[:])
		}
		f.hash[y] = mh.Sum64()
	}
	f.CurX, f.CurY, f.CurVis = e.Cursor()
	f.Title = e.Title()
	return f
}

// Clone deep-copies a frame (the server keeps the last acknowledged one).
func (f *Frame) Clone() *Frame {
	g := *f
	g.Rows = make([][]Cell, f.H)
	for y := range f.Rows {
		g.Rows[y] = append([]Cell(nil), f.Rows[y]...)
	}
	g.hash = append([]uint64(nil), f.hash...)
	return &g
}

type enc struct{ bytes.Buffer }

func (e *enc) u(v uint64) {
	var b [binary.MaxVarintLen64]byte
	e.Write(b[:binary.PutUvarint(b[:], v)])
}
func (e *enc) s(v string) { e.u(uint64(len(v))); e.WriteString(v) }

// Diff encodes the ops taking a client from prev (nil: blank screen of
// unknown size) to cur. st.fresh lists styles the client has not seen.
func Diff(prev, cur *Frame, st *Styles) []byte {
	var e enc
	for _, id := range st.fresh {
		s := st.byID[id]
		e.WriteByte('D')
		e.u(uint64(id))
		e.u(uint64(s.Fg))
		e.u(uint64(s.Bg))
		e.u(uint64(s.Attr))
		e.s(s.Link)
	}
	st.fresh = st.fresh[:0]

	base := prev
	if prev == nil || prev.W != cur.W || prev.H != cur.H {
		e.WriteByte('Z')
		e.u(uint64(cur.W))
		e.u(uint64(cur.H))
		base = blank(cur.W, cur.H)
	} else if n := scrollUp(prev, cur); n > 0 {
		e.WriteByte('U')
		e.u(uint64(n))
		base = shifted(prev, n)
	}
	for y := 0; y < cur.H; y++ {
		if base.hash[y] == cur.hash[y] && base.hash[y] != 0 {
			continue
		}
		a, b := base.Rows[y], cur.Rows[y]
		x0, x1 := 0, cur.W-1
		for x0 < cur.W && a[x0] == b[x0] {
			x0++
		}
		if x0 == cur.W {
			continue
		}
		for x1 > x0 && a[x1] == b[x1] {
			x1--
		}
		// never start or end inside a wide cell
		if x0 > 0 && b[x0] == (Cell{}) && b[x0-1].Wide {
			x0--
		}
		if x1+1 < cur.W && b[x1].Wide {
			x1++
		}
		e.WriteByte('R')
		e.u(uint64(y))
		e.u(uint64(x0))
		e.u(uint64(x1 - x0 + 1))
		for x := x0; x <= x1; {
			sid := b[x].Style
			n := 0
			j := x
			for j <= x1 && b[j].Style == sid {
				n++
				if b[j].Wide {
					j += 2
				} else {
					j++
				}
			}
			e.u(uint64(sid))
			e.u(uint64(n))
			for k := x; k < j; {
				c := b[k]
				l := uint64(len(c.Text)) << 1
				if c.Wide {
					l |= 1
				}
				e.u(l)
				e.WriteString(c.Text)
				if c.Wide {
					k += 2
				} else {
					k++
				}
			}
			x = j
		}
	}
	full := prev == nil || prev.W != cur.W || prev.H != cur.H
	if full || prev.CurX != cur.CurX || prev.CurY != cur.CurY || prev.CurVis != cur.CurVis {
		e.WriteByte('C')
		e.u(uint64(cur.CurX))
		e.u(uint64(cur.CurY))
		v := uint64(0)
		if cur.CurVis {
			v = 1
		}
		e.u(v)
	}
	if full || prev.Title != cur.Title {
		e.WriteByte('T')
		e.s(cur.Title)
	}
	return e.Bytes()
}

func blank(w, h int) *Frame {
	f := &Frame{W: w, H: h, Rows: make([][]Cell, h), hash: make([]uint64, h)}
	for y := range f.Rows {
		f.Rows[y] = make([]Cell, w)
	}
	return f
}

// scrollUp finds n such that cur's rows [0, H-n) equal prev's [n, H) for at
// least half the screen, preferring the n matching most rows.
func scrollUp(prev, cur *Frame) int {
	h := cur.H
	best, bestN := 0, 0
	for n := 1; n < h; n++ {
		m := 0
		for y := 0; y+n < h; y++ {
			if cur.hash[y] == prev.hash[y+n] {
				m++
			}
		}
		if m > bestN {
			best, bestN = n, m
		}
	}
	// Only worth it if more rows match after the shift than without it.
	same := 0
	for y := 0; y < h; y++ {
		if cur.hash[y] == prev.hash[y] {
			same++
		}
	}
	if bestN > same && bestN >= h/4 {
		return best
	}
	return 0
}

func shifted(prev *Frame, n int) *Frame {
	f := blank(prev.W, prev.H)
	f.CurX, f.CurY, f.CurVis, f.Title, f.Modes = prev.CurX, prev.CurY, prev.CurVis, prev.Title, prev.Modes
	for y := 0; y+n < prev.H; y++ {
		copy(f.Rows[y], prev.Rows[y+n])
		f.hash[y] = prev.hash[y+n]
	}
	return f
}

// Client is the receiving side: a frame and a style table, no VT parser.
type Client struct {
	F      *Frame
	Styles []Style
}

var errShort = errors.New("celldiff: truncated")

// Apply decodes one diff into c.
func (c *Client) Apply(p []byte) error {
	r := bytes.NewReader(p)
	u := func() uint64 {
		v, err := binary.ReadUvarint(r)
		if err != nil {
			panic(errShort)
		}
		return v
	}
	s := func() string {
		n := u()
		if n > uint64(r.Len()) {
			panic(errShort)
		}
		b := make([]byte, n)
		_, _ = r.Read(b)
		return string(b)
	}
	defer func() {
		if x := recover(); x != nil && x != errShort {
			panic(x)
		}
	}()
	for r.Len() > 0 {
		op, _ := r.ReadByte()
		switch op {
		case 'D':
			id := u()
			st := Style{Fg: emu.Color(u()), Bg: emu.Color(u()), Attr: emu.Attr(u()), Link: s()}
			for uint64(len(c.Styles)) <= id {
				c.Styles = append(c.Styles, Style{})
			}
			c.Styles[id] = st
		case 'Z':
			w, h := int(u()), int(u())
			if w > 4096 || h > 4096 {
				return errors.New("celldiff: size out of range")
			}
			c.F = blank(w, h)
		case 'U':
			c.F = shifted(c.F, int(u()))
		case 'R':
			y, x0, n := int(u()), int(u()), int(u())
			if y >= c.F.H || x0+n > c.F.W {
				return errors.New("celldiff: row op out of range")
			}
			row := c.F.Rows[y]
			x := x0
			for x < x0+n {
				sid, cnt := uint32(u()), int(u())
				for i := 0; i < cnt; i++ {
					l := u()
					wide := l&1 == 1
					t := make([]byte, l>>1)
					_, _ = r.Read(t)
					if x >= c.F.W {
						return errors.New("celldiff: run past row end")
					}
					row[x] = Cell{Text: string(t), Wide: wide, Style: sid}
					x++
					if wide && x < c.F.W {
						row[x] = Cell{}
						x++
					}
				}
			}
		case 'C':
			c.F.CurX, c.F.CurY, c.F.CurVis = int(u()), int(u()), u() == 1
		case 'T':
			c.F.Title = s()
		default:
			return errors.New("celldiff: bad op")
		}
	}
	return nil
}

// Equal reports whether two frames show the same cells, cursor and title.
func Equal(a, b *Frame) bool {
	if a.W != b.W || a.H != b.H || a.CurX != b.CurX || a.CurY != b.CurY || a.CurVis != b.CurVis || a.Title != b.Title {
		return false
	}
	for y := range a.Rows {
		for x := range a.Rows[y] {
			if a.Rows[y][x] != b.Rows[y][x] {
				return false
			}
		}
	}
	return true
}
