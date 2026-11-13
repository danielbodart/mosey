// Package celldiff is a prototype of D9's structured cell diffs: the server
// snapshots the emulator's screen into a Frame, and Diff(prev, cur) encodes
// what a client holding prev must do to reach cur. The client applies it
// with Apply and never parses a terminal escape sequence.
//
// Wire format (all integers are unsigned varints, strings are length-prefixed):
//
//	frame   := op*
//	op      := 'X'                        reset the style table to {0: default} and blank the cells
//	         | 'D' id fg bg attr link     define style id (fg/bg as in emu.Color);
//	                                      ids are dense: id == current table size
//	         | 'Z' w h                    resize + clear (a full repaint follows)
//	         | 'U' n                      scroll the whole screen up n rows
//	         | 'R' y x0 n run*            replace n columns of row y from x0
//	         | 'C' x y flags              cursor (flags bit0 visible)
//	         | 'T' title                  window title
//	run     := styleID count cell{count}
//	cell    := (len<<1 | wide) bytes      grapheme cluster; wide cells cover 2 columns
//
// Every text field (title, link, cell) passes the D9 allow-list in allow.go
// on the server (Snapshot sanitises) and again on the client (Apply rejects
// the whole diff). Sizes are clamped to MaxCols x MaxRows on the server
// before the emulator's Resize, and the client refuses anything larger.
//
// Rows are compared by a cached 64-bit hash, so an unchanged row costs one
// comparison; scrolls are detected by matching row hashes at an offset.
// This is a spike: no versioning, no input-mode op yet, no OSC 52 channel.
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

// Limits on what one session can make either end hold.
const (
	// MaxCols and MaxRows clamp the window size the client asks for. The
	// server applies them before the emulator's Resize (see ClampSize);
	// the client refuses a larger 'Z'. Chosen from the worst-case memory
	// per session in FINDINGS ("Worst-case memory per session").
	MaxCols = 1000
	MaxRows = 500

	maxStyles    = 1 << 16
	maxLinkBytes = 1 << 20
)

// ClampSize is what the server does to a window size from the client before
// it reaches the emulator.
func ClampSize(w, h int) (int, int) {
	return min(max(w, 1), MaxCols), min(max(h, 1), MaxRows)
}

// Styles interns styles to small ids (the server's table; the client keeps
// the matching slice in Client.Styles).
type Styles struct {
	ids       map[Style]uint32
	byID      []Style
	fresh     []uint32 // ids defined since the last Diff
	linkBytes int
	reset     bool // the next Diff starts with 'X' and a full repaint
	Degraded  int  // styles replaced because the table was full
}

func NewStyles() *Styles {
	s := &Styles{}
	s.Reset()
	s.reset = false
	return s
}

// Reset empties the table; the next Diff tells the client to do the same.
func (s *Styles) Reset() {
	s.ids = map[Style]uint32{{}: 0}
	s.byID = []Style{{}}
	s.fresh = nil
	s.linkBytes = 0
	s.reset = true
}

func (s *Styles) id(st Style) uint32 {
	if id, ok := s.ids[st]; ok {
		return id
	}
	if len(s.byID) >= maxStyles || s.linkBytes+len(st.Link) > maxLinkBytes {
		// Hostile style churn: keep the cell's colours if the link was what
		// did not fit, otherwise fall back to the default style. Memory on
		// both ends stays bounded; the screen is wrong only for a program
		// that shows more than 65,535 distinct styles at once.
		s.Degraded++
		if st.Link != "" {
			st.Link = ""
			return s.id(st)
		}
		return 0
	}
	id := uint32(len(s.byID))
	s.ids[st] = id
	s.byID = append(s.byID, st)
	s.fresh = append(s.fresh, id)
	s.linkBytes += len(st.Link)
	return id
}

// Full reports whether the table is three-quarters full; Snapshot then
// resets both ends at the start of the next frame.
func (s *Styles) Full() bool {
	return len(s.byID) >= maxStyles*3/4 || s.linkBytes >= maxLinkBytes*3/4
}

var seed = maphash.MakeSeed()

// Snapshot reads e into a Frame (styles interned into st).
func Snapshot(e emu.Emulator, st *Styles, f *Frame) *Frame {
	if st.Full() {
		st.Reset()
	}
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
			sid := st.id(Style{Fg: c.Fg, Bg: c.Bg, Attr: c.Attr, Link: SanitizeLink(c.Link)})
			text := SanitizeCell(c.Text)
			row[x] = Cell{Text: text, Wide: c.Width == 2, Style: sid}
			_, _ = mh.WriteString(text)
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
	f.CurX, f.CurY = min(max(f.CurX, 0), w-1), min(max(f.CurY, 0), h-1)
	f.Title = SanitizeTitle(e.Title())
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
	if st.reset {
		e.WriteByte('X')
		st.reset = false
		prev = nil // cells refer to the old ids: repaint everything
	}
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
//
// Apply treats the diff as hostile input from an authenticated but untrusted
// peer: every length and index is bounded before it is used, ops are
// rejected before the first 'Z', a truncated diff is an error, and on any
// error the client state is left exactly as it was (the whole diff is
// decoded and validated into a list of ops before anything is applied).
// Memory the peer can make the client hold is bounded by MaxCols*MaxRows
// cells of at most MaxCluster bytes, maxStyles styles and maxLinkBytes of
// link text.
type Client struct {
	F         *Frame
	Styles    []Style
	linkBytes int
}

var (
	errShort = errors.New("celldiff: truncated")
	errRange = errors.New("celldiff: value out of range")
	errOrder = errors.New("celldiff: op before the first resize")
	errStyle = errors.New("celldiff: bad style")
	errText  = errors.New("celldiff: text not allowed")
	errOp    = errors.New("celldiff: bad op")
)

type dec struct{ p []byte }

func (d *dec) u(limit uint64) (uint64, error) {
	v, n := binary.Uvarint(d.p)
	if n <= 0 {
		return 0, errShort
	}
	d.p = d.p[n:]
	if v > limit {
		return 0, errRange
	}
	return v, nil
}

func (d *dec) bytes(n uint64) ([]byte, error) {
	if n > uint64(len(d.p)) {
		return nil, errShort
	}
	b := d.p[:n]
	d.p = d.p[n:]
	return b, nil
}

type cellOp struct {
	x    int
	cell Cell
}

type op struct {
	kind    byte
	a, b, c int
	style   Style
	text    string
	cells   []cellOp
	y       int
}

// Apply decodes one diff into c. On error c is unchanged.
func (c *Client) Apply(p []byte) error {
	ops, err := c.parse(p)
	if err != nil {
		return err
	}
	if len(c.Styles) == 0 {
		c.Styles = []Style{{}}
	}
	for _, o := range ops {
		switch o.kind {
		case 'X':
			// Cells would refer to ids that no longer exist: blank them
			// too (the server always repaints after 'X').
			c.Styles = []Style{{}}
			c.linkBytes = 0
			if c.F != nil {
				c.F = blank(c.F.W, c.F.H)
			}
		case 'D':
			c.Styles = append(c.Styles, o.style)
			c.linkBytes += len(o.style.Link)
		case 'Z':
			c.F = blank(o.a, o.b)
		case 'U':
			c.F = shifted(c.F, o.a)
		case 'R':
			row := c.F.Rows[o.y]
			for _, co := range o.cells {
				row[co.x] = co.cell
				if co.cell.Wide && co.x+1 < c.F.W {
					row[co.x+1] = Cell{}
				}
			}
		case 'C':
			c.F.CurX, c.F.CurY, c.F.CurVis = o.a, o.b, o.c == 1
		case 'T':
			c.F.Title = o.text
		}
	}
	return nil
}

// parse validates the whole diff against the state each op will see, and
// returns the ops; it does not touch c.
func (c *Client) parse(p []byte) ([]op, error) {
	d := &dec{p: p}
	w, h := 0, 0
	if c.F != nil {
		w, h = c.F.W, c.F.H
	}
	nStyles, linkBytes := len(c.Styles), c.linkBytes
	if nStyles == 0 {
		nStyles = 1 // style 0 is always the default
	}
	var ops []op
	for len(d.p) > 0 {
		kind := d.p[0]
		d.p = d.p[1:]
		o := op{kind: kind}
		switch kind {
		case 'X':
			nStyles, linkBytes = 1, 0
		case 'D':
			id, err := d.u(maxStyles)
			if err != nil {
				return nil, err
			}
			if id != uint64(nStyles) || nStyles >= maxStyles {
				return nil, errStyle
			}
			var v [3]uint64
			for i, lim := range []uint64{1<<32 - 1, 1<<32 - 1, 1<<16 - 1} {
				if v[i], err = d.u(lim); err != nil {
					return nil, err
				}
			}
			n, err := d.u(MaxLink)
			if err != nil {
				return nil, err
			}
			lb, err := d.bytes(n)
			if err != nil {
				return nil, err
			}
			link := string(lb)
			if !ValidLink(link) || linkBytes+len(link) > maxLinkBytes {
				return nil, errStyle
			}
			o.style = Style{Fg: emu.Color(v[0]), Bg: emu.Color(v[1]), Attr: emu.Attr(v[2]), Link: link}
			nStyles++
			linkBytes += len(link)
		case 'Z':
			cw, err := d.u(MaxCols)
			if err != nil {
				return nil, err
			}
			ch, err := d.u(MaxRows)
			if err != nil {
				return nil, err
			}
			if cw == 0 || ch == 0 {
				return nil, errRange
			}
			w, h = int(cw), int(ch)
			o.a, o.b = w, h
		case 'U':
			if w == 0 {
				return nil, errOrder
			}
			n, err := d.u(uint64(h))
			if err != nil {
				return nil, err
			}
			if n == 0 {
				return nil, errRange
			}
			o.a = int(n)
		case 'R':
			if w == 0 {
				return nil, errOrder
			}
			y, err := d.u(uint64(h - 1))
			if err != nil {
				return nil, err
			}
			x0, err := d.u(uint64(w - 1))
			if err != nil {
				return nil, err
			}
			n, err := d.u(uint64(w) - x0)
			if err != nil {
				return nil, err
			}
			if n == 0 {
				return nil, errRange
			}
			o.y = int(y)
			x, end := int(x0), int(x0)+int(n)
			for x < end {
				sid, err := d.u(uint64(nStyles - 1))
				if err != nil {
					return nil, err
				}
				cnt, err := d.u(uint64(end - x))
				if err != nil {
					return nil, err
				}
				if cnt == 0 {
					return nil, errRange
				}
				for i := uint64(0); i < cnt; i++ {
					if x >= end {
						return nil, errRange
					}
					l, err := d.u(MaxCluster<<1 | 1)
					if err != nil {
						return nil, err
					}
					tb, err := d.bytes(l >> 1)
					if err != nil {
						return nil, err
					}
					t := string(tb)
					if !ValidCell(t) {
						return nil, errText
					}
					wide := l&1 == 1
					o.cells = append(o.cells, cellOp{x: x, cell: Cell{Text: t, Wide: wide, Style: uint32(sid)}})
					x++
					if wide {
						x++
					}
				}
			}
			// a run ends exactly at end, except a wide cell in the last
			// column, whose continuation would fall off the row
			if x > end+1 || (x == end+1 && (end != w || !o.cells[len(o.cells)-1].cell.Wide)) {
				return nil, errRange
			}
		case 'C':
			if w == 0 {
				return nil, errOrder
			}
			x, err := d.u(uint64(w - 1))
			if err != nil {
				return nil, err
			}
			y, err := d.u(uint64(h - 1))
			if err != nil {
				return nil, err
			}
			v, err := d.u(1)
			if err != nil {
				return nil, err
			}
			o.a, o.b, o.c = int(x), int(y), int(v)
		case 'T':
			if w == 0 {
				return nil, errOrder
			}
			n, err := d.u(MaxTitle)
			if err != nil {
				return nil, err
			}
			tb, err := d.bytes(n)
			if err != nil {
				return nil, err
			}
			if !ValidTitle(string(tb)) {
				return nil, errText
			}
			o.text = string(tb)
		default:
			return nil, errOp
		}
		ops = append(ops, o)
	}
	return ops, nil
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
