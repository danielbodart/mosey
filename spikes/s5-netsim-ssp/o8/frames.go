// Package o8 measures compression of realistic screen-diff frames (open
// question O8). Frames are made by replaying captured terminal byte streams
// (cmd/capture) through a real terminal emulator (charmbracelet/x/vt; we
// never write our own, D19) on SSP's frame schedule, then encoding the cell
// difference between consecutive frames with a simple structured encoding.
// S2's real encoding was not available; this one is in the same spirit:
// changed cells only, with style runs, no escape sequences.
package o8

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"time"

	uv "github.com/charmbracelet/ultraviolet"
	"github.com/charmbracelet/x/vt"
)

// Chunk is one write from the program, at offset T.
type Chunk struct {
	T    time.Duration
	Data []byte
}

// LoadCapture reads a cmd/capture file.
func LoadCapture(path string) ([]Chunk, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []Chunk
	for len(b) >= 12 {
		t := time.Duration(binary.BigEndian.Uint64(b)) * time.Microsecond
		n := int(binary.BigEndian.Uint32(b[8:]))
		b = b[12:]
		if n > len(b) {
			break
		}
		out = append(out, Chunk{t, b[:n]})
		b = b[n:]
	}
	return out, nil
}

type cell struct {
	content string
	style   string
}

type snapshot struct {
	w, h   int
	cells  []cell
	cx, cy int
}

func snap(e *vt.Emulator) snapshot {
	w, h := e.Width(), e.Height()
	s := snapshot{w: w, h: h, cells: make([]cell, w*h)}
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			c := e.CellAt(x, y)
			if c == nil {
				continue
			}
			st := c.Style
			s.cells[y*w+x] = cell{c.Content, styleKey(&st)}
		}
	}
	p := e.CursorPosition()
	s.cx, s.cy = p.X, p.Y
	return s
}

func styleKey(s *uv.Style) string {
	if s.IsZero() {
		return ""
	}
	return s.String()
}

// encodeDiff encodes old -> cur: cursor, then per changed row: row+1,
// then runs (start col, run length, cells). Within a run a style change is
// 0x00, uvarint len, style bytes; otherwise cell content (UTF-8, a space
// for empty). Terminated by a 0 row.
func encodeDiff(old, cur snapshot) []byte {
	var b bytes.Buffer
	var tmp [binary.MaxVarintLen64]byte
	uvar := func(v uint64) { b.Write(tmp[:binary.PutUvarint(tmp[:], v)]) }
	uvar(uint64(cur.cx))
	uvar(uint64(cur.cy))
	for y := 0; y < cur.h; y++ {
		rowStarted := false
		x := 0
		for x < cur.w {
			i := y*cur.w + x
			if old.cells[i] == cur.cells[i] {
				x++
				continue
			}
			// a run: extend while cells differ, bridging gaps of <= 3 equal cells
			end := x + 1
			for end < cur.w {
				j := y*cur.w + end
				if old.cells[j] != cur.cells[j] {
					end++
					continue
				}
				gap := 0
				for end+gap < cur.w && gap <= 3 && old.cells[y*cur.w+end+gap] == cur.cells[y*cur.w+end+gap] {
					gap++
				}
				if gap <= 3 && end+gap < cur.w {
					end += gap
					continue
				}
				break
			}
			if !rowStarted {
				uvar(uint64(y + 1))
				rowStarted = true
			}
			uvar(uint64(x + 1))
			uvar(uint64(end - x))
			style := "\xff" // force a style record at run start
			for k := x; k < end; k++ {
				c := cur.cells[y*cur.w+k]
				if c.style != style {
					b.WriteByte(0)
					uvar(uint64(len(c.style)))
					b.WriteString(c.style)
					style = c.style
				}
				if c.content == "" {
					b.WriteByte(' ')
				} else {
					b.WriteString(c.content)
				}
			}
			x = end
		}
		if rowStarted {
			uvar(0) // end of row runs
		}
	}
	uvar(0)
	return b.Bytes()
}

// EmulatorPanics counts panics recovered from the emulator's Write.
// charmbracelet/x/vt v0.1.0 panics (index out of range in ultraviolet's
// buffer) when output written for 120x40 is replayed at 80x24. That is a
// security finding for spike S2: any program's output (or a file the user
// cats) can panic the server's emulator. After a panic the emulator's
// state is undefined, so Frames stops the session there (ExcludedFrames
// counts what was dropped) rather than carrying on with suspect frames.
var EmulatorPanics, ExcludedChunks int

func safeWrite(e *vt.Emulator, b []byte) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			EmulatorPanics++
			ok = false
		}
	}()
	e.Write(b)
	return true
}

// ScreenText serialises a snapshot's characters row by row: the dictionary
// for FlateDelta (what the receiver already has).
func ScreenText(s snapshot) []byte {
	var b bytes.Buffer
	for y := 0; y < s.h; y++ {
		for x := 0; x < s.w; x++ {
			c := s.cells[y*s.w+x].content
			if c == "" {
				c = " "
			}
			b.WriteString(c)
		}
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// Frames replays a capture at w x h and returns the diff frames SSP's
// server would send with the given frame interval (collection interval
// 8 ms after the first write, then at most one frame per interval), each
// diffed against the previous frame.
func Frames(chunks []Chunk, w, h int, interval time.Duration) [][]byte {
	fr, _ := FramesWithBase(chunks, w, h, interval)
	return fr
}

// FramesWithBase is Frames, also returning for each frame ScreenText of
// the screen it is diffed from.
func FramesWithBase(chunks []Chunk, w, h int, interval time.Duration) ([][]byte, [][]byte) {
	var bases [][]byte
	e := vt.NewEmulator(w, h)
	go io.Copy(io.Discard, e) // drain replies (DA, DSR) so writes never block
	defer e.Close()
	prev := snap(e)
	var out [][]byte
	const collect = 8 * time.Millisecond
	var lastFrame time.Duration = -time.Hour
	i := 0
	for i < len(chunks) {
		first := chunks[i].T
		at := max(first+collect, lastFrame+interval)
		broken := false
		for i < len(chunks) && chunks[i].T <= at {
			if !safeWrite(e, chunks[i].Data) {
				broken = true
				break
			}
			i++
		}
		if broken {
			ExcludedChunks += len(chunks) - i
			break
		}
		cur := snap(e)
		d := encodeDiff(prev, cur)
		if len(d) > 3 {
			out = append(out, d)
			bases = append(bases, ScreenText(prev))
		}
		prev = cur
		lastFrame = at
	}
	return out, bases
}
