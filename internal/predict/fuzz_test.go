package predict

import (
	"testing"
	"time"

	"github.com/danielbodart/mosey/internal/screen"
)

// fuzzSource reads the fuzzer's bytes as choices, and runs dry as zeros.
type fuzzSource struct{ b []byte }

func (s *fuzzSource) byte() byte {
	if len(s.b) == 0 {
		return 0
	}
	c := s.b[0]
	s.b = s.b[1:]
	return c
}

func (s *fuzzSource) n(k int) int { return int(s.byte()) % k }

// The glyphs a hostile server's cells and a user's keys are drawn from:
// ASCII, a wide character, an ambiguous one, a combining mark, controls,
// arrows, backspace and the paste markers.
var fuzzTexts = []string{"a", "b", " ", "漢", "●", "é", "😀"}
var fuzzKeys = []string{"a", "b", " ", "漢", "😀", "\x7f", "\x08", "\x1b[D", "\x1b[C", "\x1bOD", "\r", "\t", "\x1b", "\x1b[200~", "\x1b[201~", "é", "א", "ab", "\x15"}
var fuzzStyles = []screen.Style{{}, grey, {Attrs: screen.Reverse}, {Fg: screen.Palette(1), Attrs: screen.Bold}}

// fuzzGrid is a hostile server's screen: any size, any cells that keep the
// grid's invariants, any cursor, and any echo fields.
func fuzzGrid(s *fuzzSource, cols, rows int) *screen.Grid {
	g := screen.NewGrid(cols, rows)
	for range s.n(40) {
		x, y := s.n(cols), s.n(rows)
		t := fuzzTexts[s.n(len(fuzzTexts))]
		st := fuzzStyles[s.n(len(fuzzStyles))]
		w := 1
		if t == "漢" || t == "😀" {
			w = 2
		}
		if x+w > cols {
			continue
		}
		if t == " " {
			t = ""
		}
		// Keep G2: never write over half of a wide character.
		if c := g.Cell(x, y); c.Width == 0 || c.Width == 2 {
			continue
		}
		if w == 2 && g.Cell(x+1, y).Width != 1 {
			continue
		}
		g.SetCell(x, y, screen.Cell{Text: t, Width: uint8(w), Style: st})
		if w == 2 {
			g.SetCell(x+1, y, screen.Cell{Style: st})
		}
	}
	g.Cursor = screen.Cursor{X: s.n(cols), Y: s.n(rows), Visible: s.n(2) == 0}
	return g
}

// FuzzEngine drives an engine with any keys and any server, and checks
// prediction.md §12: every overlay is a valid grid with its cursor inside,
// the bounds hold, nothing is drawn from an epoch that was never
// confirmed, and nothing is drawn while the last frame had echo off.
func FuzzEngine(f *testing.F) {
	f.Add([]byte{1, 20, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte("\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x01\x02\x02\x00\x02\x00\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x05\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		s := &fuzzSource{b: data}
		e := New(Config{Mode: Mode(s.n(3))})
		e.SetRTT(time.Duration(s.n(200)) * time.Millisecond)
		var n uint64
		cols, rows := 1+s.n(40), 1+s.n(6)
		echoOffKeys := map[uint64]bool{}
		for steps := 0; len(s.b) > 0 && steps < 2000; steps++ {
			switch s.n(5) {
			case 0, 1:
				n++
				var b []byte
				for range 1 + s.n(4) {
					b = append(b, fuzzKeys[s.n(len(fuzzKeys))]...)
				}
				if e.echoOff {
					echoOffKeys[n] = true
				}
				e.Key(n, b)
			case 2:
				if s.n(8) == 0 {
					cols, rows = 1+s.n(40), 1+s.n(6)
				}
				g := fuzzGrid(s, cols, rows)
				// Echo fields that jump, fall, or exceed what was sent.
				g.EchoAck = uint64(s.n(int(n) + 3))
				g.EchoApplied = g.EchoAck + uint64(s.n(4))
				if s.n(16) == 0 {
					g.EchoAck, g.EchoApplied = 1<<62, 1<<63
				}
				g.EchoOff = s.n(6) == 0
				e.Frame(g)
			case 3:
				n += uint64(1 + s.n(3))
				e.Skip(n)
			case 4:
				e.SetRTT(time.Duration(s.n(200)) * time.Millisecond)
			}
			check(t, e, echoOffKeys)
		}
	})
}

func check(t *testing.T, e *Engine, echoOffKeys map[uint64]bool) {
	t.Helper()
	if len(e.cells) > MaxPending || len(e.cursors) > maxCursors || len(e.bumps) > maxBumps {
		t.Fatalf("bounds: %d cells, %d cursors, %d bumps", len(e.cells), len(e.cursors), len(e.bumps))
	}
	if len(e.confirmed) > MaxPending+maxCursors+1 {
		t.Fatalf("%d confirmed epochs kept", len(e.confirmed))
	}
	v := e.Overlay()
	if v == nil {
		return
	}
	if err := v.Valid(); err != nil {
		t.Fatalf("overlay: %v", err)
	}
	if e.echoOff && v != e.frame {
		t.Fatal("something was drawn while echo was off")
	}
	for at, p := range e.cells {
		_, ok := e.confirmed[p.epoch]
		if ok && echoOffKeys[p.n] {
			t.Fatalf("a key typed with echo off is displayed at %v", at)
		}
	}
	if v != e.frame {
		for at, p := range e.cells {
			if _, ok := e.confirmed[p.epoch]; !ok && !sameGlyph(v.Cell(at.x, at.y), e.frame.Cell(at.x, at.y)) {
				// A cell only an unconfirmed epoch predicted must show the
				// frame (or what mend made of a confirmed neighbour).
				if v.Cell(at.x, at.y) == p.cell {
					t.Fatalf("cell %v of an unconfirmed epoch is drawn", at)
				}
			}
		}
	}
	for q := range uint64(LogSize) {
		if l := e.log[q]; l.b != nil && echoOffKeys[l.n] {
			t.Fatalf("event %d typed with echo off is logged", l.n)
		}
	}
}
