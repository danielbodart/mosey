package celldiff

import (
	"fmt"
	"math/rand/v2"
	"testing"

	"mosey.spike/s2-terminal/emu"
)

// TestRoundTrip drives a server emulator with mixed output and checks that a
// client applying only diffs always reaches the same frame.
func TestRoundTrip(t *testing.T) {
	for _, name := range []string{"tuios", "xtermgo"} {
		f, ok := emu.Get(name)
		if !ok {
			continue
		}
		t.Run(name, func(t *testing.T) {
			e := f.New(80, 24)
			st := NewStyles()
			var prev *Frame
			cl := &Client{}
			rng := rand.New(rand.NewPCG(1, 2))
			chunks := []string{
				"hello \x1b[1;31mred\x1b[0m world\r\n", "漢字👍🏽é\r\n", "\x1b[2J\x1b[H",
				"\x1b[10;10H\x1b[7mrev\x1b[0m", "\x1b]2;title\x07", "\x1b[?25l", "\x1b[?25h",
				"\x1b]8;;http://x\x1b\\link\x1b]8;;\x1b\\", "\x1b[38;2;10;20;30mtc\x1b[0m",
			}
			for i := 0; i < 3000; i++ {
				switch rng.IntN(20) {
				case 0:
					e.Resize(20+rng.IntN(100), 5+rng.IntN(40))
				case 1, 2:
					for j := 0; j < rng.IntN(60); j++ {
						e.Write([]byte("line of scrolling output\r\n"))
					}
				default:
					e.Write([]byte(chunks[rng.IntN(len(chunks))]))
				}
				cur := Snapshot(e, st, nil)
				d := Diff(prev, cur, st)
				if err := cl.Apply(d); err != nil {
					t.Fatalf("step %d: %v", i, err)
				}
				if !Equal(cl.F, cur) {
					t.Fatalf("step %d: client diverged: %s", i, firstDiff(cl.F, cur))
				}
				prev = cur
			}
		})
	}
}

func firstDiff(a, b *Frame) string {
	if a.W != b.W || a.H != b.H {
		return "size"
	}
	if a.CurX != b.CurX || a.CurY != b.CurY || a.CurVis != b.CurVis {
		return fmt.Sprintf("cursor client=%d,%d,%v server=%d,%d,%v", a.CurX, a.CurY, a.CurVis, b.CurX, b.CurY, b.CurVis)
	}
	if a.Title != b.Title {
		return "title"
	}
	for y := range a.Rows {
		for x := range a.Rows[y] {
			if a.Rows[y][x] != b.Rows[y][x] {
				return fmt.Sprintf("cell %d,%d client=%+v server=%+v", x, y, a.Rows[y][x], b.Rows[y][x])
			}
		}
	}
	return ""
}
