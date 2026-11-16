//go:build linux

package e2e

import (
	"testing"

	"tuios.dev/vt"

	"github.com/danielbodart/mosey/internal/emu"
	"github.com/danielbodart/mosey/internal/render"
	"github.com/danielbodart/mosey/internal/screen"
)

// localTerminal is the user's terminal for a test that resizes it: a
// reference emulator with a scrollback, written to as the renderer writes
// and resized when the user would resize it. The client never parses it
// (D9); the test does, to see what the user would.
type localTerminal struct{ t vt.Terminal }

func (l *localTerminal) Write(p []byte) (int, error) {
	_, _ = l.t.Write(p)
	l.t.TakeResponses()
	return len(p), nil
}

// TestAResizeLosesOrDoublesAtMostTheRowsItMoves pins down what history
// does across a local resize, which screen.md §8.7 leaves to the local
// terminal's own reflow: a shrink of k rows can print up to k lines twice
// (the terminal pushes its top rows into its scrollback, and the server's
// emulator sends the same rows as history), and a grow of k rows can lose
// up to k lines (the terminal pulls lines back out of its scrollback onto
// the screen, and the full redraw paints over them). Nothing else is lost
// or doubled, and the order holds.
func TestAResizeLosesOrDoublesAtMostTheRowsItMoves(t *testing.T) {
	const cols, rows, small, big = 20, 6, 3, 9
	e, err := emu.New(cols, rows, emu.Options{ScrollbackCells: emu.DefaultScrollbackCells})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	local := &localTerminal{t: vt.NewWithScrollback(cols, rows, 100_000)}
	defer local.t.Close()
	r := render.New(local, render.Capabilities{UTF8: true})
	r.Resize(cols, rows)
	if err := r.Enter(); err != nil {
		t.Fatal(err)
	}
	g := screen.NewGrid(0, 0)
	draw := func() {
		t.Helper()
		e.Snapshot(g)
		if err := r.Render(g); err != nil {
			t.Fatal(err)
		}
	}
	resize := func(c, rw int) {
		e.Resize(c, rw)
		local.t.Resize(c, rw)
		r.Resize(c, rw)
		draw()
	}
	// The renderer draws the empty screen first, as a client that was
	// already attached would, so its first frame's one screenful (§8.7)
	// does not cut lines 1–30: every line is then the resize's to lose.
	draw()
	e.Write([]byte(numbered(1, 30)))
	draw()
	resize(cols, small)
	e.Write([]byte(numbered(31, 60)))
	draw()
	resize(cols, big)
	e.Write([]byte(numbered(61, 90)))
	draw()

	got := numbers(contents(local.t))
	seen := map[int]int{}
	last := 0
	for _, v := range got {
		seen[v]++
		if seen[v] == 1 {
			if v < last {
				t.Errorf("line-%04d after line-%04d", v, last)
			}
			last = v
		}
	}
	doubled, lost := 0, 0
	for i := 1; i <= 90; i++ {
		switch seen[i] {
		case 0:
			lost++
		case 1:
		default:
			doubled += seen[i] - 1
		}
	}
	if doubled > rows-small {
		t.Errorf("%d lines doubled; the shrink moved %d rows", doubled, rows-small)
	}
	if lost > big-small {
		t.Errorf("%d lines lost; the grow moved %d rows", lost, big-small)
	}
	// Measured with tuios v0.3.2 as the local terminal: 3 doubled and 6
	// lost, each bound exactly.
	t.Logf("doubled %d, lost %d", doubled, lost)
}
