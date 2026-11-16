package render_test

import (
	"fmt"
	"strings"
	"testing"

	"tuios.dev/vt"

	"github.com/danielbodart/mosey/internal/render"
	"github.com/danielbodart/mosey/internal/screen"
)

// local is a user's terminal with a scrollback of its own, the reference
// the history tests read back: tuios itself, as a terminal emulator would
// show what the renderer wrote. Tests only; render never imports it.
type local struct {
	t   vt.Terminal
	out []byte
}

func newLocal(cols, rows int) *local {
	return &local{t: vt.NewWithScrollback(cols, rows, 100_000)}
}

func (l *local) Write(p []byte) (int, error) {
	l.out = append(l.out, p...)
	_, _ = l.t.Write(p)
	l.t.TakeResponses()
	return len(p), nil
}

func cellsText(line func(x int) string, w int) string {
	var b strings.Builder
	for x := range w {
		b.WriteString(line(x))
	}
	return strings.TrimRight(b.String(), " ")
}

// scrollback is the terminal's history, its blank lines left out (Enter
// scrolls the screen it found into history, blank or not).
func (l *local) scrollback() []string {
	var out []string
	for i := range l.t.ScrollbackLen() {
		ln := l.t.ScrollbackLine(i)
		s := cellsText(func(x int) string {
			if c := ln[x].Content; c != "" {
				return c
			}
			return " "
		}, len(ln))
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func (l *local) row(y int) string {
	return cellsText(func(x int) string {
		c := l.t.CellAt(x, y)
		if c == nil || c.Content == "" {
			return " "
		}
		return c.Content
	}, l.t.Width())
}

func histLine(s string, w int) []screen.Cell {
	l := make([]screen.Cell, w)
	for i := range l {
		l[i] = screen.Cell{Width: 1}
	}
	for i := range len(s) {
		l[i] = screen.Cell{Text: s[i : i+1], Width: 1, Style: screen.Style{Fg: screen.Palette(3)}}
	}
	return l
}

func histLines(from, n, w int) [][]screen.Cell {
	var out [][]screen.Cell
	for i := range n {
		out = append(out, histLine(fmt.Sprintf("h%d", from+i), w))
	}
	return out
}

func names(from, to int) []string {
	var out []string
	for i := from; i < to; i++ {
		out = append(out, fmt.Sprintf("h%d", i))
	}
	return out
}

func screenWith(cols, rows int, top string) *screen.Grid {
	g := screen.NewGrid(cols, rows)
	for i := range len(top) {
		g.SetCell(i, 0, screen.Cell{Text: top[i : i+1], Width: 1})
	}
	g.Cursor.Visible = true
	return g
}

func render1(t *testing.T, r *render.Renderer, l *local, g *screen.Grid) {
	t.Helper()
	before := len(l.out)
	if err := r.Render(g); err != nil {
		t.Fatal(err)
	}
	if err := checkAlphabet(l.out[before:], true); err != nil {
		t.Fatal(err)
	}
}

// The first frame prints the whole window, the recent history, above the
// screen; after that each line is printed once, in order, however many
// chunks of the screen's height it takes (docs/spec/screen.md §8.7).
func TestHistoryEntersTheLocalScrollbackOnceInOrder(t *testing.T) {
	l := newLocal(20, 5)
	r := render.New(l, allCaps)
	r.Resize(20, 5)
	_ = r.Enter()
	g := screenWith(20, 5, "screen one")
	g.History = g.History.Add(12, histLines(0, 12, 20))
	render1(t, r, l, g)
	g2 := screenWith(20, 5, "screen two")
	g2.History = g.History.Add(14, histLines(12, 2, 20))
	render1(t, r, l, g2)
	// The same history again, with a new screen: nothing printed again.
	g3 := screenWith(20, 5, "screen three")
	g3.History = g2.History
	render1(t, r, l, g3)
	if got, want := strings.Join(l.scrollback(), "|"), strings.Join(names(0, 14), "|"); got != want {
		t.Errorf("scrollback\n%s\nwant\n%s", got, want)
	}
	if l.row(0) != "screen three" {
		t.Errorf("the screen's top row is %q", l.row(0))
	}
	// A history line keeps its style.
	if c := l.t.ScrollbackLine(l.t.ScrollbackLen() - 1)[0]; c.Content != "h" || c.Style.Fg == nil {
		t.Errorf("the last history line's first cell is %+v", c)
	}
}

// Lines that were never received, because the client fell behind past the
// window, are one marker line with their count (§2.5, §8.7).
func TestAGapPrintsOneMarkerWithTheCount(t *testing.T) {
	l := newLocal(30, 4)
	r := render.New(l, allCaps)
	r.Resize(30, 4)
	_ = r.Enter()
	g := screenWith(30, 4, "$")
	g.History = g.History.Add(5, histLines(0, 5, 30))
	render1(t, r, l, g)
	g2 := g.Clone()
	g2.History = g.History.Add(5000, histLines(4998, 2, 30))
	render1(t, r, l, g2)
	want := append(names(0, 5), "… 4993 lines not shown", "h4998", "h4999")
	if got := l.scrollback(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("scrollback %q, want %q", got, want)
	}
	// Without UTF-8 the marker is ASCII.
	var ascii strings.Builder
	r2 := render.New(&ascii, render.Capabilities{})
	r2.Resize(30, 4)
	_ = r2.Render(g)
	_ = r2.Render(g2)
	if !strings.Contains(ascii.String(), "... 4993 lines not shown") {
		t.Errorf("no ASCII marker in %q", ascii.String())
	}
}

// While the remote program has the alternate screen, the local terminal
// has its own, and no history is printed; it is printed once the program
// leaves (§8.5, §8.7).
func TestTheAlternateScreenIsMirroredAndPrintsNoHistory(t *testing.T) {
	l := newLocal(20, 4)
	r := render.New(l, allCaps)
	r.Resize(20, 4)
	_ = r.Enter()
	g := screenWith(20, 4, "$ vim")
	render1(t, r, l, g)
	vim := screenWith(20, 4, "vim's screen")
	vim.Modes.AltScreen = true
	vim.History = vim.History.Add(2, histLines(0, 2, 20)) // no honest server does this
	render1(t, r, l, vim)
	if !l.t.IsAltScreen() {
		t.Fatal("the local terminal is not on its alternate screen")
	}
	if n := len(l.scrollback()); n != 0 {
		t.Fatalf("%d lines printed during the alternate screen", n)
	}
	back := screenWith(20, 4, "$ vim")
	back.History = vim.History
	render1(t, r, l, back)
	if l.t.IsAltScreen() || l.row(0) != "$ vim" {
		t.Fatalf("back on the primary screen: alt %v, top row %q", l.t.IsAltScreen(), l.row(0))
	}
	if got := strings.Join(l.scrollback(), "|"); got != "h0|h1" {
		t.Errorf("scrollback %q after leaving the alternate screen", got)
	}
}

// A reconnect (R3) keeps the renderer: the new connection's first frame
// carries the whole window again, and only what was not printed is.
func TestAReconnectsFreshWindowPrintsOnlyWhatIsNew(t *testing.T) {
	l := newLocal(20, 4)
	r := render.New(l, allCaps)
	r.Resize(20, 4)
	_ = r.Enter()
	g := screenWith(20, 4, "$")
	g.History = g.History.Add(3, histLines(0, 3, 20))
	render1(t, r, l, g)
	r.Invalidate()
	again := screenWith(20, 4, "$")
	again.History = g.History.Add(4, histLines(3, 1, 20))
	render1(t, r, l, again)
	if got := strings.Join(l.scrollback(), "|"); got != "h0|h1|h2|h3" {
		t.Errorf("scrollback %q", got)
	}
}

// A history line wider than the local terminal is clipped to it, as a
// screen row is (§8.3).
func TestAWideHistoryLineIsClippedToTheLocalWidth(t *testing.T) {
	l := newLocal(10, 3)
	r := render.New(l, allCaps)
	r.Resize(10, 3)
	_ = r.Enter()
	g := screenWith(10, 3, "$")
	g.History = g.History.Add(1, [][]screen.Cell{histLine("0123456789abcdef", 40)})
	render1(t, r, l, g)
	if got := strings.Join(l.scrollback(), "|"); got != "0123456789" {
		t.Errorf("scrollback %q", got)
	}
}
