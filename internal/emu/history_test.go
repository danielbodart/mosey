package emu_test

import (
	"fmt"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/danielbodart/mosey/internal/screen"
)

func lineText(l []screen.Cell) string {
	var b strings.Builder
	for _, c := range l {
		switch {
		case c.Width == 0:
		case c.Text == "":
			b.WriteByte(' ')
		default:
			b.WriteString(c.Text)
		}
	}
	return strings.TrimRight(b.String(), " ")
}

func historyText(h screen.History) []string {
	var out []string
	for _, l := range h.Lines {
		out = append(out, lineText(l))
	}
	return out
}

// Lines that scroll off the top of the primary screen are its history, in
// order and numbered, with their styles and without their links
// (docs/spec/screen.md §2.5, §6.3).
func TestLinesThatScrollOffThePrimaryScreenAreItsHistory(t *testing.T) {
	e := newEmu(t, 20, 3)
	e.Write([]byte("\x1b[1;32mone\x1b[0m\r\n\x1b]8;;https://example.com/\x1b\\two\x1b]8;;\x1b\\\r\nthree\r\nfour\r\nfive"))
	g := snapshot(t, e)
	if got := historyText(g.History); strings.Join(got, "|") != "one|two" || g.History.Next != 2 {
		t.Fatalf("history %q, next %d", got, g.History.Next)
	}
	if st := g.History.Lines[0][0].Style; st.Fg != screen.Palette(2) || st.Attrs != screen.Bold {
		t.Errorf("the first line's style is %+v", st)
	}
	if link := g.History.Lines[1][0].Style.Link; link != "" {
		t.Errorf("a history cell kept its link %q", link)
	}
	if len(g.History.Lines[0]) != 20 {
		t.Errorf("a line %d wide, not the screen's 20", len(g.History.Lines[0]))
	}
	e.Write([]byte("\r\nsix"))
	g = snapshot(t, e)
	if got := historyText(g.History); strings.Join(got, "|") != "one|two|three" || g.History.Next != 3 {
		t.Fatalf("then history %q, next %d", got, g.History.Next)
	}
}

// The alternate screen never makes history, as on a real terminal, and
// nor does a scroll region that starts below the top row.
func TestTheAlternateScreenAndALowerRegionMakeNoHistory(t *testing.T) {
	e := newEmu(t, 20, 3)
	e.Write([]byte("\x1b[?1049h"))
	for i := range 50 {
		fmt.Fprintf(writer{e}, "alt %d\r\n", i)
	}
	e.Write([]byte("\x1b[?1049l"))
	if g := snapshot(t, e); g.History.Next != 0 {
		t.Errorf("the alternate screen made %d lines of history", g.History.Next)
	}
	e.Write([]byte("\x1b[2;3r\x1b[2;1H"))
	for i := range 50 {
		fmt.Fprintf(writer{e}, "region %d\r\n", i)
	}
	if g := snapshot(t, e); g.History.Next != 0 {
		t.Errorf("a region below the top made %d lines of history", g.History.Next)
	}
}

type writer struct{ e interface{ Write([]byte) } }

func (w writer) Write(p []byte) (int, error) { w.e.Write(p); return len(p), nil }

// A flood keeps the newest window and counts every line, however much one
// Write carries.
func TestAFloodKeepsTheWindowAndCountsEveryLine(t *testing.T) {
	e := newEmu(t, 80, 24)
	var b strings.Builder
	for i := range 5000 {
		fmt.Fprintf(&b, "line %d\r\n", i)
	}
	e.Write([]byte(b.String()))
	g := snapshot(t, e)
	// 5000 lines and the empty one the cursor is on: 4977 scrolled off.
	if g.History.Next != 5000-23 {
		t.Errorf("next %d", g.History.Next)
	}
	if len(g.History.Lines) != screen.HistoryLines {
		t.Errorf("%d lines held", len(g.History.Lines))
	}
	if last := lineText(g.History.Lines[len(g.History.Lines)-1]); last != "line 4976" {
		t.Errorf("the newest line is %q", last)
	}
}

// A held snapshot (mode 2026) carries the history as it stands, so its
// Next never goes backwards (§6.2).
func TestAHeldSnapshotsHistoryDoesNotGoBackwards(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEmu(t, 20, 3)
		e.Write([]byte("a\r\nb\r\nc\r\nd"))
		before := snapshot(t, e)
		e.Write([]byte("\x1b[?2026h\r\ne\r\nf\r\ng"))
		held := snapshot(t, e)
		if held.History.Next < before.History.Next {
			t.Fatalf("held next %d below %d", held.History.Next, before.History.Next)
		}
		if held.History.Next != 4 {
			t.Errorf("held next %d, want the lines scrolled so far, 4", held.History.Next)
		}
	})
}

// The rows a shrinking resize pushes off the top are history; a growing
// one pulls nothing back, since the emulator's ring is always empty.
func TestAResizeMakesHistoryOfWhatItPushesOff(t *testing.T) {
	e := newEmu(t, 20, 4)
	e.Write([]byte("a\r\nb\r\nc\r\nd"))
	e.Resize(20, 2)
	g := snapshot(t, e)
	if got := historyText(g.History); strings.Join(got, "|") != "a|b" {
		t.Fatalf("history after shrinking %q", got)
	}
	e.Resize(20, 6)
	g = snapshot(t, e)
	if g.History.Next != 2 || rowText(g, 0) != "c" {
		t.Errorf("after growing: next %d, top row %q", g.History.Next, rowText(g, 0))
	}
}

// The history diffs like any other field: a line that scrolls is sent as
// the base row it was.
func TestAScrolledLineCostsAFewBytes(t *testing.T) {
	e := newEmu(t, 80, 24)
	var b strings.Builder
	for i := range 23 {
		fmt.Fprintf(&b, "a fairly long line of output number %d\r\n", i)
	}
	e.Write([]byte(b.String()))
	before := snapshot(t, e)
	e.Write([]byte("one more line of output\r\n"))
	after := snapshot(t, e)
	d := after.Diff(before)
	if len(d) > 40 {
		t.Errorf("%d bytes for a line that scrolled: % x", len(d), d)
	}
	got := before.Clone()
	if err := got.Apply(d); err != nil || !got.Equal(after) {
		t.Fatalf("the diff does not round-trip: %v", err)
	}
}
