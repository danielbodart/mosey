package screen_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/danielbodart/mosey/internal/screen"
	"github.com/danielbodart/mosey/internal/screen/screentest"
)

// line is a history line of the text s, w cells wide.
func line(s string, w int) []screen.Cell {
	g := screen.NewGrid(w, 1)
	ascii(g, 0, 0, s, screen.Style{})
	return screentest.Unlinked(g.Row(0))
}

func lines(from, n, w int) [][]screen.Cell {
	var out [][]screen.Cell
	for i := range n {
		out = append(out, line(fmt.Sprintf("line %d", from+i), w))
	}
	return out
}

// A line of output that scrolls the screen is SCROLL 1 and HROW 0: the
// line is not sent again, since the receiver holds it as the top row of
// the screen it acknowledged (docs/spec/screen.md §5.6).
func TestALineThatScrolledOffIsSentAsTheBaseRowItWas(t *testing.T) {
	from := base80x24()
	for y := range 24 {
		ascii(from, 0, y, fmt.Sprintf("output line number %d", y), screen.Style{})
	}
	from.Cursor.Y = 23
	to := from.Clone()
	screentest.ScrollIntoHistory(to, 1)
	ascii(to, 0, 23, "$ ", screen.Style{})
	d := roundTrip(t, from, to)
	if !bytes.Contains(d, []byte{0x60, 0x00, 0x62, 0x00}) {
		t.Errorf("no HIST 0, HROW 0 in % x", d)
	}
	if len(d) > 12 {
		t.Errorf("%d bytes for one scrolled line: % x", len(d), d)
	}
	if got := to.History.Lines[0]; got[0].Text != "o" || len(got) != 80 {
		t.Errorf("history line %+v", got[:3])
	}
}

// A diff from the acknowledged version carries the lines numbered from its
// Next on, and no others (§2.5).
func TestADiffCarriesOnlyTheLinesTheReceiverLacks(t *testing.T) {
	from := base80x24()
	from.History = from.History.Add(10, lines(0, 10, 40))
	to := from.Clone()
	to.History = to.History.Add(13, lines(10, 3, 40))
	d := roundTrip(t, from, to)
	if bytes.Contains(d, []byte("line 9")) || !bytes.Contains(d, []byte("line 12")) {
		t.Errorf("the diff carries the wrong lines: %q", d)
	}
}

// A client that fell behind by more than the window gets a diff starting
// after a gap, and keeps none of its old lines: the window holds a run
// with no hole (§5.6).
func TestAGapKeepsNoneOfTheBasesLines(t *testing.T) {
	from := base80x24()
	from.History = from.History.Add(5, lines(0, 5, 40))
	to := from.Clone()
	to.History = to.History.Add(5000, lines(4998, 2, 40))
	roundTrip(t, from, to)
	got := from.Clone()
	if err := got.Apply(to.Diff(from)); err != nil {
		t.Fatal(err)
	}
	if got.History.Next != 5000 || len(got.History.Lines) != 2 || got.History.First() != 4998 {
		t.Errorf("history next %d, %d lines from %d", got.History.Next, len(got.History.Lines), got.History.First())
	}
}

// The window drops the oldest lines once either bound is passed (§2.5).
func TestTheWindowDropsTheOldestLines(t *testing.T) {
	var h screen.History
	h = h.Add(screen.HistoryLines+5, lines(0, screen.HistoryLines+5, 10))
	if len(h.Lines) != screen.HistoryLines || h.First() != 5 {
		t.Errorf("by lines: %d held from %d", len(h.Lines), h.First())
	}
	h = screen.History{}
	wide := screen.HistoryCells/screen.MaxCols + 3
	h = h.Add(uint64(wide), lines(0, wide, screen.MaxCols))
	if len(h.Lines) != screen.HistoryCells/screen.MaxCols || h.First() != 3 {
		t.Errorf("by cells: %d held from %d", len(h.Lines), h.First())
	}
}

// Each history op refuses what breaks its rule, and a refused diff
// changes nothing (§5.6, §10).
func TestEachHistoryRuleRefusesWhatBreaksIt(t *testing.T) {
	hist := []byte{0x60, 0}
	text := []byte{0x01, 'h', 'i'}
	for name, d := range map[string][]byte{
		"HIST twice":                cat(hist, hist),
		"HIST past the wrap bound":  cat([]byte{0x60}, uv(^uint64(0)-screen.HistoryLines+1)),
		"a line op before HLINE":    cat(hist, text),
		"a line op after HROW":      cat(hist, []byte{0x62, 0}, text),
		"COL before HLINE":          cat(hist, []byte{0x45, 0}),
		"a screen op after HIST":    cat(hist, []byte{0x51}),
		"a cursor op after HIST":    cat(hist, []byte{0x61, 5, 0x80, 'a'}),
		"a state op after HIST":     cat(hist, []byte{0x56, 1}),
		"a row move after HIST":     cat(hist, []byte{0x43, 1}),
		"ERASED after HIST":         cat(hist, []byte{0x61, 5, 0x49}),
		"PEN with a link":           cat([]byte{0x4d, 6}, []byte("http:x"), hist, []byte{0x61, 5, 0x4c, 0x10, 1}),
		"HLINE of 0 columns":        cat(hist, []byte{0x61, 0}),
		"HLINE past MaxCols":        cat(hist, []byte{0x61}, uv(screen.MaxCols+1)),
		"TEXT past the line":        cat(hist, []byte{0x61, 2, 0x02, 'a', 'b', 'c'}),
		"a wide character at edge":  cat(hist, []byte{0x61, 1, 0x03, 0x02, 0xe6, 0xbc, 0xa2}),
		"HROW past the base":        cat(hist, []byte{0x62}, uv(24)),
		"one line over the window":  cat(hist, bytes.Repeat([]byte{0x61, 1}, screen.HistoryLines+1)),
		"one cell over the window":  cat(hist, bytes.Repeat(cat([]byte{0x61}, uv(screen.MaxCols)), screen.HistoryCells/screen.MaxCols), []byte{0x61, 1}),
		"REPEAT before a character": cat(hist, []byte{0x61, 5, 0x4a, 1}),
		"SKIP past the line":        cat(hist, []byte{0x61, 3, 0x47, 4}),
		"ERASE past the line":       cat(hist, []byte{0x61, 3, 0x48, 4}),
		"a truncated HIST":          {0x60},
	} {
		refused(t, name, d)
	}

	// Below the base's next line: history only grows.
	g := base80x24()
	g.History = g.History.Add(7, lines(0, 3, 10))
	before := g.Clone()
	if err := g.Apply(cat([]byte{0x60, 6, 0x61, 3})); err == nil || !g.Equal(before) {
		t.Errorf("HIST below the base's next line: %v", err)
	}
	// A base row with a link cannot be copied into the history.
	g = base80x24()
	g.SetCell(0, 3, screen.Cell{Text: "x", Width: 1, Style: screen.Style{Link: "https://example.com/"}})
	before = g.Clone()
	if err := g.Apply([]byte{0x60, 0, 0x62, 3}); err == nil || !g.Equal(before) {
		t.Errorf("HROW of a row with a link: %v", err)
	}
}

// However many diffs a hostile server sends, each as full as the decoder
// allows, the client never holds more than the window (§2.5,
// threat-model.md §4.6).
func TestAHostileServerNeverMakesTheClientHoldMoreThanTheWindow(t *testing.T) {
	g := base80x24()
	full := bytes.Repeat(cat([]byte{0x61}, uv(screen.MaxCols), []byte{0x00, 'x', 0x48, 0}), screen.HistoryCells/screen.MaxCols)
	for i := range 12 {
		d := cat([]byte{0x60}, uv(g.History.Next+uint64(i)*7), full)
		if err := g.Apply(d); err != nil {
			t.Fatalf("diff %d: %v", i, err)
		}
		if err := g.Valid(); err != nil {
			t.Fatal(err)
		}
		cells := 0
		for _, l := range g.History.Lines {
			cells += len(l)
		}
		if len(g.History.Lines) > screen.HistoryLines || cells > screen.HistoryCells {
			t.Fatalf("diff %d: %d lines, %d cells held", i, len(g.History.Lines), cells)
		}
	}
	// And many narrow lines: the line bound holds too.
	narrow := bytes.Repeat([]byte{0x61, 1, 0x00, 'y'}, screen.HistoryLines)
	for range 3 {
		if err := g.Apply(cat([]byte{0x60}, uv(g.History.Next), narrow)); err != nil {
			t.Fatal(err)
		}
		if len(g.History.Lines) > screen.HistoryLines {
			t.Fatalf("%d lines held", len(g.History.Lines))
		}
	}
}

// The worst valid diff, a full screen at the clamp and a full window, each
// cell with its own style and the longest cluster, is within MaxDiff
// (§5.12).
func TestAWorstCaseScreenAndWindowStayWithinMaxDiff(t *testing.T) {
	cluster := strings.Repeat("á", 21) // 63 bytes
	cell := func(x, y int) screen.Cell {
		return screen.Cell{Text: cluster, Width: 1, Style: screen.Style{
			Fg: screen.RGB(byte(x), byte(y), byte(y>>8)), Bg: screen.RGB(1, byte(x), byte(y)), Underline: screen.RGB(byte(y), 1, byte(x)),
			Attrs: screen.Attrs(x%512) &^ (screen.DoubleUnderline | screen.CurlyUnderline),
		}}
	}
	to := screen.NewGrid(screen.MaxCols, screen.MaxRows)
	for y := range screen.MaxRows {
		for x := range screen.MaxCols {
			to.SetCell(x, y, cell(x, y))
		}
	}
	var hist [][]screen.Cell
	for y := range screen.HistoryCells / screen.MaxCols {
		l := make([]screen.Cell, screen.MaxCols)
		for x := range l {
			l[x] = cell(x, y+screen.MaxRows) // no screen row is the same line
		}
		hist = append(hist, l)
	}
	to.History = to.History.Add(uint64(len(hist)), hist)
	d := roundTrip(t, screen.NewGrid(0, 0), to)
	if len(d) > screen.MaxDiff {
		t.Fatalf("%d bytes, over MaxDiff %d", len(d), screen.MaxDiff)
	}
	t.Logf("a full screen and a full window of %d lines: %d bytes of %d", len(to.History.Lines), len(d), screen.MaxDiff)
}

// Generated grids whose next version scrolls into, adds to, or overtakes
// their history with a gap round-trip, from the base and from version 0.
func TestRoundTripsOfGeneratedHistories(t *testing.T) {
	seen := 0
	for i := range 3000 {
		s := screentest.Seeded(uint64(i) + 1<<20)
		a := s.Grid(14, 7)
		b := s.Next(a, 14, 7)
		if !b.History.Equal(a.History) {
			seen++
		}
		roundTrip(t, a, b)
		roundTrip(t, screen.NewGrid(0, 0), b)
	}
	if seen < 300 {
		t.Errorf("only %d of 3000 versions changed the history", seen)
	}
}

func TestTheWindowHoldsAThousandLinesUpTo200ColumnsAndFewerBeyond(t *testing.T) {
	for cols, want := range map[int]int{0: 1000, 1: 1000, 80: 1000, 200: 1000, 250: 800, screen.MaxCols: 200} {
		if got := screen.WindowLines(cols); got != want {
			t.Errorf("WindowLines(%d) = %d, want %d", cols, got, want)
		}
	}
}
