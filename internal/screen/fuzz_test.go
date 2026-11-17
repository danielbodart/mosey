package screen_test

import (
	"bytes"
	"runtime"
	"testing"

	"github.com/danielbodart/mosey/internal/screen"
	"github.com/danielbodart/mosey/internal/screen/screentest"
)

// fuzzBases are the grids FuzzApply applies its input to: version 0, a
// real-looking 80 x 24 frame, and a frame at the clamp.
func fuzzBases() []*screen.Grid {
	frame := screen.NewGrid(80, 24)
	for y := range 24 {
		ascii(frame, 0, y, "$ ls -l --hyperlink", screen.Style{Fg: screen.Palette(uint8(y))})
	}
	screentest.SetWide(frame, 30, 3, "漢", screen.Style{Attrs: screen.Bold})
	frame.SetCell(40, 5, screen.Cell{Text: "é", Width: 1, Style: screen.Style{Link: "https://example.com/"}})
	frame.Cursor = screen.Cursor{X: 20, Y: 23, Visible: true}
	big := screen.NewGrid(screen.MaxCols, screen.MaxRows)
	ascii(big, 990, 499, "corner", screen.Style{})
	big.Cursor = screen.Cursor{X: 999, Y: 499}
	// A frame with a history most of a window long (§2.5).
	scrolled := frame.Clone()
	scrolled.History = scrolled.History.Add(900, lines(0, 899, 80))
	return []*screen.Grid{screen.NewGrid(0, 0), frame, big, scrolled}
}

// FuzzApply feeds arbitrary bytes to Apply. A refused diff leaves the grid
// exactly as it was; an accepted one leaves it valid; nothing panics, and
// the heap stays bounded, as S2's target checked.
func FuzzApply(f *testing.F) {
	for _, ex := range examples(f) {
		f.Add(uint8(1), ex)
	}
	for _, d := range [][]byte{
		{0x41, 0x50, 0x18, 0x49}, {0x43, 0x01}, {0x42, 0, 2, 21, 0x42, 23, 23, 1},
		{0x44, 0, 2, 0x4b, 0, 3, 3, 0x48, 1},
		cat([]byte{0x47}, uv(^uint64(0))), cat([]byte{0x45, 5, 0x48}, uv(^uint64(0)-4)),
		cat([]byte{0x00, 'a', 0x4a}, uv(1<<63)), cat([]byte{0x03, 0x02, 0xe6, 0xbc, 0xa2, 0x4a}, uv(1<<63)),
		cat([]byte{0x4b}, uv(0), uv(3), uv(^uint64(0)-2)), cat([]byte{0x42}, uv(3), uv(0), uv(^uint64(0)-2)),
		cat([]byte{0xe1, 10}, []byte("a\u009d0;evil\u009cb")[:10]),
		{0x49, 0x49, 0x49, 0x49, 0x49},
		// The container mark and the directory (§4.6, §4.7): good, cleared,
		// and with an escape smuggled in.
		cat([]byte{0xe5, 14, 0x03}, []byte("box"), []byte{0x05}, []byte("flong"), []byte("1000")),
		{0xe5, 0x02, 0x00, 0x00, 0xe6, 0x00},
		cat([]byte{0xe5, 0x07, 0x04}, []byte("a\u009cb"), []byte{0x00, '0'}),
		cat([]byte{0xe6, 0x0d}, []byte("file://h/home")),
		cat([]byte{0xe6, 0x0c}, []byte("file://h/%1b")),
		{0xf0, 0x03, 'a', 'b', 'c', 0x80, 'x'},
		{0xd0, 0x00, 0x80, 'x'},
		// ROOT (§4.8): set, cleared, a byte out of range, and twice.
		{0xe7, 0x01, 0x01}, {0xe7, 0x01, 0x00, 0xe6, 0x00}, {0xe7, 0x01, 0x02}, {0xe7, 0x01, 0x01, 0xe7, 0x01, 0x00},
		// History (§5.6): a scrolled line, new lines, a gap, and the
		// bounds' edges.
		{0x43, 0x01, 0x60, 0x00, 0x62, 0x00},
		cat([]byte{0x60}, uv(900), []byte{0x61, 0x05, 0x02, 'h', 'i', 0x48, 0x00, 0x61, 0x50, 0x4c, 0x09, 0x01, 0x02, 0x01, 0x4a, 0x05}),
		cat([]byte{0x60}, uv(1<<40), []byte{0x62, 0x03, 0x61, 0x02, 0x03, 0x02, 0xe6, 0xbc, 0xa2}),
		cat([]byte{0x60}, uv(^uint64(0)-screen.HistoryLines), bytes.Repeat([]byte{0x61, 0x01}, screen.HistoryLines)),
		cat([]byte{0x60, 0x00}, bytes.Repeat(cat([]byte{0x61}, uv(screen.MaxCols), []byte{0x00, 'x', 0x48, 0x00}), screen.HistoryCells/screen.MaxCols)),
	} {
		for base := range uint8(4) {
			f.Add(base, d)
		}
	}
	bases := fuzzBases()
	var ms runtime.MemStats
	f.Fuzz(func(t *testing.T, which uint8, d []byte) {
		g := bases[int(which)%len(bases)].Clone()
		before := g.Clone()
		if err := g.Apply(d); err != nil {
			if !g.Equal(before) {
				t.Fatalf("a refused diff changed the grid: %v", err)
			}
			return
		}
		if err := g.Valid(); err != nil {
			t.Fatalf("an accepted diff left an invalid grid: %v", err)
		}
		// Applying the encoder's own diff back to the base gets the same
		// grid: the decoder and encoder agree on whatever the fuzzer made.
		back := before.Clone()
		if err := back.Apply(g.Diff(before)); err != nil || !back.Equal(g) {
			t.Fatalf("re-encoding what the diff made does not round-trip: %v", err)
		}
		mustIgnore(t, before, d, g)
		runtime.ReadMemStats(&ms)
		if ms.HeapAlloc > 2<<30 {
			t.Fatalf("heap at %d MiB", ms.HeapAlloc>>20)
		}
	})
}

// mustIgnore checks versioning.md §7 on a diff d that took base to want: a
// property op this decoder does not know, inserted at an op boundary where
// a property op may stand (after any SIZE, before any HIST), changes
// nothing when its opcode says it may be ignored, and makes the diff an
// error, the grid unchanged, when it is critical (screen.md §5.4). It
// tries the first, a middle and the last such boundary.
func mustIgnore(t *testing.T, base *screen.Grid, d []byte, want *screen.Grid) {
	t.Helper()
	starts, skipped := screen.OpStarts(base, d)
	if skipped == screen.MaxUnknownProps {
		return // one more would be over the bound, and refused for that
	}
	starts = append(starts, len(d))
	var at []int
	for i, p := range starts {
		if p < len(d) && d[p] == 0x60 {
			at = append(at, p) // HIST: the last place a property op may go
			break
		}
		if i == 0 && len(d) > 0 && d[0] == 0x41 {
			continue // before SIZE, which must be first
		}
		at = append(at, p)
	}
	if len(at) > 3 {
		at = []int{at[0], at[len(at)/2], at[len(at)-1]}
	}
	unknown := []byte{0xf3, 0x02, 0xc1, 0x00}
	critical := []byte{0xd3, 0x00}
	for _, p := range at {
		with := cat(d[:p], unknown, d[p:])
		g := base.Clone()
		if err := g.Apply(with); err != nil || !g.Equal(want) {
			t.Fatalf("an unknown property op at %d of % x changed the result: %v", p, d, err)
		}
		g = base.Clone()
		if err := g.Apply(cat(d[:p], critical, d[p:])); err == nil || !g.Equal(base) {
			t.Fatalf("an unknown critical property op at %d of % x was not refused cleanly: %v", p, d, err)
		}
	}
}

// FuzzRoundTrip builds two valid grids from the fuzz bytes, the second a
// later version of the first, and checks E1, E2 and E3 for b.Diff(a), and
// from version 0.
func FuzzRoundTrip(f *testing.F) {
	f.Add([]byte("seed"), uint8(12), uint8(6))
	f.Add([]byte("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"), uint8(3), uint8(2))
	f.Add([]byte("\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8\xf7\xf6\xf5\xf4\xf3\xf2\xf1\xf0\xef"), uint8(40), uint8(10))
	f.Fuzz(func(t *testing.T, seed []byte, maxCols, maxRows uint8) {
		s := screentest.NewSource(seed)
		mc, mr := 1+int(maxCols)%80, 1+int(maxRows)%30
		a := s.Grid(mc, mr)
		b := s.Next(a, mc, mr)
		for _, from := range []*screen.Grid{a, screen.NewGrid(0, 0)} {
			d := roundTrip(t, from, b)
			cols, rows := b.Size()
			// E3: within MaxDiff; the cells-written budget is checked by
			// Apply itself, which accepted it.
			if len(d) > screen.MaxDiff {
				t.Fatalf("E3: %d bytes for %d x %d", len(d), cols, rows)
			}
			mustIgnore(t, from, d, b)
		}
	})
}
