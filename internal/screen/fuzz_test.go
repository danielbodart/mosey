package screen_test

import (
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
	return []*screen.Grid{screen.NewGrid(0, 0), frame, big}
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
		cat([]byte{0x53}, uv(10), []byte("a\u009d0;evil\u009cb")[:10]),
		{0x49, 0x49, 0x49, 0x49, 0x49},
	} {
		for base := range uint8(3) {
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
		runtime.ReadMemStats(&ms)
		if ms.HeapAlloc > 2<<30 {
			t.Fatalf("heap at %d MiB", ms.HeapAlloc>>20)
		}
	})
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
		}
	})
}
