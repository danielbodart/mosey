package emu_test

import (
	"runtime"
	"testing"

	"github.com/danielbodart/mosey/internal/emu"
	"github.com/danielbodart/mosey/internal/screen"
)

// FuzzEmuRoundTrip feeds program bytes and a resize, up to the clamp, to
// the shipped emulator, taking a snapshot after each half and sending the
// client the diff. Every snapshot is valid, the client always ends up
// Equal, and the heap stays bounded. It is S2's FuzzRoundTrip and
// FuzzTuiosClamp, rebuilt on the production types.
func FuzzEmuRoundTrip(f *testing.F) {
	for _, s := range []string{
		"hello\r\nworld", "\x1b[1;31mred\x1b[0m\x1b[2J\x1b[H", "é漢字👨‍👩‍👧",
		"\x1b]8;;https://x/\x1b\\l\x1b]8;;\x1b\\", "\x1b]2;a\u009db\x07", "\x1b]52;c;aGk=\x07",
		"\x1b[?1049h\x1b[?1002h\x1b[?1006h", "\x1b[?2026hheld", "abcd漢\x1b[3;10r\x1b[5S",
		"x\x1b[2147483647b", "\x1b[?3h\x1b[8;50;200t",
	} {
		f.Add([]byte(s), []byte("\r\n\x1b[1;1Hmore"), uint16(80), uint16(24))
	}
	f.Add([]byte("x"), []byte("y"), uint16(screen.MaxCols), uint16(screen.MaxRows))
	var ms runtime.MemStats
	f.Fuzz(func(t *testing.T, first, second []byte, cols, rows uint16) {
		e, err := emu.New(1+int(cols)%120, 1+int(rows)%40, emu.Options{})
		if err != nil {
			t.Fatal(err)
		}
		defer e.Close()
		client := screen.NewGrid(0, 0)
		server := screen.NewGrid(0, 0)
		step := func() {
			prev := server.Clone()
			e.Snapshot(server)
			if err := server.Valid(); err != nil {
				t.Fatalf("an invalid snapshot: %v", err)
			}
			if err := client.Apply(server.Diff(prev)); err != nil || !client.Equal(server) {
				t.Fatalf("the client did not follow: %v", err)
			}
		}
		e.Write(first)
		e.TakeReplies()
		step()
		// A resize anywhere up to the clamp, then the rest.
		e.Resize(int(cols)%(screen.MaxCols+1), int(rows)%(screen.MaxRows+1))
		e.Write(second)
		e.TakeReplies()
		step()
		runtime.ReadMemStats(&ms)
		if ms.HeapAlloc > 2<<30 {
			t.Fatalf("heap at %d MiB", ms.HeapAlloc>>20)
		}
	})
}
