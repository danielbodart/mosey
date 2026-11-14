package emu_test

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/danielbodart/mosey/internal/emu"
	"github.com/danielbodart/mosey/internal/screen"
)

// The O11 acceptance gate (docs/spec/screen.md §5.12): the diff format,
// uncompressed, is no bigger than the raw pty output it stands for, on the
// spikes' recordings, with frames taken on D11's server schedule.

const (
	// collect is how long the server lets output collect after the first
	// byte before it takes a frame [D11].
	collect = 8 * time.Millisecond
	// interval is the frame interval: SRTT/2 for a 100 ms path [D11], the
	// schedule S5 used.
	interval = 50 * time.Millisecond
	// flateThreshold is SSP's: shorter instructions are not compressed
	// [measured S5].
	flateThreshold = 32
)

type record struct {
	at   time.Duration
	data []byte
}

func readCapture(t *testing.T, path string) []record {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []record
	for len(b) > 0 {
		if len(b) < 12 {
			t.Fatalf("%s: a truncated record", path)
		}
		at := time.Duration(binary.BigEndian.Uint64(b)) * time.Microsecond
		n := int(binary.BigEndian.Uint32(b[8:]))
		if n > len(b)-12 {
			t.Fatalf("%s: a record of %d bytes past the end", path, n)
		}
		out = append(out, record{at, b[12 : 12+n]})
		b = b[12+n:]
	}
	return out
}

// tally takes frames from an emulator and counts what they cost.
type tally struct {
	e                       emu.Emulator
	prev                    *screen.Grid
	client                  *screen.Grid
	pty, diff, wire, frames int
	zw                      *flate.Writer
	zb                      bytes.Buffer
}

func newTally(t *testing.T, cols, rows int) *tally {
	e, err := emu.New(cols, rows, emu.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	zw, _ := flate.NewWriter(nil, flate.DefaultCompression)
	return &tally{e: e, prev: screen.NewGrid(0, 0), client: screen.NewGrid(0, 0), zw: zw}
}

func (ta *tally) write(p []byte) {
	ta.e.Write(p)
	ta.e.TakeReplies()
	ta.pty += len(p)
}

func (ta *tally) frame(t *testing.T) {
	g := ta.prev.Clone()
	ta.e.Snapshot(g)
	d := g.Diff(ta.prev)
	if err := ta.client.Apply(d); err != nil || !ta.client.Equal(g) {
		t.Fatalf("frame %d: the client did not follow: %v", ta.frames, err)
	}
	ta.prev = g
	if len(d) == 0 {
		return
	}
	ta.frames++
	ta.diff += len(d)
	wire := len(d)
	if len(d) >= flateThreshold {
		ta.zb.Reset()
		ta.zw.Reset(&ta.zb)
		_, _ = ta.zw.Write(d)
		_ = ta.zw.Close()
		wire = ta.zb.Len()
	}
	ta.wire += wire
}

func (ta *tally) log(t *testing.T, name string) {
	t.Logf("| %s | %d | %d | %d | %.2f | %d | %.2f |", name, ta.pty, ta.frames, ta.diff,
		float64(ta.diff)/float64(ta.pty), ta.wire, float64(ta.wire)/float64(ta.pty))
}

func TestDiffNotBiggerThanRaw(t *testing.T) {
	t.Log("| stream | pty bytes | frames | diff bytes | diff/pty | flate bytes | flate/pty |")
	t.Log("|---|---|---|---|---|---|---|")
	for _, name := range []string{"flood", "less", "shell", "vim"} {
		recs := readCapture(t, filepath.Join("testdata", "corpus", "s5", name+".bin"))
		ta := newTally(t, 120, 40)
		ta.frame(t)
		// Output collects for 8 ms after the first byte, and frames are at
		// least 50 ms apart.
		var due time.Duration
		pending := false
		lastFrame := -interval
		for _, r := range recs {
			if pending && r.at >= due {
				ta.frame(t)
				lastFrame, pending = due, false
			}
			if !pending {
				due = max(r.at+collect, lastFrame+interval)
				pending = true
			}
			ta.write(r.data)
		}
		ta.frame(t)
		ta.log(t, "s5/"+name)
		if ta.diff > ta.pty {
			t.Errorf("s5/%s: %d diff bytes for %d pty bytes", name, ta.diff, ta.pty)
		}
	}

	type event struct {
		Off  int    `json:"off"`
		Kind string `json:"kind"`
		W    int    `json:"w"`
		H    int    `json:"h"`
	}
	var sumPty, sumDiff int
	for _, name := range []string{"fish", "less", "unicode", "vim", "zsh"} {
		dir := filepath.Join("testdata", "corpus", "s2", name)
		raw, err := os.ReadFile(filepath.Join(dir, "raw.bin"))
		if err != nil {
			t.Fatal(err)
		}
		js, err := os.ReadFile(filepath.Join(dir, "events.json"))
		if err != nil {
			t.Fatal(err)
		}
		var evs []event
		if err := json.Unmarshal(js, &evs); err != nil {
			t.Fatal(err)
		}
		ta := newTally(t, 80, 24)
		ta.frame(t)
		// No timing: a frame at every checkpoint and every 1 KiB, as S2 did.
		ev := 0
		for pos := 0; pos < len(raw); {
			end := min(pos+1024, len(raw))
			if ev < len(evs) && evs[ev].Off >= pos && evs[ev].Off < end {
				end = evs[ev].Off
			}
			ta.write(raw[pos:end])
			pos = end
			for ev < len(evs) && evs[ev].Off <= pos {
				if evs[ev].Kind == "resize" {
					ta.e.Resize(evs[ev].W, evs[ev].H)
				}
				ev++
			}
			ta.frame(t)
		}
		// Each is gated only in the sum: unicode is a torture file, not a
		// program, and is reported but not gated alone (§5.12).
		ta.log(t, "s2/"+name)
		sumPty += ta.pty
		sumDiff += ta.diff
	}
	t.Logf("s2 together: %d diff bytes for %d pty bytes (%.2f)", sumDiff, sumPty, float64(sumDiff)/float64(sumPty))
	if sumDiff > sumPty {
		t.Errorf("s2 together: %d diff bytes for %d pty bytes", sumDiff, sumPty)
	}
}
