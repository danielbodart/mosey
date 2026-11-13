package o8

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
)

// maxFrag is the instruction bytes one datagram carries: 1280 payload minus
// the spike's 35 bytes of datagram + fragment overhead minus ~8 bytes of
// instruction header (ssp-spec.md §2).
const maxFrag = 1280 - 35 - 8

func TestEncodeDiffRoundTripShape(t *testing.T) {
	chunks := []Chunk{{0, []byte("hello\r\nworld\x1b[1;31m red\x1b[0m")}}
	fr := Frames(chunks, 40, 5, 50*time.Millisecond)
	if len(fr) != 1 || !bytes.Contains(fr[0], []byte("hello")) || !bytes.Contains(fr[0], []byte("red")) {
		t.Fatalf("unexpected frames %q", fr)
	}
}

type sessionFrames struct {
	name   string
	frames [][]byte
}

func loadAll(t *testing.T, dir string, w, h int, iv time.Duration) []sessionFrames {
	paths, _ := filepath.Glob(filepath.Join(dir, "*.bin"))
	sort.Strings(paths)
	var out []sessionFrames
	for _, p := range paths {
		ch, err := LoadCapture(p)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, sessionFrames{strings.TrimSuffix(filepath.Base(p), ".bin"), Frames(ch, w, h, iv)})
	}
	return out
}

type agg struct {
	raw, comp, eff, frames, dgRaw, dgEff int
	sizes                                []int
	encNs, decNs                         float64
}

func datagrams(n int) int { return (n + maxFrag - 1) / maxFrag }

// TestO8Report runs the compression comparison over captures in
// $S5_CAPTURES (made with cmd/capture). Each session is tested with
// dictionaries trained on the *other* sessions (leave-one-out).
func TestO8Report(t *testing.T) {
	dir := os.Getenv("S5_CAPTURES")
	if dir == "" {
		t.Skip("set S5_CAPTURES to a directory of cmd/capture files")
	}
	var report strings.Builder
	for _, geom := range []struct {
		w, h int
		iv   time.Duration
	}{{120, 40, 50 * time.Millisecond}, {120, 40, 20 * time.Millisecond}} {
		sess := loadAll(t, dir, geom.w, geom.h, geom.iv)
		fmt.Fprintf(&report, "\n### %dx%d, frame interval %v\n\n", geom.w, geom.h, geom.iv)
		fmt.Fprintln(&report, "| session | frames | raw bytes | median raw | frames > 1 datagram (raw) |")
		fmt.Fprintln(&report, "|---|---|---|---|---|")
		for _, s := range sess {
			var sz []int
			n, big := 0, 0
			for _, f := range s.frames {
				sz = append(sz, len(f))
				n += len(f)
				if len(f) > maxFrag {
					big++
				}
			}
			slices.Sort(sz)
			med := 0
			if len(sz) > 0 {
				med = sz[len(sz)/2]
			}
			fmt.Fprintf(&report, "| %s | %d | %d | %d | %d |\n", s.name, len(s.frames), n, med, big)
		}
		names := []string{"raw", "flate-1", "flate-6", "flate-6+dict16k", "zstd-fastest", "zstd-default", "zstd-default+rawdict16k", "zstd-default+dict16k", "zstd-fastest+dict16k"}
		tot := map[string]*agg{}
		for _, n := range names {
			tot[n] = &agg{}
		}
		for i, s := range sess {
			var train [][]byte
			for j, o := range sess {
				if j != i {
					train = append(train, o.frames...)
				}
			}
			raw16 := RawDict(train, 16<<10)
			zd, err := ZstdDict(train, 16<<10)
			if err != nil {
				t.Fatalf("BuildDict: %v", err)
			}
			codecs := []Codec{
				Raw(),
				Flate("flate-1", 1, nil),
				Flate("flate-6", 6, nil),
				Flate("flate-6+dict16k", 6, raw16),
				Zstd("zstd-fastest", zstd.SpeedFastest, nil, false),
				Zstd("zstd-default", zstd.SpeedDefault, nil, false),
				Zstd("zstd-default+rawdict16k", zstd.SpeedDefault, raw16, true),
				Zstd("zstd-default+dict16k", zstd.SpeedDefault, zd, false),
				Zstd("zstd-fastest+dict16k", zstd.SpeedFastest, zd, false),
			}
			for _, c := range codecs {
				a := tot[c.Name]
				var encd [][]byte
				st := time.Now()
				for _, f := range s.frames {
					encd = append(encd, c.Enc(f))
				}
				a.encNs += float64(time.Since(st).Nanoseconds())
				st = time.Now()
				for k, e := range encd {
					d, err := c.Dec(e)
					if err != nil || !bytes.Equal(d, s.frames[k]) {
						t.Fatalf("%s/%s frame %d: round trip failed: %v", s.name, c.Name, k, err)
					}
				}
				a.decNs += float64(time.Since(st).Nanoseconds())
				for k, e := range encd {
					f := s.frames[k]
					a.frames++
					a.raw += len(f)
					a.comp += len(e)
					// one flag byte; send compressed only if smaller
					eff := 1 + min(len(e), len(f))
					a.eff += eff
					a.sizes = append(a.sizes, eff)
					a.dgRaw += datagrams(len(f))
					a.dgEff += datagrams(eff)
				}
			}
		}
		fmt.Fprintln(&report, "\nAll sessions, leave-one-out dictionaries. 'eff' = 1 flag byte + min(compressed, raw).")
		fmt.Fprintln(&report, "\n| codec | total eff bytes | ratio vs raw | median frame | p99 frame | datagrams | enc µs/frame | dec µs/frame |")
		fmt.Fprintln(&report, "|---|---|---|---|---|---|---|---|")
		for _, n := range names {
			a := tot[n]
			slices.Sort(a.sizes)
			fmt.Fprintf(&report, "| %s | %d | %.3f | %d | %d | %d | %.1f | %.1f |\n", n, a.eff, float64(a.eff)/float64(a.raw),
				a.sizes[len(a.sizes)/2], a.sizes[len(a.sizes)*99/100], a.dgEff, a.encNs/float64(a.frames)/1e3, a.decNs/float64(a.frames)/1e3)
		}
	}
	fmt.Fprintf(&report, "\nRecovered x/vt panics while rendering: %d\n", EmulatorPanics)
	t.Log(report.String())
	if out := os.Getenv("S5_O8_OUT"); out != "" {
		os.WriteFile(out, []byte(report.String()), 0o644)
	}
}

// TestVTPanicOnSmallerScreen records an incidental S2 finding: replaying
// output produced for a 120x40 terminal into an 80x24 x/vt emulator panics
// inside the emulator (recovered by safeWrite and counted).
func TestVTPanicOnSmallerScreen(t *testing.T) {
	dir := os.Getenv("S5_CAPTURES")
	if dir == "" {
		t.Skip("set S5_CAPTURES")
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "*.bin"))
	sort.Strings(paths)
	for _, p := range paths {
		ch, _ := LoadCapture(p)
		before := EmulatorPanics
		Frames(ch, 80, 24, 20*time.Millisecond)
		t.Logf("%s at 80x24: %d recovered emulator panics", filepath.Base(p), EmulatorPanics-before)
	}
}
