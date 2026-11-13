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
// the spike's datagram + fragment overhead (ssp.Overhead, 41 bytes) minus
// ~8 bytes of instruction header (ssp-spec.md §2).
const maxFrag = 1280 - 41 - 8

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
	bases  [][]byte // ScreenText of each frame's base screen
}

// capturesDir is $S5_CAPTURES, else the committed captures (four of the six
// sessions; top and htop are not committed, see testdata/captures/README.md).
func capturesDir() string {
	if d := os.Getenv("S5_CAPTURES"); d != "" {
		return d
	}
	return "../testdata/captures"
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
		fr, bs := FramesWithBase(ch, w, h, iv)
		out = append(out, sessionFrames{strings.TrimSuffix(filepath.Base(p), ".bin"), fr, bs})
	}
	return out
}

func datagrams(n int) int { return max(1, (n+maxFrag-1)/maxFrag) }

// result is one codec on one session: per-frame encoded sizes (before the
// flag byte and min-with-raw rule) and timings.
type result struct {
	enc          []int
	encNs, decNs float64
}

func padTo(n, p int) int {
	if p <= 1 {
		return n
	}
	return (n + p - 1) / p * p
}

// eff is what goes on the wire for one frame: 1 flag byte + min(compressed,
// raw), then padded to a multiple of pad.
func eff(raw, comp, pad int) int { return padTo(1+min(raw, comp), pad) }

// TestO8Report runs the compression comparison over the captures (see
// capturesDir). Static dictionaries are trained leave-one-out on the
// *other* sessions; the "prevscreen" variant uses the frame's own base
// screen, which the receiver already holds.
func TestO8Report(t *testing.T) {
	dir := capturesDir()
	if paths, _ := filepath.Glob(filepath.Join(dir, "*.bin")); len(paths) == 0 {
		t.Skip("no captures in " + dir)
	}
	var report strings.Builder
	fmt.Fprintf(&report, "Captures: %s\n", dir)
	for gi, geom := range []struct {
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
		names := []string{"raw", "flate-1", "flate-6", "flate-6+dict16k", "flate-6+prevscreen", "zstd-fastest", "zstd-default", "zstd-default+rawdict16k", "zstd-default+dict16k", "zstd-fastest+dict16k"}
		res := map[string][]result{} // codec -> per session
		dEnc, dDec := FlateDelta(6)
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
				{Name: "flate-6+prevscreen"},
				Zstd("zstd-fastest", zstd.SpeedFastest, nil, false),
				Zstd("zstd-default", zstd.SpeedDefault, nil, false),
				Zstd("zstd-default+rawdict16k", zstd.SpeedDefault, raw16, true),
				Zstd("zstd-default+dict16k", zstd.SpeedDefault, zd, false),
				Zstd("zstd-fastest+dict16k", zstd.SpeedFastest, zd, false),
			}
			for _, c := range codecs {
				var r result
				var encd [][]byte
				st := time.Now()
				for k, f := range s.frames {
					if c.Enc == nil {
						encd = append(encd, dEnc(f, s.bases[k]))
					} else {
						encd = append(encd, c.Enc(f))
					}
				}
				r.encNs = float64(time.Since(st).Nanoseconds())
				st = time.Now()
				for k, e := range encd {
					var d []byte
					var err error
					if c.Dec == nil {
						d, err = dDec(e, s.bases[k])
					} else {
						d, err = c.Dec(e)
					}
					if err != nil || !bytes.Equal(d, s.frames[k]) {
						t.Fatalf("%s/%s frame %d: round trip failed: %v", s.name, c.Name, k, err)
					}
				}
				r.decNs = float64(time.Since(st).Nanoseconds())
				for _, e := range encd {
					r.enc = append(r.enc, len(e))
				}
				res[c.Name] = append(res[c.Name], r)
			}
		}
		total := func(codec string, pad, thresh int) (rawB, effB, dg, frames, compressed int, sizes []int) {
			for si, s := range sess {
				for k, f := range s.frames {
					c := res[codec][si].enc[k]
					if len(f) < thresh {
						c = len(f) // below threshold: not compressed
					} else if codec != "raw" {
						compressed++
					}
					e := eff(len(f), c, pad)
					rawB += len(f)
					effB += e
					dg += datagrams(e)
					frames++
					sizes = append(sizes, e)
				}
			}
			slices.Sort(sizes)
			return
		}
		fmt.Fprintln(&report, "\nAll sessions. 'eff' = 1 flag byte + min(compressed, raw). Static dictionaries leave-one-out; prevscreen = the frame's base screen as a preset dictionary.")
		fmt.Fprintln(&report, "\n| codec | total eff bytes | ratio vs raw | median frame | p99 frame | datagrams | enc µs/frame | dec µs/frame |")
		fmt.Fprintln(&report, "|---|---|---|---|---|---|---|---|")
		for _, n := range names {
			rawB, effB, dg, frames, _, sizes := total(n, 1, 0)
			var en, de float64
			for _, r := range res[n] {
				en += r.encNs
				de += r.decNs
			}
			fmt.Fprintf(&report, "| %s | %d | %.3f | %d | %d | %d | %.1f | %.1f |\n", n, effB, float64(effB)/float64(rawB),
				sizes[len(sizes)/2], sizes[len(sizes)*99/100], dg, en/float64(frames)/1e3, de/float64(frames)/1e3)
		}
		if gi != 0 {
			continue
		}
		// Per-session ratios (review: the headline ratio is mostly `less`).
		fmt.Fprintln(&report, "\nPer session (no padding). byte ratio = eff bytes / raw bytes; frame-weighted = mean over frames of eff/raw.")
		fmt.Fprintln(&report, "\n| session | frames | raw bytes | flate-6 byte ratio | flate-6 frame-weighted | flate-6+prevscreen byte ratio | zstd-default byte ratio |")
		fmt.Fprintln(&report, "|---|---|---|---|---|---|---|")
		var fwAll float64
		nAll := 0
		for si, s := range sess {
			ratio := func(codec string) (float64, float64) {
				var r, e int
				var fw float64
				for k, f := range s.frames {
					x := eff(len(f), res[codec][si].enc[k], 1)
					r += len(f)
					e += x
					fw += float64(x) / float64(len(f))
				}
				return float64(e) / float64(r), fw / float64(len(s.frames))
			}
			fb, fw := ratio("flate-6")
			db, _ := ratio("flate-6+prevscreen")
			zb, _ := ratio("zstd-default")
			raw := 0
			for _, f := range s.frames {
				raw += len(f)
			}
			fwAll += fw * float64(len(s.frames))
			nAll += len(s.frames)
			fmt.Fprintf(&report, "| %s | %d | %d | %.3f | %.3f | %.3f | %.3f |\n", s.name, len(s.frames), raw, fb, fw, db, zb)
		}
		fmt.Fprintf(&report, "\nAll frames, flate-6 frame-weighted ratio: %.3f\n", fwAll/float64(nAll))
		// Padding (review: compression-length side channel).
		fmt.Fprintln(&report, "\nLength padding: eff rounded up to a multiple of the bucket. Ratios are against raw unpadded bytes.")
		fmt.Fprintln(&report, "\n| codec | pad bucket | total bytes | ratio vs raw | datagrams |")
		fmt.Fprintln(&report, "|---|---|---|---|---|")
		for _, n := range []string{"raw", "flate-6", "flate-6+prevscreen"} {
			for _, pad := range []int{1, 64, 128, 256} {
				rawB, effB, dg, _, _, _ := total(n, pad, 0)
				fmt.Fprintf(&report, "| %s | %d | %d | %.3f | %d |\n", n, pad, effB, float64(effB)/float64(rawB), dg)
			}
		}
		// Threshold (review: the ~64 B threshold was never measured). CPU is
		// estimated as the measured mean flate-6 encode time per frame times
		// the frames actually compressed.
		fmt.Fprintln(&report, "\nCompression threshold: frames shorter than T bytes are sent raw (flate-6, no padding). Encode time is estimated from the measured per-frame mean.")
		fmt.Fprintln(&report, "\n| T | frames compressed | total bytes | ratio vs raw | est. enc µs/frame |")
		fmt.Fprintln(&report, "|---|---|---|---|---|")
		var en float64
		for _, r := range res["flate-6"] {
			en += r.encNs
		}
		for _, th := range []int{0, 32, 64, 128} {
			rawB, effB, _, frames, comp, _ := total("flate-6", 1, th)
			per := en / float64(frames) / 1e3
			fmt.Fprintf(&report, "| %d | %d / %d | %d | %.3f | %.1f |\n", th, comp, frames, effB, float64(effB)/float64(rawB), per*float64(comp)/float64(frames))
		}
	}
	fmt.Fprintf(&report, "\nRecovered x/vt panics while rendering: %d (chunks excluded after a panic: %d)\n", EmulatorPanics, ExcludedChunks)
	t.Log(report.String())
	if out := os.Getenv("S5_O8_OUT"); out != "" {
		os.WriteFile(out, []byte(report.String()), 0o644)
	}
}

// TestFlateBombRejected: a DEFLATE stream that fits in one datagram and
// inflates to 512 KiB must be refused (here with a 64 KiB frame limit), not
// decoded.
func TestFlateBombRejected(t *testing.T) {
	defer func(m int) { MaxFrame = m }(MaxFrame)
	MaxFrame = 64 << 10
	c := Flate("flate-6", 6, nil)
	bomb := c.Enc(make([]byte, 512<<10))
	if len(bomb) > maxFrag {
		t.Fatalf("bomb is %d bytes", len(bomb))
	}
	if _, err := c.Dec(bomb); err != ErrTooBig {
		t.Fatalf("got %v, want ErrTooBig", err)
	}
	z := Zstd("zstd", zstd.SpeedDefault, nil, false)
	if _, err := z.Dec(z.Enc(make([]byte, 1<<20))); err == nil {
		t.Fatal("zstd bomb accepted")
	}
	_, dec := FlateDelta(6)
	if _, err := dec(bomb, nil); err != ErrTooBig {
		t.Fatalf("delta: got %v", err)
	}
}

// TestVTPanicOnSmallerScreen records a security finding for S2: replaying
// output produced for a 120x40 terminal into an 80x24 x/vt emulator panics
// inside the emulator (recovered by safeWrite and counted). Plain program
// output, at a fixed size, is enough.
func TestVTPanicOnSmallerScreen(t *testing.T) {
	paths, _ := filepath.Glob(filepath.Join(capturesDir(), "*.bin"))
	sort.Strings(paths)
	for _, p := range paths {
		ch, _ := LoadCapture(p)
		before := EmulatorPanics
		Frames(ch, 80, 24, 20*time.Millisecond)
		t.Logf("%s at 80x24: %d recovered emulator panics", filepath.Base(p), EmulatorPanics-before)
	}
}
