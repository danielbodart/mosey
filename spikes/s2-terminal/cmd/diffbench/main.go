// Command diffbench replays recorded program output through an emulator,
// takes a frame every -chunk bytes (a stand-in for SSP's 8 ms collection
// window, since the recordings carry no timing) and at every recorded
// checkpoint, and measures the structured cell diffs: bytes on the wire raw
// and deflated, and the server CPU time to snapshot+diff. Each diff is
// checked by applying it to a client frame.
package main

import (
	"bytes"
	"compress/flate"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"mosey.spike/s2-terminal/celldiff"
	"mosey.spike/s2-terminal/emu"
)

type Event struct {
	Off  int    `json:"off"`
	Kind string `json:"kind"`
	W    int    `json:"w,omitempty"`
	H    int    `json:"h,omitempty"`
}

func synth() map[string][]byte {
	var seq bytes.Buffer
	for i := 1; i <= 100000; i++ {
		fmt.Fprintf(&seq, "%d\r\n", i)
	}
	// A 200x60 full-screen redraw (htop-like) 500 times with changing numbers.
	var top bytes.Buffer
	for f := 0; f < 500; f++ {
		top.WriteString("\x1b[H")
		for y := 0; y < 60; y++ {
			fmt.Fprintf(&top, "\x1b[%d;1H\x1b[32m%6d\x1b[0m \x1b[1m%-40s\x1b[0m %5.1f%% %s", y+1, 1000+y, fmt.Sprintf("process-%d", (y*7+f)%97), float64((y*13+f*7)%1000)/10, strings.Repeat("|", (y+f)%60))
		}
	}
	return map[string][]byte{"synth-seq100k": seq.Bytes(), "synth-top200x60": top.Bytes()}
}

func main() {
	rec := flag.String("rec", "", "apprec directory")
	name := flag.String("emu", "tuios", "emulator")
	chunk := flag.Int("chunk", 1024, "bytes per frame")
	flag.Parse()
	fac, ok := emu.Get(*name)
	if !ok {
		log.Fatal("no emulator")
	}
	type input struct {
		raw  []byte
		evs  []Event
		w, h int
	}
	inputs := map[string]input{}
	if *rec != "" {
		paths, _ := filepath.Glob(filepath.Join(*rec, "*", "events.json"))
		for _, p := range paths {
			raw, _ := os.ReadFile(filepath.Join(filepath.Dir(p), "raw.bin"))
			var evs []Event
			b, _ := os.ReadFile(p)
			_ = json.Unmarshal(b, &evs)
			inputs[filepath.Base(filepath.Dir(p))] = input{raw, evs, 80, 24}
		}
	}
	for k, v := range synth() {
		w, h := 80, 24
		if strings.Contains(k, "200x60") {
			w, h = 200, 60
		}
		inputs[k] = input{raw: v, w: w, h: h}
	}
	var names []string
	for k := range inputs {
		names = append(names, k)
	}
	sort.Strings(names)

	fmt.Printf("emulator %s, frame every %d bytes\n\n", *name, *chunk)
	fmt.Println("| stream | raw bytes | frames | diff bytes | diff/raw | deflated diffs | mean diff | p99 snapshot+diff | mean snapshot+diff |")
	fmt.Println("|---|---|---|---|---|---|---|---|---|")
	for _, n := range names {
		in := inputs[n]
		e := fac.New(in.w, in.h)
		st := celldiff.NewStyles()
		cl := &celldiff.Client{}
		var prev *celldiff.Frame
		var diffBytes, zBytes, frames int
		var times []time.Duration
		var zb bytes.Buffer
		zw, _ := flate.NewWriter(&zb, flate.DefaultCompression)
		frame := func() {
			t0 := time.Now()
			cur := celldiff.Snapshot(e, st, nil)
			d := celldiff.Diff(prev, cur, st)
			times = append(times, time.Since(t0))
			if err := cl.Apply(d); err != nil || !celldiff.Equal(cl.F, cur) {
				log.Fatalf("%s: client diverged after frame %d (%v)", n, frames, err)
			}
			prev = cur
			frames++
			diffBytes += len(d)
			zb.Reset()
			zw.Reset(&zb)
			_, _ = zw.Write(d)
			_ = zw.Close()
			zBytes += min(zb.Len(), len(d)) // send whichever is smaller
		}
		frame()
		evi := 0
		for pos := 0; pos < len(in.raw); {
			end := min(pos+*chunk, len(in.raw))
			if evi < len(in.evs) && in.evs[evi].Off < end && in.evs[evi].Off >= pos {
				end = in.evs[evi].Off
			}
			e.Write(in.raw[pos:end])
			_ = e.Responses()
			pos = end
			for evi < len(in.evs) && in.evs[evi].Off <= pos {
				if in.evs[evi].Kind == "resize" {
					e.Resize(in.evs[evi].W, in.evs[evi].H)
				}
				evi++
			}
			frame()
		}
		sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
		var sum time.Duration
		for _, t := range times {
			sum += t
		}
		fmt.Printf("| %s | %d | %d | %d | %.2f | %d | %d B | %v | %v |\n", n, len(in.raw), frames, diffBytes,
			float64(diffBytes)/float64(len(in.raw)), zBytes, diffBytes/frames,
			times[len(times)*99/100].Round(time.Microsecond), (sum / time.Duration(len(times))).Round(time.Microsecond))
		e.Close()
	}
}
