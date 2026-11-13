package fuzz

import (
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"mosey.spike/s2-terminal/celldiff"
	"mosey.spike/s2-terminal/emu"
)

// FuzzTuiosClamp answers the S2 review: the first fuzz run capped resizes at
// 200x100 and had no memory invariant. Here a 0xFE byte followed by four
// bytes is a resize to any size up to the planned client clamp
// (celldiff.MaxCols x MaxRows), and the live heap of the worker is checked
// after a GC every 256 inputs against a per-session budget.
//
//	go test ./fuzz -run '^$' -fuzz '^FuzzTuiosClamp$' -fuzztime 20m -parallel 3

// clampHeapBudget: tuios costs about 116 B per on-screen cell (S2 hostile
// battery, 5000x5000), so a 1000x500 session with its alternate screen is
// about 110 MiB before scrollback; fuzz inputs are a few KiB, so scrollback
// adds little. 384 MiB leaves room for GC slack.
const clampHeapBudget = 384 << 20

var clampN atomic.Int64

func FuzzTuiosClamp(f *testing.F) {
	fac, _ := emu.Get("tuios")
	seeds(f, "tuios")
	f.Add([]byte("\xfe\x03\xe7\x01\xf3\x1b[999;999Hx\x1b[?1049h\x1b[2Jy\xfe\x00\x01\x00\x01z"))
	f.Add([]byte("\xfe\xff\xff\xff\xff\x1b[65535b\x1b[1000L\x1b[1000@"))
	f.Fuzz(func(t *testing.T, data []byte) {
		e := fac.New(80, 24)
		defer e.Close()
		start := time.Now()
		big := false
		for len(data) > 0 {
			i := 0
			for i < len(data) && data[i] != 0xFE {
				i++
			}
			if i > 0 {
				e.Write(data[:i])
			}
			data = data[i:]
			if len(data) >= 5 {
				w, h := celldiff.ClampSize(1+(int(data[1])<<8|int(data[2]))%celldiff.MaxCols, 1+(int(data[3])<<8|int(data[4]))%celldiff.MaxRows)
				e.Resize(w, h)
				big = big || w*h > 200*100
				data = data[5:]
			} else if len(data) > 0 {
				e.Write(data)
				data = nil
			}
			_ = e.Responses()
			if !big {
				check(t, e)
			}
			if d := time.Since(start); d > budget {
				fail(t, "input took %v (> %v)", d, budget)
			}
		}
		check(t, e)
		if clampN.Add(1)%256 == 0 {
			runtime.GC()
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			if m.HeapAlloc > clampHeapBudget {
				fail(t, "heap %d MiB after GC > %d MiB", m.HeapAlloc>>20, clampHeapBudget>>20)
			}
		}
	})
}
