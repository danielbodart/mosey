// Command memworst measures the most memory a remote program can make one
// tuios.dev/vt session hold, as a function of the window size, the
// scrollback line cap and what each cell carries. It answers the S2 review:
// the 1.2 MiB figure was an 80x24 session of cheap cells.
//
// Each run writes `lines` full-width lines in which every cell is as
// expensive as the program can make it:
//
//	plain   one ASCII byte, default style            (the cheap baseline)
//	color   one ASCII byte, distinct truecolour fg+bg, bold+italic+underline
//	cluster a 64-byte grapheme cluster (tuios' cap) with a distinct colour
//	link    as color, plus a distinct OSC 8 URI of `linklen` bytes per cell
//
// It reports the Go heap after a forced GC, at several points, so the cost
// per history line (and per cell) can be read off the slope. Run each case
// in its own process (scripts/memworst.sh does, inside a systemd scope with
// a hard MemoryMax) so one case cannot distort the next.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"tuios.dev/vt"
)

func heapMiB() float64 {
	runtime.GC()
	debug.FreeOSMemory()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return float64(m.HeapAlloc) / (1 << 20)
}

func rssMiB() float64 {
	b, _ := os.ReadFile("/proc/self/status")
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "VmRSS:") {
			var kb float64
			fmt.Sscanf(strings.TrimSpace(l[6:]), "%f", &kb)
			return kb / 1024
		}
	}
	return 0
}

func main() {
	cols := flag.Int("cols", 200, "columns")
	rows := flag.Int("rows", 60, "rows")
	sb := flag.Int("scrollback", 10000, "scrollback line cap")
	lines := flag.Int("lines", 12000, "lines to write")
	mode := flag.String("mode", "cluster", "plain|color|cluster|link")
	linkLen := flag.Int("linklen", 2048, "OSC 8 URI length for mode=link")
	flag.Parse()

	t := vt.NewWithScrollback(*cols, *rows, *sb)
	fmt.Printf("backend=%T\n", t)
	base := heapMiB()
	// A 64-byte cluster: 'e' + 31 x U+0301 (2 bytes each) = 63 bytes, which
	// tuios keeps as one cell (cap 64). Each cell gets a different colour so
	// no style can be shared.
	cluster := "e" + strings.Repeat("\u0301", 31)
	pad := strings.Repeat("x", max(0, *linkLen-40))
	var buf bytes.Buffer
	n := 0
	start := time.Now()
	report := func(done int) {
		h := heapMiB()
		fmt.Printf("%s cols=%d rows=%d sb=%d lines=%d heap_mib=%.1f rss_mib=%.1f per_line_kib=%.2f per_cell_b=%.1f elapsed_s=%.1f\n",
			*mode, *cols, *rows, *sb, done, h-base, rssMiB(),
			(h-base)*1024/float64(min(done, *sb+*rows)),
			(h-base)*(1<<20)/float64(min(done, *sb+*rows)*(*cols)),
			time.Since(start).Seconds())
	}
	marks := map[int]bool{*lines / 4: true, *lines / 2: true, *lines: true}
	for l := 1; l <= *lines; l++ {
		buf.Reset()
		for x := 0; x < *cols; x++ {
			n++
			switch *mode {
			case "plain":
				buf.WriteByte('a' + byte(x%26))
				continue
			case "color", "cluster", "link":
				fmt.Fprintf(&buf, "\x1b[1;3;4;38;2;%d;%d;%d;48;2;%d;%d;%dm", n&255, n>>8&255, n>>16&255, (n*7)&255, (n*13)&255, (n*31)&255)
			}
			if *mode == "link" {
				fmt.Fprintf(&buf, "\x1b]8;;https://example.invalid/%012d/%s\x1b\\", n, pad)
			}
			if *mode == "cluster" {
				buf.WriteString(cluster)
			} else {
				buf.WriteByte('a' + byte(x%26))
			}
		}
		buf.WriteString("\x1b[0m\x1b]8;;\x1b\\\r\n")
		_, _ = t.Write(buf.Bytes())
		_ = t.TakeResponses()
		if marks[l] {
			report(l)
		}
	}
}
