// Package fuzz holds one go-fuzz target per candidate emulator. Each target
// treats the input as a program's output, with an escape hatch for resizes,
// and checks only things every emulator must guarantee: no panic, no hang
// (a per-input wall-clock budget), the cursor stays on the screen, and every
// cell can be read back.
//
// Run one at a time, e.g.
//
//	go test ./fuzz -run '^$' -fuzz '^FuzzTuios$' -fuzztime 20m -parallel 3
package fuzz

import (
	"fmt"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"mosey.spike/s2-terminal/emu"
)

// budget is the wall-clock time one input may take. Inputs are capped by the
// fuzzer at a few KiB, so anything near this is a quadratic or worse path.
const budget = 3 * time.Second

// known lists seeds that already fail for a candidate (recorded in
// FINDINGS.md). They are left out of that candidate's fuzz corpus, because a
// failing seed stops go's fuzzer before it starts.
var known = map[string]map[string]bool{
	"xtermgo": {"x\x1b[2147483647b": true}, // REP INT_MAX: 23 s of CPU
}

func seeds(f *testing.F, name string) {
	for _, s := range []string{
		"hello\r\nworld",
		"\x1b[2J\x1b[H\x1b[1;31mred\x1b[0m",
		"\x1b[?1049h\x1b[10;20r\x1b[5S\x1b[3T\x1b[?1049l",
		"\x1b[99999999;99999999H\x1b[999999999@\x1b[999999999P",
		"\x1b[65535b",       // REP
		"x\x1b[2147483647b", // REP huge
		"\x1b]0;title\x07\x1b]8;;http://x\x1b\\link\x1b]8;;\x1b\\",
		"\x1b]52;c;aGVsbG8=\x07",
		"\x1bP0;1;0q#0;2;0;0;0#0!100~-\x1b\\", // sixel
		"\x1b_Ga=T,f=24,s=1,v=1;AAAA\x1b\\",   // kitty graphics
		"\x1b#8\x1b#6\x1b#3",
		"\x1b(0lqk\x1b(B",
		"é 👍🏽 漢字 🇬🇧 ‍",
		"\x1b[?3h\x1b[?3l\x1b[?6h\x1b[?69h\x1b[5;10s",
		"\x1b[38;2;1;2;3;48;5;200;58:2::1:2:3m",
		"\xff\x00\x10\x05abc", // resize op
		"\x1bc\x1b[!p\x1b[?2026h\x1b[?2026l",
	} {
		if known[name][s] {
			continue
		}
		f.Add([]byte(s))
	}
}

// run feeds data to e. A 0xFF byte followed by two bytes is a resize to
// (1+b1%200, 1+b2%100); everything else is terminal output.
func run(t *testing.T, newEmu func(w, h int) emu.Emulator, data []byte) {
	e := newEmu(80, 24)
	defer e.Close()
	start := time.Now()
	chunk := data
	for len(chunk) > 0 {
		i := 0
		for i < len(chunk) && chunk[i] != 0xFF {
			i++
		}
		if i > 0 {
			e.Write(chunk[:i])
		}
		chunk = chunk[i:]
		if len(chunk) >= 3 {
			e.Resize(1+int(chunk[1])%200, 1+int(chunk[2])%100)
			chunk = chunk[3:]
		} else if len(chunk) > 0 {
			e.Write(chunk)
			chunk = nil
		}
		check(t, e)
		_ = e.Responses()
		if d := time.Since(start); d > budget {
			fail(t, "input took %v (> %v)", d, budget)
		}
	}
}

func check(t *testing.T, e emu.Emulator) {
	w, h := e.Size()
	if w < 1 || h < 1 || w > 10000 || h > 10000 {
		fail(t, "size %dx%d", w, h)
	}
	x, y, _ := e.Cursor()
	if x < 0 || y < 0 || x > w || y >= h {
		fail(t, "cursor %d,%d outside %dx%d", x, y, w, h)
	}
	for yy := 0; yy < h; yy++ {
		for xx := 0; xx < w; xx++ {
			c := e.CellAt(xx, yy)
			if c.Width > 2 {
				fail(t, "cell %d,%d width %d", xx, yy, c.Width)
			}
		}
	}
}

func target(f *testing.F, name string) {
	fac, ok := emu.Get(name)
	if !ok {
		f.Skipf("%s not compiled in", name)
	}
	seeds(f, name)
	logPath := os.Getenv("MOSEY_FUZZ_RECOVER")
	if logPath == "" {
		f.Fuzz(func(t *testing.T, data []byte) { run(t, fac.New, data) })
		return
	}
	// Recover mode: record every distinct failure site and keep fuzzing, so a
	// bounded run counts distinct bugs instead of stopping at the first.
	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			r := recover()
			if r == nil {
				return
			}
			kind := "panic"
			msg := fmt.Sprint(r)
			if fl, ok := r.(failure); ok {
				kind, msg = "invariant", string(fl)
			}
			record(logPath, kind, msg, siteOf(debug.Stack(), kind), data)
		}()
		run(t, fac.New, data)
	})
}

type failure string

func fail(t *testing.T, format string, args ...any) {
	if os.Getenv("MOSEY_FUZZ_RECOVER") != "" {
		panic(failure(fmt.Sprintf(format, args...)))
	}
	t.Helper()
	t.Fatalf(format, args...)
}

// siteOf picks the innermost stack frame outside the runtime and this
// harness: the emulator function that panicked.
func siteOf(stack []byte, kind string) string {
	if kind != "panic" {
		return kind
	}
	for _, l := range strings.Split(string(stack), "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "runtime") || strings.HasPrefix(l, "panic(") ||
			strings.HasPrefix(l, "testing.") || strings.HasPrefix(l, "goroutine") ||
			strings.HasPrefix(l, "/") || strings.HasPrefix(l, "mosey.spike") || l == "" {
			continue
		}
		if i := strings.LastIndex(l, "("); i > 0 {
			return l[:i]
		}
		return l
	}
	return "unknown"
}

var recMu sync.Mutex
var seen = map[string]bool{}

func record(path, kind, msg, site string, data []byte) {
	recMu.Lock()
	defer recMu.Unlock()
	key := site + "|" + firstWord(msg)
	if seen[key] {
		return
	}
	seen[key] = true
	fh, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer fh.Close()
	fmt.Fprintf(fh, "%s\t%s\t%s\t%q\n", kind, site, msg, data)
}

func firstWord(s string) string {
	if i := strings.IndexAny(s, "0123456789"); i > 0 {
		return s[:i]
	}
	return s
}

func FuzzTuios(f *testing.F)   { target(f, "tuios") }
func FuzzCharm(f *testing.F)   { target(f, "charm") }
func FuzzXtermgo(f *testing.F) { target(f, "xtermgo") }
func FuzzCy(f *testing.F)      { target(f, "cy") }
func FuzzGhostty(f *testing.F) { target(f, "ghostty") }
