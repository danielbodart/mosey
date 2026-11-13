// Command hostile measures how each candidate copes with hostile output:
// huge CSI parameters and repeat counts, sixel and kitty graphics with huge
// declared sizes, very long and unterminated OSC/DCS strings, unbounded
// grapheme clusters, hyperlink and style churn, title-stack floods and
// resize storms.
//
// Each (emulator, case) runs in a child process (this binary with -child)
// under a watchdog that kills it at -timeout or when its RSS passes -maxrss.
// The parent reports wall time, peak RSS and the outcome.
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"mosey.spike/s2-terminal/celldiff"
	"mosey.spike/s2-terminal/emu"
)

// A case writes its stream to w through feed, which forwards it to the
// emulator in 64 KiB writes. Resize-storm cases also get the emulator.
type hcase struct {
	name, desc string
	run        func(e emu.Emulator, feed func([]byte))
}

func rep(s string, n int) []byte { return bytes.Repeat([]byte(s), n) }

// stream feeds total bytes made of chunk repeated.
func stream(feed func([]byte), prefix string, chunk []byte, total int, suffix string) {
	feed([]byte(prefix))
	block := bytes.Repeat(chunk, max(1, 65536/len(chunk)))
	for sent := 0; sent < total; sent += len(block) {
		feed(block)
	}
	feed([]byte(suffix))
}

var cases = []hcase{
	{"csi-huge-params", "CUP/ICH/DCH/IL/DL/ECH/SU/SD with 2^31-1 and 20-digit params, 10k times", func(e emu.Emulator, f func([]byte)) {
		seq := "\x1b[2147483647;2147483647H\x1b[2147483647@\x1b[2147483647P\x1b[2147483647L\x1b[2147483647M\x1b[2147483647X\x1b[2147483647S\x1b[2147483647T\x1b[99999999999999999999;99999999999999999999H\x1b[2147483647I\x1b[2147483647Z"
		for i := 0; i < 10000; i++ {
			f([]byte("x" + seq))
		}
	}},
	{"csi-many-params", "one SGR with 1,000,000 parameters", func(e emu.Emulator, f func([]byte)) {
		stream(f, "\x1b[", []byte("1;"), 2_000_000, "1mX")
	}},
	{"rep-intmax", "'x' then REP 2^31-1", func(e emu.Emulator, f func([]byte)) { f([]byte("x\x1b[2147483647b")) }},
	{"rep-overflow", "'x' then REP with a 19-digit count (the charm fuzz hang)", func(e emu.Emulator, f func([]byte)) { f([]byte("x\x1b[2147483600000047b")) }},
	{"rep-65535-x10k", "REP 65535, 10,000 times", func(e emu.Emulator, f func([]byte)) {
		for i := 0; i < 10000; i++ {
			f([]byte("x\x1b[65535b"))
		}
	}},
	{"sixel-huge-raster", "sixel declaring 30000x30000 and repeating 2^31 columns", func(e emu.Emulator, f func([]byte)) {
		f([]byte("\x1bPq\"1;1;30000;30000#0;2;100;0;0#0!2147483647~-!2147483647~\x1b\\"))
	}},
	{"sixel-many-bands", "sixel 4000 px wide x 10000 bands (60000 px tall)", func(e emu.Emulator, f func([]byte)) {
		stream(f, "\x1bPq#0;2;100;0;0#0", []byte("!4000~-"), 10000*7, "\x1b\\")
	}},
	{"kitty-huge-declared", "kitty graphics a=T f=32 s=v=100000, 64 MiB of base64 in chunks", func(e emu.Emulator, f func([]byte)) {
		f([]byte("\x1b_Ga=T,f=32,s=100000,v=100000,i=1,m=1;AAAA\x1b\\"))
		chunk := []byte("\x1b_Gm=1;" + strings.Repeat("AAAA", 1024) + "\x1b\\")
		for sent := 0; sent < 64<<20; sent += len(chunk) {
			f(chunk)
		}
		f([]byte("\x1b_Gm=0;AAAA\x1b\\"))
	}},
	{"kitty-many-images", "10,000 distinct 1x1 kitty images", func(e emu.Emulator, f func([]byte)) {
		for i := 1; i <= 10000; i++ {
			f([]byte(fmt.Sprintf("\x1b_Ga=T,f=24,s=1,v=1,i=%d;AAAA\x1b\\", i)))
		}
	}},
	{"osc-title-64MiB", "OSC 2 title of 64 MiB, terminated", func(e emu.Emulator, f func([]byte)) {
		stream(f, "\x1b]2;", []byte("A"), 64<<20, "\x07")
	}},
	{"osc-unterminated-256MiB", "OSC 2 never terminated, 256 MiB", func(e emu.Emulator, f func([]byte)) {
		stream(f, "\x1b]2;", []byte("A"), 256<<20, "")
	}},
	{"osc52-64MiB", "OSC 52 clipboard set, 64 MiB base64", func(e emu.Emulator, f func([]byte)) {
		stream(f, "\x1b]52;c;", []byte("QUFB"), 64<<20, "\x07")
	}},
	{"dcs-unterminated-256MiB", "DCS never terminated, 256 MiB", func(e emu.Emulator, f func([]byte)) {
		stream(f, "\x1bP1$r", []byte("A"), 256<<20, "")
	}},
	{"osc8-1M-links", "1,000,000 distinct OSC 8 hyperlinks, one per cell", func(e emu.Emulator, f func([]byte)) {
		for i := 0; i < 1_000_000; i++ {
			f([]byte(fmt.Sprintf("\x1b]8;id=%d;https://example.com/%d\x1b\\x", i, i)))
		}
	}},
	{"title-stack-1M", "XTWINOPS push title 1,000,000 times with distinct titles", func(e emu.Emulator, f func([]byte)) {
		for i := 0; i < 1_000_000; i++ {
			f([]byte(fmt.Sprintf("\x1b]2;title %d\x07\x1b[22;0t", i)))
		}
	}},
	{"grapheme-1M-combining", "one base char followed by 1,000,000 combining marks", func(e emu.Emulator, f func([]byte)) {
		stream(f, "e", []byte("́"), 2_000_000, "\r\n")
	}},
	{"zwj-chain-1M", "a ZWJ emoji chain 1,000,000 long", func(e emu.Emulator, f func([]byte)) {
		stream(f, "👨", []byte("‍👩"), 7_000_000, "\r\n")
	}},
	{"truecolor-churn", "16M cells each with a distinct RGB fg/bg", func(e emu.Emulator, f func([]byte)) {
		var b bytes.Buffer
		for i := 0; i < 1<<24; i++ {
			fmt.Fprintf(&b, "\x1b[38;2;%d;%d;%d;48;2;%d;%d;%dmx", i>>16&255, i>>8&255, i&255, i&255, i>>16&255, i>>8&255)
			if b.Len() > 60000 {
				f(b.Bytes())
				b.Reset()
			}
		}
		f(b.Bytes())
	}},
	{"scrollback-flood", "1 GiB of 200-column lines", func(e emu.Emulator, f func([]byte)) {
		stream(f, "", []byte(strings.Repeat("y", 199)+"\n"), 1<<30, "")
	}},
	{"altscreen-toggle", "1,000,000 alt-screen enter/leave with output", func(e emu.Emulator, f func([]byte)) {
		stream(f, "", []byte("\x1b[?1049hA\x1b[?1049lB"), 20_000_000, "")
	}},
	{"dsr-flood", "1,000,000 DSR/DA queries (responses drained per write)", func(e emu.Emulator, f func([]byte)) {
		stream(f, "", []byte("\x1b[6n\x1b[c\x1b[>c"), 14_000_000, "")
	}},
	{"sync-never-ends", "mode 2026 opened and never closed, then 10 MiB output", func(e emu.Emulator, f func([]byte)) {
		stream(f, "\x1b[?2026h", []byte("abcdefgh\r\n"), 10<<20, "")
	}},
	{"resize-storm", "100,000 resizes between 1x1 and 300x100 with output between", func(e emu.Emulator, f func([]byte)) {
		seed := uint32(1)
		for i := 0; i < 100_000; i++ {
			seed = seed*1664525 + 1013904223
			e.Resize(1+int(seed>>8)%300, 1+int(seed>>20)%100)
			f([]byte("漢字 hello 👍🏽 world\r\n\x1b[5;5Hx"))
		}
	}},
	// Cases added for the S2 review: sizes up to the client clamp, and cells
	// as expensive as a program can make them.
	{"resize-to-clamp", "resize to the clamp (1000x500) then back, 20 times, writing in the corner", func(e emu.Emulator, f func([]byte)) {
		for i := 0; i < 20; i++ {
			e.Resize(celldiff.ClampSize(5000, 5000))
			f([]byte("\x1b[?1049h\x1b[500;1000Hx\x1b[?1049l\x1b[500;1000Hx"))
			e.Resize(80, 24)
		}
	}},
	{"resize-storm-clamp", "2,000 resizes between 1x1 and 1000x500 with output between", func(e emu.Emulator, f func([]byte)) {
		seed := uint32(1)
		for i := 0; i < 2000; i++ {
			seed = seed*1664525 + 1013904223
			e.Resize(celldiff.ClampSize(1+int(seed>>8)%1000, 1+int(seed>>20)%500))
			f([]byte("漢字 hello 👍🏽 world\r\n\x1b[5;5Hx"))
		}
	}},
	{"cluster-color-scrollback", "12,000 full-width lines of 63-byte clusters, each cell a distinct truecolour", func(e emu.Emulator, f func([]byte)) {
		w, _ := e.Size()
		cl := "e" + strings.Repeat("\u0301", 31)
		var b bytes.Buffer
		n := 0
		for l := 0; l < 12000; l++ {
			for x := 0; x < w; x++ {
				n++
				fmt.Fprintf(&b, "\x1b[38;2;%d;%d;%dm%s", n&255, n>>8&255, n>>16&255, cl)
			}
			b.WriteString("\r\n")
			if b.Len() > 60000 {
				f(b.Bytes())
				b.Reset()
			}
		}
		f(b.Bytes())
	}},
	{"osc8-long-links", "a distinct 2 KiB OSC 8 URI on every cell, 512 MiB in all", func(e emu.Emulator, f func([]byte)) {
		pad := strings.Repeat("x", 2000)
		for i := 0; i < (512<<20)/2048; i++ {
			f([]byte(fmt.Sprintf("\x1b]8;;https://example.invalid/%d/%s\x1b\\x", i, pad)))
		}
	}},
	{"resize-huge", "resize to 5000x5000 then back, 20 times (host-controlled; shows per-size cost)", func(e emu.Emulator, f func([]byte)) {
		for i := 0; i < 20; i++ {
			e.Resize(5000, 5000)
			f([]byte("\x1b[5000;5000Hx"))
			e.Resize(80, 24)
		}
	}},
}

func child(name, cname string) {
	fac, ok := emu.Get(name)
	if !ok {
		fmt.Println("RESULT missing")
		os.Exit(3)
	}
	var c *hcase
	for i := range cases {
		if cases[i].name == cname {
			c = &cases[i]
		}
	}
	if c == nil {
		fmt.Println("RESULT nocase")
		os.Exit(3)
	}
	w0, h0 := 80, 24
	if v := os.Getenv("MOSEY_HOSTILE_SIZE"); v != "" {
		fmt.Sscanf(v, "%dx%d", &w0, &h0)
	}
	e := fac.New(w0, h0)
	var fed, calls atomic.Int64
	feed := func(p []byte) {
		calls.Add(1)
		for len(p) > 0 {
			n := min(len(p), 65536)
			e.Write(p[:n])
			_ = e.Responses()
			fed.Add(int64(n))
			p = p[n:]
		}
	}
	start := time.Now()
	// Progress lines let the parent report throughput for a run it kills.
	go func() {
		for range time.Tick(250 * time.Millisecond) {
			fmt.Printf("PROGRESS %d %d %d\n", fed.Load(), calls.Load(), time.Since(start).Milliseconds())
		}
	}()
	c.run(e, feed)
	// Touch the screen so lazily-applied work happens.
	_ = emu.Text(e)
	el := time.Since(start)
	w, h := e.Size()
	fmt.Printf("RESULT ok fed=%d elapsed_ms=%d size=%dx%d title_len=%d\n", fed.Load(), el.Milliseconds(), w, h, len(e.Title()))
}

func rssKB(pid int) int {
	fh, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "VmRSS:"); ok {
			n, _ := strconv.Atoi(strings.Fields(v)[0])
			return n
		}
	}
	return 0
}

func main() {
	ch := flag.Bool("child", false, "")
	emus := flag.String("emus", strings.Join(emu.Names(), ","), "")
	only := flag.String("cases", "", "comma-separated case names (default all)")
	timeout := flag.Duration("timeout", 20*time.Second, "")
	maxRSS := flag.Int("maxrss", 4<<20, "kill above this RSS, KiB")
	size := flag.String("size", "80x24", "session size for every case (the S2 review reran at the clamp, 1000x500)")
	list := flag.Bool("list", false, "list cases")
	flag.Parse()
	if *ch {
		child(flag.Arg(0), flag.Arg(1))
		return
	}
	if *list {
		for _, c := range cases {
			fmt.Printf("%-26s %s\n", c.name, c.desc)
		}
		return
	}
	sel := map[string]bool{}
	for _, s := range strings.Split(*only, ",") {
		if s != "" {
			sel[s] = true
		}
	}
	self, _ := os.Executable()
	_ = os.Setenv("MOSEY_HOSTILE_SIZE", *size)
	fmt.Printf("| case | %s |\n|---|%s\n", strings.ReplaceAll(*emus, ",", " | "), strings.Repeat("---|", len(strings.Split(*emus, ","))))
	for _, c := range cases {
		if len(sel) > 0 && !sel[c.name] {
			continue
		}
		names := strings.Split(*emus, ",")
		results := make([]string, len(names))
		var wg sync.WaitGroup
		for i, name := range names {
			wg.Add(1)
			go func() {
				defer wg.Done()
				results[i] = measure(self, name, c.name, *timeout, *maxRSS)
			}()
		}
		wg.Wait()
		fmt.Printf("| %s | %s |\n", c.name, strings.Join(results, " | "))
	}
}

func measure(self, name, cname string, timeout time.Duration, maxRSS int) string {
	{
		{
			cmd := exec.Command(self, "-child", name, cname)
			cmd.Env = append(os.Environ(), "GOMAXPROCS=2")
			var out bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = io.Discard
			start := time.Now()
			if err := cmd.Start(); err != nil {
				return "start error"
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			peak, verdict := 0, ""
			tick := time.NewTicker(25 * time.Millisecond)
		loop:
			for {
				select {
				case err := <-done:
					if err != nil && verdict == "" {
						if ee, ok := err.(*exec.ExitError); ok && ee.Sys().(syscall.WaitStatus).Signaled() {
							verdict = "killed:" + ee.Sys().(syscall.WaitStatus).Signal().String()
						} else {
							verdict = "CRASH"
						}
					}
					break loop
				case <-tick.C:
					r := rssKB(cmd.Process.Pid)
					peak = max(peak, r)
					if r > maxRSS {
						verdict = fmt.Sprintf("OOM>%dMiB", maxRSS>>10)
						_ = cmd.Process.Kill()
					} else if time.Since(start) > timeout {
						verdict = fmt.Sprintf("TIMEOUT>%s", timeout)
						_ = cmd.Process.Kill()
					}
				}
			}
			tick.Stop()
			if ps := cmd.ProcessState; ps != nil {
				if ru, ok := ps.SysUsage().(*syscall.Rusage); ok {
					peak = max(peak, int(ru.Maxrss))
				}
			}
			el := time.Since(start)
			if verdict == "" {
				if strings.Contains(out.String(), "RESULT ok") {
					verdict = "ok"
				} else {
					verdict = "CRASH"
				}
			}
			// Throughput from the child's last progress line (fed bytes, feed
			// calls, ms), so a run killed at the timeout still says how far
			// it got.
			rate := ""
			lines := strings.Split(strings.TrimSpace(out.String()), "\n")
			for i := len(lines) - 1; i >= 0; i-- {
				var fb, calls, ms int64
				if n, _ := fmt.Sscanf(lines[i], "PROGRESS %d %d %d", &fb, &calls, &ms); n == 3 && ms > 0 {
					rate = fmt.Sprintf(" (%.1f MB/s, %d writes)", float64(fb)/1e3/float64(ms), calls)
					break
				}
			}
			if verdict == "ok" {
				rate = ""
			}
			return fmt.Sprintf("%s %.1fs %dMiB%s", verdict, el.Seconds(), peak>>10, rate)
		}
	}
}
