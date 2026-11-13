// Command perf measures per-session memory and parse throughput for each
// candidate, each in its own child process so RSS (which includes C
// allocations for the libghostty backend) is attributable.
//
//	memory: RSS growth per session for 100 sessions of 80x24 (a) fresh and
//	        (b) after 10,000 lines of 100-column coloured output each
//	        (scrollback depth is each backend's default; noted below).
//	speed:  MB/s for plain text, SGR-heavy text, a recorded app stream mix,
//	        and the CPU of an idle session (none: emulators have no timers).
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"mosey.spike/s2-terminal/emu"
)

func rssKB() int {
	fh, _ := os.Open("/proc/self/status")
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

func settle() int {
	runtime.GC()
	debug.FreeOSMemory()
	time.Sleep(50 * time.Millisecond)
	return rssKB()
}

func coloured(lines int) []byte {
	var b bytes.Buffer
	for i := 0; i < lines; i++ {
		fmt.Fprintf(&b, "\x1b[3%dm%06d\x1b[0m %s \x1b[1mbold\x1b[0m %s\r\n", i%8, i, strings.Repeat("lorem ipsum ", 6), strings.Repeat("x", 10))
	}
	return b.Bytes()
}

func child(name, rec string) {
	f, _ := emu.Get(name)
	// memory
	base := settle()
	var es []emu.Emulator
	for i := 0; i < 100; i++ {
		es = append(es, f.New(80, 24))
	}
	fresh := settle()
	data := coloured(10000)
	for _, e := range es {
		e.Write(data)
		_ = e.Responses()
	}
	full := settle()
	runtime.KeepAlive(es)
	fmt.Printf("MEM fresh_per_session_KiB=%d filled_per_session_KiB=%d\n", (fresh-base)/100, (full-base)/100)
	for _, e := range es {
		e.Close()
	}
	es = nil

	// throughput
	plain := bytes.Repeat([]byte(strings.Repeat("the quick brown fox jumps over the lazy dog ", 2)+"\r\n"), 200000)
	sgr := coloured(200000)
	var mix []byte
	if rec != "" {
		paths, _ := filepath.Glob(filepath.Join(rec, "*", "raw.bin"))
		var one []byte
		for _, p := range paths {
			b, _ := os.ReadFile(p)
			one = append(one, b...)
			one = append(one, "\x1b[?1049l\x1b[0m\x1bc"...) // reset between programs
		}
		for len(mix) < 16<<20 && len(one) > 0 {
			mix = append(mix, one...)
		}
	}
	for _, w := range []struct {
		n string
		d []byte
	}{{"plain", plain}, {"sgr", sgr}, {"apps", mix}} {
		if len(w.d) == 0 {
			continue
		}
		e := f.New(80, 24)
		t0 := time.Now()
		for p := 0; p < len(w.d); p += 4096 {
			e.Write(w.d[p:min(p+4096, len(w.d))])
			_ = e.Responses()
		}
		el := time.Since(t0)
		e.Close()
		fmt.Printf("SPEED %s %.1f\n", w.n, float64(len(w.d))/1e6/el.Seconds())
	}
}

func main() {
	if len(os.Args) > 2 && os.Args[1] == "-child" {
		child(os.Args[2], os.Args[3])
		return
	}
	emus := flag.String("emus", strings.Join(emu.Names(), ","), "")
	rec := flag.String("rec", "", "apprec directory for the app-mix stream")
	flag.Parse()
	self, _ := os.Executable()
	fmt.Println("| emulator | RSS per fresh 80x24 session | RSS per session after 10k coloured lines | plain MB/s | SGR MB/s | recorded-apps MB/s |")
	fmt.Println("|---|---|---|---|---|---|")
	for _, n := range strings.Split(*emus, ",") {
		cmd := exec.Command(self, "-child", n, *rec)
		cmd.Env = append(os.Environ(), "GOMAXPROCS=1")
		out, err := cmd.Output()
		if err != nil {
			fmt.Printf("| %s | error %v |\n", n, err)
			continue
		}
		var fresh, full int
		sp := map[string]string{}
		for _, l := range strings.Split(string(out), "\n") {
			fmt.Sscanf(l, "MEM fresh_per_session_KiB=%d filled_per_session_KiB=%d", &fresh, &full)
			if f := strings.Fields(l); len(f) == 3 && f[0] == "SPEED" {
				sp[f[1]] = f[2]
			}
		}
		fmt.Printf("| %s | %d KiB | %d KiB | %s | %s | %s |\n", n, fresh, full, sp["plain"], sp["sgr"], sp["apps"])
	}
}
