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
	"sort"
	"strconv"
	"strings"
	"syscall"
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
		c0 := cpuTime()
		t0 := time.Now()
		for p := 0; p < len(w.d); p += 4096 {
			e.Write(w.d[p:min(p+4096, len(w.d))])
			_ = e.Responses()
		}
		el := time.Since(t0)
		cpu := cpuTime() - c0
		e.Close()
		// Both wall-clock and CPU-time rates: CPU time (user+sys of the whole
		// process, so GC counts) is much less sensitive to other load on the
		// machine than wall time, which includes time spent descheduled.
		fmt.Printf("SPEED %s %.1f %.1f\n", w.n, float64(len(w.d))/1e6/el.Seconds(), float64(len(w.d))/1e6/cpu.Seconds())
	}
}

func cpuTime() time.Duration {
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

// med returns "median [min-max]" of xs.
func med(xs []float64) string {
	if len(xs) == 0 {
		return "-"
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	m := s[len(s)/2]
	if len(s)%2 == 0 {
		m = (s[len(s)/2-1] + s[len(s)/2]) / 2
	}
	if len(s) == 1 {
		return fmt.Sprintf("%.1f", m)
	}
	return fmt.Sprintf("%.1f [%.1f-%.1f]", m, s[0], s[len(s)-1])
}

func main() {
	if len(os.Args) > 2 && os.Args[1] == "-child" {
		child(os.Args[2], os.Args[3])
		return
	}
	emus := flag.String("emus", strings.Join(emu.Names(), ","), "")
	rec := flag.String("rec", "", "apprec directory for the app-mix stream")
	reps := flag.Int("reps", 1, "repetitions per emulator (interleaved); report median [min-max]")
	flag.Parse()
	self, _ := os.Executable()
	names := strings.Split(*emus, ",")
	type acc struct {
		fresh, full []float64
		wall, cpu   map[string][]float64
	}
	res := map[string]*acc{}
	for _, n := range names {
		res[n] = &acc{wall: map[string][]float64{}, cpu: map[string][]float64{}}
	}
	for r := 0; r < *reps; r++ {
		for _, n := range names {
			cmd := exec.Command(self, "-child", n, *rec)
			cmd.Env = append(os.Environ(), "GOMAXPROCS=1")
			out, err := cmd.Output()
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v\n", n, err)
				continue
			}
			a := res[n]
			for _, l := range strings.Split(string(out), "\n") {
				var fresh, full int
				if k, _ := fmt.Sscanf(l, "MEM fresh_per_session_KiB=%d filled_per_session_KiB=%d", &fresh, &full); k == 2 {
					a.fresh = append(a.fresh, float64(fresh))
					a.full = append(a.full, float64(full))
				}
				if f := strings.Fields(l); len(f) == 4 && f[0] == "SPEED" {
					w, _ := strconv.ParseFloat(f[2], 64)
					c, _ := strconv.ParseFloat(f[3], 64)
					a.wall[f[1]] = append(a.wall[f[1]], w)
					a.cpu[f[1]] = append(a.cpu[f[1]], c)
				}
			}
		}
	}
	fmt.Printf("%d repetitions, interleaved; each cell is median [min-max].\n\n", *reps)
	fmt.Println("| emulator | RSS KiB, fresh 80x24 session | RSS KiB after 10k coloured lines | plain MB/s wall | plain MB per CPU-s | SGR MB/s wall | SGR MB per CPU-s | apps MB/s wall | apps MB per CPU-s |")
	fmt.Println("|---|---|---|---|---|---|---|---|---|")
	for _, n := range names {
		a := res[n]
		fmt.Printf("| %s | %s | %s | %s | %s | %s | %s | %s | %s |\n", n, med(a.fresh), med(a.full),
			med(a.wall["plain"]), med(a.cpu["plain"]), med(a.wall["sgr"]), med(a.cpu["sgr"]), med(a.wall["apps"]), med(a.cpu["apps"]))
	}
}
