package main

import (
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"mosey.spike/s4-privsep/sandbox"
)

var sink [][]byte

var stressGOMAXPROCS = os.Getenv("MOSEY_SPIKE_STRESS_GOMAXPROCS") == "1"

// stressRuntime churns the parts of the Go runtime that make syscalls
// rarely: thread creation (blocking syscalls), GC, scavenger (madvise),
// FreeOSMemory, async preemption (tgkill SIGURG), timers, goroutine stacks
// growing and shrinking, GOMAXPROCS changes. Used for syscall discovery under
// strace and for soak runs under a KILL filter.
func stressRuntime(secs int) {
	deadline := time.Now().Add(time.Duration(secs) * time.Second)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			i := 0
			for time.Now().Before(deadline) {
				i++
				// allocation churn, some large (direct mmap spans)
				b := make([]byte, 1<<(10+i%14))
				sink = append(sink, b)
				if len(sink) > 256 {
					sink = sink[:0]
				}
				// deep recursion -> stack growth/copy
				if i%97 == 0 {
					recurse(2000)
				}
				// tight loop with no calls -> async preemption
				if i%101 == 0 {
					x := 0
					for j := 0; j < 50_000_000; j++ {
						x += j
					}
					_ = x
				}
				// a blocking syscall forces handoff + new M creation
				if i%53 == 0 {
					var ts = unix.Timespec{Nsec: 200_000}
					unix.Nanosleep(&ts, nil)
				}
				if i%211 == 0 {
					runtime.GC()
				}
				if i%509 == 0 {
					debug.FreeOSMemory()
				}
				// Calling runtime.GOMAXPROCS disables Go >= 1.25's periodic
				// GOMAXPROCS updates (sched_getaffinity + pread64 of cgroup
				// cpu.max), which hid that path from the first soak run. Off
				// unless MOSEY_SPIKE_STRESS_GOMAXPROCS=1.
				if stressGOMAXPROCS && i%307 == 0 {
					runtime.GOMAXPROCS(1 + i%runtime.NumCPU())
				}
				if i%31 == 0 {
					time.Sleep(time.Millisecond)
					t := time.AfterFunc(time.Microsecond, func() {})
					t.Stop()
				}
				if i%41 == 0 {
					ch := make(chan int)
					for k := 0; k < 64; k++ {
						go func() { ch <- k }()
					}
					for k := 0; k < 64; k++ {
						<-ch
					}
				}
			}
		}(w)
	}
	wg.Wait()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	fmt.Fprintf(os.Stderr, "[stress pid=%d] done %ds: numGC=%d goroutines=%d\n", os.Getpid(), secs, ms.NumGC, runtime.NumGoroutine())
}

//go:noinline
func recurse(n int) int {
	var pad [64]byte
	if n == 0 {
		return int(pad[0])
	}
	return recurse(n-1) + int(pad[n%64])
}

// runSleeper is a red-team target: a separate same-uid process that has
// opted out of Yama (PR_SET_PTRACER_ANY) so that what stops ptrace, if
// anything, is our sandbox and not Yama.
func runSleeper() error {
	unix.Prctl(unix.PR_SET_PTRACER, unix.PR_SET_PTRACER_ANY, 0, 0, 0)
	fmt.Printf("SLEEPER %d\n", os.Getpid())
	os.Stdout.Sync()
	time.Sleep(10 * time.Minute)
	return nil
}

// runBenchSeccomp measures getppid(2) cost with no filter, then with the
// net filter installed (getppid is not in the allow-list, so we measure an
// allowed call: getpid via the raw syscall, which walks most of the list).
func runBenchSeccomp() error {
	const n = 2_000_000
	measure := func() time.Duration {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		t0 := time.Now()
		for i := 0; i < n; i++ {
			unix.RawSyscall(unix.SYS_GETPID, 0, 0, 0)
		}
		return time.Since(t0) / n
	}
	measure()
	base := measure()
	prog, _, _ := sandbox.Program(sandbox.Native, sandbox.NetPolicy(sandbox.KillProcess))
	if err := sandbox.InstallTSYNC(prog); err != nil {
		return err
	}
	measure()
	filt := measure()
	fmt.Printf("getpid: %v/call unfiltered, %v/call with %d-insn filter (+%v)\n", base, filt, len(prog), filt-base)
	return nil
}
