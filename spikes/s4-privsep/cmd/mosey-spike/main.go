// mosey-spike is the S4 privilege-separation spike: one static binary that
// re-executes itself into roles.
//
//	mosey-spike server [udp-addr]   session process: pty + shell + keys (layout B); prints CONNECT line
//	mosey-spike net                 network process (spawned by server; fd 3 = UDP, fd 4 = IPC)
//	mosey-spike emu                 emulator helper  (spawned by server; fd 3 = IPC)
//	mosey-spike client PORT KEY     toy client: stdin lines -> keystrokes, prints screen bytes
//	mosey-spike sleeper             red-team target: a same-user process that allows any ptracer
//	mosey-spike bench-seccomp       per-syscall filter overhead
//
// Environment (read by every role):
//
//	MOSEY_SPIKE_LAYOUT          A (net holds key) | B (session holds key, default) |
//	                            B2 (B, session sends) | C (spawner + sandboxed proto)
//	MOSEY_SPIKE_ROAM            validate (default) | trust (Mosh's rule)
//	MOSEY_SPIKE_SANDBOX         none | landlock | seccomp | both (default)
//	MOSEY_SPIKE_SECCOMP_ACTION  kill (default) | errno | log
//	MOSEY_SPIKE_SECCOMP_HOW     tsync (default) | prethread | entry
//	MOSEY_SPIKE_REDTEAM         1: net (A/B/B2) or proto (C) runs the attack battery;
//	                            emu: the emulator helper runs it; relabel: net relays
//	                            but replays and relabels genuine packets
//	MOSEY_SPIKE_STRESS          N: the net process churns the runtime for N seconds
//
// SPIKE CODE: a record, not production.
package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"mosey.spike/s4-privsep/sandbox"
)

var processStart = time.Now()

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: mosey-spike server|net|emu|client|sleeper|bench-seccomp")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "server":
		err = runServer(os.Args[2:])
	case "net":
		err = runNet()
	case "emu":
		err = runEmu()
	case "proto":
		err = runProto()
	case "client-rtt":
		err = runClientRTT(os.Args[2:])
	case "client-load":
		err = runClientLoad(os.Args[2:])
	case "client":
		err = runClient(os.Args[2:])
	case "sleeper":
		err = runSleeper()
	case "bench-ipc":
		err = runBenchIPC()
	case "bench-ipc-child":
		err = runBenchIPCChild()
	case "soak":
		err = runSoak()
	case "bench-seccomp":
		err = runBenchSeccomp()
	default:
		err = fmt.Errorf("unknown role %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "mosey-spike %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func seccompAction() sandbox.Action {
	switch env("MOSEY_SPIKE_SECCOMP_ACTION", "kill") {
	case "errno":
		return sandbox.Errno(unix.EPERM)
	case "log":
		return sandbox.Log
	}
	return sandbox.KillProcess
}

// procStatus returns selected /proc/self/status fields. Must be read before
// Landlock, which denies /proc like any other path.
func procStatus(keys ...string) map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return out
	}
	for _, l := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		for _, want := range keys {
			if k == want {
				out[k] = strings.TrimSpace(v)
			}
		}
	}
	return out
}

// applySandbox confines the current process according to the environment
// and logs one line describing what was done, for the harness to parse.
func applySandbox(role string, pol sandbox.Policy) {
	mode := env("MOSEY_SPIKE_SANDBOX", "both")
	how := env("MOSEY_SPIKE_SECCOMP_HOW", "tsync")
	st := procStatus("Seccomp", "Seccomp_filters", "NoNewPrivs", "Threads")
	logf := func(f string, a ...any) {
		fmt.Fprintf(os.Stderr, "[%s pid=%d] "+f+"\n", append([]any{role, os.Getpid()}, a...)...)
	}
	logf("pre-sandbox status: seccomp=%s filters=%s nnp=%s threads=%s (t+%v)", st["Seccomp"], st["Seccomp_filters"], st["NoNewPrivs"], st["Threads"], time.Since(processStart))

	// Not dumpable: a SIGSYS (or any crash) must not write this process's
	// memory to systemd-coredump (measured: it does by default), and
	// same-uid processes lose ptrace and /proc/<pid>/{mem,environ,fd}
	// regardless of the Yama setting. Process-wide (mm attribute).
	if env("MOSEY_SPIKE_DUMPABLE", "0") == "0" {
		if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
			logf("FATAL prctl(DUMPABLE): %v", err)
			os.Exit(3)
		}
	}

	if mode == "landlock" || mode == "both" {
		t0 := time.Now()
		r, err := sandbox.LandlockDenyAll()
		if err != nil {
			logf("FATAL landlock: %v", err)
			os.Exit(3)
		}
		logf("landlock: abi=%d fs=%#x net=%#x scoped=%#x futureUDP=%v futureUnix=%v tsync=%v allthreads=%v (%v)",
			r.ABI, r.HandledFS, r.HandledNet, r.Scoped, r.FutureUDP, r.FutureUnix, r.TSYNC, r.AllThreadsOK, time.Since(t0))
	}
	if mode == "seccomp" || mode == "both" {
		// counterfactuals: MOSEY_SPIKE_DROP=pread64,prctl removes entries
		if d := os.Getenv("MOSEY_SPIKE_DROP"); d != "" {
			drop := map[string]bool{}
			for _, n := range strings.Split(d, ",") {
				drop[n] = true
			}
			var keep []string
			for _, n := range pol.Allow {
				if !drop[n] {
					keep = append(keep, n)
				}
			}
			pol.Allow = keep
			fail := map[string]unix.Errno{}
			for n, e := range pol.Fail {
				if !drop[n] {
					fail[n] = e
				}
			}
			pol.Fail = fail
			logf("policy: dropped %s", d)
		}
		prog, missing, err := sandbox.Program(sandbox.Native, pol)
		if err != nil {
			logf("FATAL seccomp program: %v", err)
			os.Exit(3)
		}
		t0 := time.Now()
		if err := sandbox.InstallTSYNC(prog); err != nil {
			logf("FATAL seccomp: %v", err)
			os.Exit(3)
		}
		logf("seccomp: how=%s policy=%s insns=%d skipped=%v threads-at-install=%s (%v, t+%v)",
			how, pol.Name, len(prog), missing, st["Threads"], time.Since(t0), time.Since(processStart))
	}
}
