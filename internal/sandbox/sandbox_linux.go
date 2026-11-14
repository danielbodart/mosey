package sandbox

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Native is the architecture this binary was built for, whose filter Enter
// installs. Only amd64 and arm64 servers are built (D10).
func Native() (Arch, error) {
	switch runtime.GOARCH {
	case "amd64":
		return AMD64, nil
	case "arm64":
		return ARM64, nil
	}
	return 0, fmt.Errorf("sandbox: no seccomp policy for %s", runtime.GOARCH)
}

func enter(role Role, action Action, params Params, warn func(string)) error {
	return enterWith(PolicyFor(role), action, params, warn, true)
}

// enterWith is Enter for any policy, so tests can confine a child with a
// policy of their own; landlock false skips Landlock, for the test of
// server.md §12 that shows seccomp alone keeps signals in.
func enterWith(p Policy, action Action, params Params, warn func(string), landlock bool) error {
	arch, err := Native()
	if err != nil {
		return err
	}
	if params.Pid == 0 {
		params.Pid = os.Getpid()
	}
	// Compiled first, so a policy error costs nothing half applied.
	prog, err := Compile(arch, p, action, params)
	if err != nil {
		return err
	}

	// The runtime makes its netpoller (epoll_create1, eventfd2) the first
	// time anything needs it, a timer included, and dies if that fails.
	// The roles wrap their fds before Enter, which makes it, but a filter
	// that a stray time.Sleep could turn into a crash is too fragile: make
	// sure here, with a pipe the poller registers.
	if r, w, err := os.Pipe(); err == nil {
		r.Close()
		w.Close()
	}

	// Before anything else: with dumpable left at 1, a seccomp kill writes
	// a core holding the keys (S4 §3.5), and the user's other processes
	// could ptrace this one or read its memory.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl(PR_SET_DUMPABLE, 0): %w", err)
	}
	// no_new_privs is per thread, and both landlock_restrict_self and an
	// unprivileged seccomp filter refuse a thread without it.
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); e != 0 {
		return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS) on every thread: %w", e)
	}
	if landlock {
		if err := landlockDenyAll(warn); err != nil {
			return err
		}
	}
	return installTSYNC(prog)
}

// installTSYNC installs prog on every thread of the process at once.
func installTSYNC(prog []Instruction) error {
	filter := make([]unix.SockFilter, len(prog))
	for i, in := range prog {
		filter[i] = unix.SockFilter{Code: in.Code, Jt: in.JT, Jf: in.JF, K: in.K}
	}
	fprog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	r, _, e := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER,
		unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&fprog)))
	runtime.KeepAlive(filter)
	if e != 0 {
		return fmt.Errorf("seccomp(SET_MODE_FILTER, TSYNC): %w", e)
	}
	if r != 0 {
		// TSYNC's non-zero return is a thread that could not be
		// synchronised, one with a filter of its own: that thread would run
		// unconfined, so it is an error.
		return fmt.Errorf("seccomp(TSYNC): thread %d could not be synchronised", r)
	}
	return nil
}
