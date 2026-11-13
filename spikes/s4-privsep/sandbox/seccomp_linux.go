package sandbox

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Native is the Arch this binary runs on.
var Native = func() Arch {
	switch runtime.GOARCH {
	case "amd64":
		return AMD64
	case "arm64":
		return ARM64
	}
	panic("unsupported arch " + runtime.GOARCH)
}()

func seccompSet(flags uintptr, prog []unix.SockFilter) (uintptr, unix.Errno) {
	fp := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	r, _, e := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, flags, uintptr(unsafe.Pointer(&fp)))
	runtime.KeepAlive(prog)
	return r, e
}

// InstallTSYNC installs prog on every thread of the process at once
// (SECCOMP_FILTER_FLAG_TSYNC). The calling thread needs no_new_privs; the
// kernel copies it to the other threads as it syncs them.
//
// Approach (1) of the spike: after the Go runtime has started its threads.
func InstallTSYNC(prog []unix.SockFilter) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl(NO_NEW_PRIVS): %w", err)
	}
	r, e := seccompSet(unix.SECCOMP_FILTER_FLAG_TSYNC, prog)
	if e != 0 {
		return fmt.Errorf("seccomp(TSYNC): %w", e)
	}
	if r != 0 {
		// TSYNC returns the TID of a thread that could not be synced
		// (one that already has a divergent filter).
		return fmt.Errorf("seccomp(TSYNC): thread %d could not be synchronised", r)
	}
	return nil
}

// InstallThisThread installs prog on the calling OS thread only. The caller
// must have locked its goroutine to the thread and should never unlock it,
// so the thread dies with the goroutine. Used by approach (2a): fork the
// child from this thread so the child image starts already filtered.
func InstallThisThread(prog []unix.SockFilter) error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl(NO_NEW_PRIVS): %w", err)
	}
	if _, e := seccompSet(0, prog); e != 0 {
		return fmt.Errorf("seccomp: %w", e)
	}
	return nil
}
