// Package sandbox is the S4 spike's Landlock + seccomp layer, written against
// golang.org/x/sys/unix only (no go-landlock, no libseccomp, no cgo).
//
// SPIKE CODE: a record of what was tried, not production code.
package sandbox

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Landlock access rights by the ABI version that introduced them
// (Documentation/userspace-api/landlock.rst).
const (
	fsV1 = unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG | unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM
	fsV2 = fsV1 | unix.LANDLOCK_ACCESS_FS_REFER
	fsV3 = fsV2 | unix.LANDLOCK_ACCESS_FS_TRUNCATE
	fsV5 = fsV3 | unix.LANDLOCK_ACCESS_FS_IOCTL_DEV

	netV4 = unix.LANDLOCK_ACCESS_NET_BIND_TCP | unix.LANDLOCK_ACCESS_NET_CONNECT_TCP

	scopeV6 = unix.LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | unix.LANDLOCK_SCOPE_SIGNAL

	// Newer than the 6.18 kernel this spike ran on; x/sys v0.50.0 already
	// carries them. Probed for, used when the kernel accepts them.
	fsFuture     = unix.LANDLOCK_ACCESS_FS_RESOLVE_UNIX
	netFutureUDP = unix.LANDLOCK_ACCESS_NET_BIND_UDP | unix.LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP
)

// LandlockABI returns the kernel's Landlock ABI version, or 0 if Landlock is
// unavailable (not built, not in the lsm= list, or disabled).
func LandlockABI() int {
	v, _, e := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if e != 0 {
		return 0
	}
	return int(v)
}

// rulesetAttr is the ABI-1..7 prefix of struct landlock_ruleset_attr
// (x/sys v0.50 has a longer one with newer "quiet" fields). The kernel takes
// the size we pass, so passing this prefix works on every ABI.
type rulesetAttr struct {
	fs, net, scoped uint64
}

// LandlockReport says what was enforced, for FINDINGS.
type LandlockReport struct {
	ABI          int
	HandledFS    uint64
	HandledNet   uint64
	Scoped       uint64
	FutureUDP    bool // LANDLOCK_ACCESS_NET_*_UDP accepted by the kernel
	FutureUnix   bool // LANDLOCK_ACCESS_FS_RESOLVE_UNIX accepted
	TSYNC        bool // LANDLOCK_RESTRICT_SELF_TSYNC used instead of AllThreadsSyscall
	AllThreadsOK bool
}

// LandlockDenyAll restricts every thread of this process (and its future
// children) to: no filesystem access at all beyond already-open fds, no TCP
// bind/connect, no abstract unix sockets or signals outside the domain.
// It is best-effort by ABI: on a kernel without a right, that right is simply
// not handled (and the report says so).
func LandlockDenyAll() (LandlockReport, error) {
	var r LandlockReport
	r.ABI = LandlockABI()
	if r.ABI == 0 {
		return r, errors.New("landlock unavailable")
	}
	attr := rulesetAttr{}
	switch {
	case r.ABI >= 5:
		attr.fs = fsV5
	case r.ABI >= 3:
		attr.fs = fsV3
	case r.ABI >= 2:
		attr.fs = fsV2
	default:
		attr.fs = fsV1
	}
	if r.ABI >= 4 {
		attr.net = netV4
	}
	if r.ABI >= 6 {
		attr.scoped = scopeV6
	}

	create := func(a rulesetAttr) (int, syscall.Errno) {
		fd, _, e := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET,
			uintptr(unsafe.Pointer(&a)), unsafe.Sizeof(a), 0)
		return int(fd), e
	}
	// Probe the not-yet-released rights one at a time.
	if fd, e := create(rulesetAttr{net: netFutureUDP}); e == 0 {
		unix.Close(fd)
		attr.net |= netFutureUDP
		r.FutureUDP = true
	}
	if fd, e := create(rulesetAttr{fs: fsFuture}); e == 0 {
		unix.Close(fd)
		attr.fs |= fsFuture
		r.FutureUnix = true
	}

	fd, e := create(attr)
	if e != 0 {
		return r, fmt.Errorf("landlock_create_ruleset: %w", e)
	}
	defer unix.Close(fd)
	r.HandledFS, r.HandledNet, r.Scoped = attr.fs, attr.net, attr.scoped

	// no_new_privs is per-thread; set it on every thread first.
	if err := AllThreadsNoNewPrivs(); err != nil {
		return r, err
	}
	// Newer kernels: one call, kernel applies it to all threads.
	if _, _, e := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(fd), unix.LANDLOCK_RESTRICT_SELF_TSYNC, 0); e == 0 {
		r.TSYNC = true
		return r, nil
	}
	// 6.18: restrict_self only applies to the calling thread. Go's
	// syscall.AllThreadsSyscall (Go >= 1.16, CGO_ENABLED=0 only) runs the
	// same syscall on every M, which is what go-landlock does via psx.
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(fd), 0, 0); e != 0 {
		return r, fmt.Errorf("landlock_restrict_self (all threads): %w", e)
	}
	r.AllThreadsOK = true
	return r, nil
}

// AllThreadsNoNewPrivs sets PR_SET_NO_NEW_PRIVS on every OS thread.
func AllThreadsNoNewPrivs() error {
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); e != 0 {
		return fmt.Errorf("prctl(NO_NEW_PRIVS) all threads: %w", e)
	}
	return nil
}
