package sandbox

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Landlock's rights by the ABI version that brought them
// (Documentation/userspace-api/landlock.rst). The ruleset handles every
// right the kernel knows and adds no rules, so everything handled is
// denied (server.md §6.2).
const (
	landlockFSv1 = unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG | unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM
	landlockFSv2 = landlockFSv1 | unix.LANDLOCK_ACCESS_FS_REFER
	landlockFSv3 = landlockFSv2 | unix.LANDLOCK_ACCESS_FS_TRUNCATE
	landlockFSv5 = landlockFSv3 | unix.LANDLOCK_ACCESS_FS_IOCTL_DEV

	landlockNetV4   = unix.LANDLOCK_ACCESS_NET_BIND_TCP | unix.LANDLOCK_ACCESS_NET_CONNECT_TCP
	landlockScopeV6 = unix.LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | unix.LANDLOCK_SCOPE_SIGNAL

	// Rights x/sys knows that no kernel S4 ran on accepted (6.18): offered
	// one at a time, used where the kernel takes them.
	landlockNetUDP     = unix.LANDLOCK_ACCESS_NET_BIND_UDP | unix.LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP
	landlockFSResolveU = unix.LANDLOCK_ACCESS_FS_RESOLVE_UNIX
)

// landlockAttr is the prefix of struct landlock_ruleset_attr that every ABI
// accepts: the kernel reads the size it is given, and x/sys's own struct
// has newer fields an older kernel refuses when they are non-zero.
type landlockAttr struct {
	fs, net, scoped uint64
}

// LandlockABI is the kernel's Landlock ABI version, or 0 with the reason
// when it has none: not built (ENOSYS), or built but not among the active
// LSMs (EOPNOTSUPP).
func LandlockABI() (int, error) {
	v, _, e := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if e != 0 {
		return 0, e
	}
	return int(v), nil
}

func landlockCreate(a landlockAttr) (int, syscall.Errno) {
	fd, _, e := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&a)), unsafe.Sizeof(a), 0)
	return int(fd), e
}

// landlockDenyAll restricts every thread, and anything they ever start, to
// no filesystem access beyond fds already open, no TCP, and (ABI 6) no
// abstract unix sockets or signals outside the domain. NO_NEW_PRIVS must
// already be set on every thread.
func landlockDenyAll(warn func(string)) error {
	abi, err := LandlockABI()
	if abi <= 0 {
		// The one non-fatal outcome (server.md §6.1): no Landlock at all.
		// seccomp alone still stops S4's battery and, with its argument
		// rules, keeps signals in.
		if err == nil || errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP) {
			warn(fmt.Sprintf("landlock unavailable (%v); carrying on with seccomp alone", err))
			return nil
		}
		return fmt.Errorf("probing the landlock ABI: %w", err)
	}

	var attr landlockAttr
	switch {
	case abi >= 5:
		attr.fs = landlockFSv5
	case abi >= 3:
		attr.fs = landlockFSv3
	case abi >= 2:
		attr.fs = landlockFSv2
	default:
		attr.fs = landlockFSv1
	}
	if abi >= 4 {
		attr.net = landlockNetV4
	}
	if abi >= 6 {
		attr.scoped = landlockScopeV6
	}
	optionals := []landlockAttr{{fs: landlockFSResolveU}}
	if abi >= 4 {
		// Below ABI 4 the kernel's struct has no net field at all.
		optionals = append(optionals, landlockAttr{net: landlockNetUDP})
	}
	for _, optional := range optionals {
		fd, e := landlockCreate(optional)
		switch e {
		case 0:
			unix.Close(fd)
			attr.fs |= optional.fs
			attr.net |= optional.net
		case unix.EINVAL, unix.E2BIG:
			// Not a right this kernel knows, or (E2BIG) a field past the
			// end of its struct: the expected answers where a feature is
			// missing.
		default:
			return fmt.Errorf("probing an optional landlock right: %w", e)
		}
	}

	fd, e := landlockCreate(attr)
	if e != 0 {
		return fmt.Errorf("landlock_create_ruleset: %w", e)
	}
	defer unix.Close(fd)

	// Kernels with LANDLOCK_RESTRICT_SELF_TSYNC apply the domain to every
	// thread in one call; older ones (6.18) only to the caller, so the same
	// call is made on every thread, as go-landlock does through psx.
	_, _, e = unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(fd), unix.LANDLOCK_RESTRICT_SELF_TSYNC, 0)
	switch e {
	case 0:
		return nil
	case unix.EINVAL:
	default:
		return fmt.Errorf("landlock_restrict_self(TSYNC): %w", e)
	}
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(fd), 0, 0); e != 0 {
		return fmt.Errorf("landlock_restrict_self on every thread: %w", e)
	}
	return nil
}
