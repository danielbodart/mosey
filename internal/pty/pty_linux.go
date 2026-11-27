package pty

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// getTermios is the ioctl that reads termios on Linux.
const getTermios = unix.TCGETS

func open(size Size) (master, slave *os.File, err error) {
	m, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("opening /dev/ptmx: %w", err)
	}
	fail := func(what string, err error) (*os.File, *os.File, error) {
		unix.Close(m)
		return nil, nil, fmt.Errorf("%s: %w", what, err)
	}
	if err := unix.IoctlSetPointerInt(m, unix.TIOCSPTLCK, 0); err != nil {
		return fail("unlocking the pty", err)
	}
	// TIOCGPTPEER opens the slave from the master itself, so no path is
	// looked up (a /dev/pts that is not ours could be mounted there), on
	// every kernel since 4.13; the path is the fallback.
	r, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(m), unix.TIOCGPTPEER, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC)
	s := int(r)
	if errno != 0 {
		n, nerr := unix.IoctlGetInt(m, unix.TIOCGPTN)
		if nerr != nil {
			return fail("naming the pty", nerr)
		}
		s, err = unix.Open(fmt.Sprintf("/dev/pts/%d", n), unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
		if err != nil {
			return fail("opening the pty's slave", err)
		}
	}
	if err := unix.IoctlSetWinsize(m, unix.TIOCSWINSZ, winsize(size)); err != nil {
		unix.Close(s)
		return fail("setting the pty's size", err)
	}
	return os.NewFile(uintptr(m), "ptmx"), os.NewFile(uintptr(s), "pts"), nil
}

// processRoot reads the Uid line of /proc/PID/status.
func processRoot(pid int) bool { return rootIn("/proc", pid) }

// otherSessionMember walks /proc for the stat files.
func otherSessionMember(sid int) (bool, error) { return hasOtherSessionMember("/proc", sid) }
