package pty

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

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

func winsize(size Size) *unix.Winsize {
	return &unix.Winsize{Col: uint16(size.Cols), Row: uint16(size.Rows)}
}

func control(f *os.File, fn func(fd int) error) error {
	raw, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var ferr error
	// Control, not Fd: Fd would switch the master to blocking mode.
	if err := raw.Control(func(fd uintptr) { ferr = fn(int(fd)) }); err != nil {
		return err
	}
	return ferr
}

func setSize(master *os.File, size Size) error {
	if size.Cols < 1 || size.Cols > 0xffff || size.Rows < 1 || size.Rows > 0xffff {
		return fmt.Errorf("pty: size %dx%d", size.Cols, size.Rows)
	}
	return control(master, func(fd int) error {
		return unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, winsize(size))
	})
}

// getSize uses TIOCGWINSZ, which proto's sandbox does not allow: it is for
// the spawner and tests.
func getSize(f *os.File) (Size, error) {
	var size Size
	err := control(f, func(fd int) error {
		ws, err := unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ)
		if err != nil {
			return err
		}
		size = Size{int(ws.Col), int(ws.Row)}
		return nil
	})
	return size, err
}

func echoOff(master *os.File) (bool, error) {
	var off bool
	err := control(master, func(fd int) error {
		t, err := unix.IoctlGetTermios(fd, unix.TCGETS)
		if err != nil {
			return err
		}
		off = t.Lflag&unix.ECHO == 0 && t.Lflag&unix.ICANON != 0
		return nil
	})
	return off, err
}

func echoes(master *os.File) (bool, error) {
	var on bool
	err := control(master, func(fd int) error {
		t, err := unix.IoctlGetTermios(fd, unix.TCGETS)
		if err != nil {
			return err
		}
		on = t.Lflag&unix.ECHO != 0
		return nil
	})
	return on, err
}

func foregroundRoot(master *os.File) (bool, error) {
	var pgrp int
	err := control(master, func(fd int) error {
		var err error
		pgrp, err = unix.IoctlGetInt(fd, unix.TIOCGPGRP)
		return err
	})
	if err != nil {
		return false, fmt.Errorf("reading the pty's foreground process group: %w", err)
	}
	if pgrp <= 0 {
		return false, nil
	}
	return rootIn("/proc", pgrp), nil
}

func sessionLeader() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
}
