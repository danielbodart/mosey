//go:build linux || darwin

package pty

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// This file holds what Linux and macOS share: the window size, termios
// and foreground-group ioctls, and the rules for root and idle. Each
// platform file gives open, getTermios (the ioctl that reads termios), and
// how to read a process's effective uid and its session's members:
// /proc on Linux, sysctl kern.proc on macOS (server.md §10).

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
		t, err := unix.IoctlGetTermios(fd, getTermios)
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
		t, err := unix.IoctlGetTermios(fd, getTermios)
		if err != nil {
			return err
		}
		on = t.Lflag&unix.ECHO != 0
		return nil
	})
	return on, err
}

func foregroundGroup(master *os.File) (int, error) {
	var pgrp int
	err := control(master, func(fd int) error {
		var err error
		pgrp, err = unix.IoctlGetInt(fd, unix.TIOCGPGRP)
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("reading the pty's foreground process group: %w", err)
	}
	return pgrp, nil
}

// foregroundRoot asks the platform about the foreground group's leader
// only: a group's id is its leader's pid.
func foregroundRoot(master *os.File) (bool, error) {
	pgrp, err := foregroundGroup(master)
	if err != nil {
		return false, err
	}
	if pgrp <= 0 {
		return false, nil
	}
	return processRoot(pgrp), nil
}

func sessionIdle(master *os.File, shellPID int) (bool, error) {
	if shellPID <= 0 {
		return false, fmt.Errorf("invalid shell pid %d", shellPID)
	}
	fg, err := foregroundGroup(master)
	if err != nil {
		return false, err
	}
	if fg != shellPID {
		return false, nil
	}
	other, err := otherSessionMember(shellPID)
	if err != nil {
		return false, err
	}
	return !other, nil
}

// sessionLeader makes the child setsid and then take fd 0, the slave, as
// its controlling terminal (TIOCSCTTY), on both platforms.
func sessionLeader() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
}
