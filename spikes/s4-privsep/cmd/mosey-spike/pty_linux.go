package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

// openPTY opens a pty pair with x/sys/unix only (no creack/pty dependency).
func openPTY() (master, slave *os.File, name string, err error) {
	m, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, "", err
	}
	if err := unix.IoctlSetPointerInt(m, unix.TIOCSPTLCK, 0); err != nil {
		unix.Close(m)
		return nil, nil, "", fmt.Errorf("unlockpt: %w", err)
	}
	n, err := unix.IoctlGetInt(m, unix.TIOCGPTN)
	if err != nil {
		unix.Close(m)
		return nil, nil, "", fmt.Errorf("ptsname: %w", err)
	}
	name = fmt.Sprintf("/dev/pts/%d", n)
	s, err := unix.Open(name, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		unix.Close(m)
		return nil, nil, "", err
	}
	return os.NewFile(uintptr(m), "ptmx"), os.NewFile(uintptr(s), name), name, nil
}

// startShell runs shell as a session leader with the pty as its controlling
// terminal, as a login shell would be (D14).
func startShell(shell string, slave *os.File, env []string) (*exec.Cmd, error) {
	c := exec.Command(shell)
	c.Args = []string{"-" + baseName(shell)} // argv[0] "-sh": login shell convention
	c.Stdin, c.Stdout, c.Stderr = slave, slave, slave
	c.Env = env
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	return c, c.Start()
}

func baseName(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}
