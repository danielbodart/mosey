package pty

import "golang.org/x/sys/unix"

const (
	// setTermios is the ioctl that writes termios on Linux.
	setTermios = unix.TCSETS
	// inputQueue is the ioctl that says how many bytes of input wait.
	inputQueue = unix.TIOCINQ
)
