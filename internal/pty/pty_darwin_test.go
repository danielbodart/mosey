package pty

import "golang.org/x/sys/unix"

const (
	// setTermios is the ioctl that writes termios on macOS.
	setTermios = unix.TIOCSETA
	// inputQueue is FIONREAD, _IOR('f', 127, int) in sys/filio.h: macOS
	// has no TIOCINQ, and x/sys has no FIONREAD for darwin.
	inputQueue = 0x4004667f
)
