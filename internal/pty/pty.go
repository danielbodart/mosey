// Package pty opens pseudo-terminals and starts login shells on them. It
// is the spawner's, the one unsandboxed role (D22): the spawner opens the
// pty, starts the shell on its slave side, and hands the master to proto
// over SCM_RIGHTS.
package pty

import (
	"os"
)

// Size is a window size in cells.
type Size struct{ Cols, Rows int }

// Open makes a new pty at the given size and returns its master and slave.
func Open(size Size) (master, slave *os.File, err error) {
	return open(size)
}

// SetSize sets the window size on a pty master; the kernel sends the
// shell's process group SIGWINCH.
func SetSize(master *os.File, size Size) error {
	return setSize(master, size)
}

// EchoOff reads the slave's termios through the master and says whether
// echo is off in canonical mode (!ECHO && ICANON), the D12 echo-off bit.
func EchoOff(master *os.File) (bool, error) {
	return echoOff(master)
}

// Shell is how to start the user's login shell (D14): their shell from the
// password database, as a login shell, in their home directory.
type Shell struct {
	// Env is the environment the bootstrap carried (TERM, COLORTERM, the
	// locale), on top of the server's own.
	Env []string
}

// Start starts the login shell as the session leader with slave as its
// controlling terminal, and closes slave in this process.
func (s Shell) Start(slave *os.File) (*os.Process, error) {
	panic("TODO slice 1")
}
