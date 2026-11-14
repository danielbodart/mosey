// Package terminal is the client's own terminal: raw mode, its size and
// changes to it, and keystrokes in. The client writes to it only through
// package render.
package terminal

import (
	"io"
	"os"

	"golang.org/x/term"
)

// Terminal is the user's terminal as the client uses it, so the client's
// tests can drive a session without one.
type Terminal interface {
	io.Reader
	io.Writer
	Size() (cols, rows int, err error)
	// Resized is signalled whenever the size may have changed (SIGWINCH).
	Resized() <-chan struct{}
}

// TTY is the process's real terminal.
type TTY struct{}

// Open puts f, which must be a terminal, in raw mode. Restore puts it back.
func Open(in, out *os.File) (*TTY, error) {
	_ = term.MakeRaw // holds the pinned dependency in go.mod until this is written
	panic("TODO slice 1")
}

func (t *TTY) Read(p []byte) (int, error)        { panic("TODO slice 1") }
func (t *TTY) Write(p []byte) (int, error)       { panic("TODO slice 1") }
func (t *TTY) Size() (cols, rows int, err error) { panic("TODO slice 1") }
func (t *TTY) Resized() <-chan struct{}          { panic("TODO slice 1") }
func (t *TTY) Restore() error                    { panic("TODO slice 1") }

var _ Terminal = (*TTY)(nil)
