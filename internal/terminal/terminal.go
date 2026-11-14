// Package terminal is the client's own terminal: raw mode, its size and
// changes to it, and keystrokes in. While a session runs, the client
// writes to it only through package render.
//
// Raw mode is a separate step from opening, because the terminal must stay
// cooked until the handshake is done (bootstrap.md §4.3): ssh may still
// need it for a password prompt, which reads a line from /dev/tty, and in
// raw mode Enter sends CR and the prompt never ends.
package terminal

import (
	"errors"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"golang.org/x/term"
)

// Terminal is the user's terminal as the client uses it, so the client's
// tests can drive a session without one.
type Terminal interface {
	io.Reader
	io.Writer
	// Size is the window size in cells. A terminal that does not know says
	// 0, 0, and the caller picks a default.
	Size() (cols, rows int, err error)
	// Resized is signalled whenever the size may have changed (SIGWINCH),
	// or the screen may have been disturbed behind the client's back
	// (SIGCONT after a stop), so the client redraws in full.
	Resized() <-chan struct{}
	// Raw puts the terminal in raw mode for the session; Restore puts it
	// back as it was. Restore is safe to call more than once, and without
	// Raw.
	Raw() error
	Restore() error
}

// ErrNotATerminal is Open's answer when stdin or stdout is not a terminal:
// mosey is interactive, so there is nothing sensible to do with a pipe.
var ErrNotATerminal = errors.New("not a terminal")

// TTY is the process's real terminal.
type TTY struct {
	in, out *os.File

	mu    sync.Mutex
	saved *term.State // non-nil while raw

	sigs    chan os.Signal
	resized chan struct{}
	done    chan struct{}
}

// Open takes in and out, which must both be terminals, and starts watching
// for size changes. It leaves the mode alone: Raw is a separate step.
func Open(in, out *os.File) (*TTY, error) {
	if !term.IsTerminal(int(in.Fd())) || !term.IsTerminal(int(out.Fd())) {
		return nil, ErrNotATerminal
	}
	t := &TTY{
		in:      in,
		out:     out,
		sigs:    make(chan os.Signal, 1),
		resized: make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
	signal.Notify(t.sigs, syscall.SIGWINCH, syscall.SIGCONT)
	go t.watch()
	return t, nil
}

// watch turns signals into Resized, coalescing: one pending signal stands
// for any number, since the reader asks for the size afresh anyway.
func (t *TTY) watch() {
	for {
		select {
		case <-t.sigs:
			select {
			case t.resized <- struct{}{}:
			default:
			}
		case <-t.done:
			return
		}
	}
}

func (t *TTY) Read(p []byte) (int, error)  { return t.in.Read(p) }
func (t *TTY) Write(p []byte) (int, error) { return t.out.Write(p) }

// Size is the window size, from the output side, which is the one the
// user sees.
func (t *TTY) Size() (cols, rows int, err error) {
	return term.GetSize(int(t.out.Fd()))
}

func (t *TTY) Resized() <-chan struct{} { return t.resized }

// Raw puts the input side in raw mode: no echo, no line editing, and no
// signals from the keyboard, so Ctrl-C and Ctrl-Z go to the remote shell
// as bytes.
func (t *TTY) Raw() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.saved != nil {
		return nil
	}
	s, err := term.MakeRaw(int(t.in.Fd()))
	if err != nil {
		return err
	}
	t.saved = s
	return nil
}

// Restore puts the terminal back as Raw found it.
func (t *TTY) Restore() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.saved == nil {
		return nil
	}
	err := term.Restore(int(t.in.Fd()), t.saved)
	t.saved = nil
	return err
}

// Close restores the terminal and stops watching signals. It does not
// close in or out.
func (t *TTY) Close() error {
	signal.Stop(t.sigs)
	select {
	case <-t.done:
	default:
		close(t.done)
	}
	return t.Restore()
}

var _ Terminal = (*TTY)(nil)
