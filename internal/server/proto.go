package server

import (
	"context"
	"io"
	"log/slog"

	"github.com/danielbodart/mosey/internal/emu"
	"github.com/danielbodart/mosey/internal/screen"
	"github.com/danielbodart/mosey/internal/ssp"
	"github.com/danielbodart/mosey/internal/transport"
	"github.com/danielbodart/mosey/internal/userinput"
)

// The two SSP objects, checked here, where both are used together.
var (
	_ ssp.State[*screen.Grid]      = (*screen.Grid)(nil)
	_ ssp.State[*userinput.Stream] = (*userinput.Stream)(nil)
)

// Terminal is the shell's pty as proto sees it.
type Terminal interface {
	io.ReadWriter
	// Resize sets the window size, after the clamp.
	Resize(cols, rows int) error
	// EchoOff is the D12 echo-off bit: !ECHO && ICANON on the slave.
	EchoOff() (bool, error)
}

// Session is everything proto runs for one terminal session.
type Session struct {
	Listener *transport.Listener
	Terminal Terminal
	// Emulator is the emu process over IPC in production, or an in-process
	// one in tests.
	Emulator emu.Emulator
	Log      *slog.Logger
}

// Run serves the session: it accepts the client's connection, then moves
// keystrokes from SSP to the terminal, output from the terminal through the
// emulator into the screen SSP sends, and well-formed replies back to the
// terminal, until the shell exits or ctx is done.
//
// Resume and agent channels are later slices: Run takes one client and the
// session ends with it, but nothing in the listener or SSP assumes that.
func (s *Session) Run(ctx context.Context) error {
	panic("TODO slice 1")
}

// ValidReply says whether b, from emu, is something a terminal could
// truthfully have answered the program: device attributes, a cursor
// position report, a colour report and the like, each in full. Anything
// else is dropped, so a compromised emu cannot type into the shell (S4).
func ValidReply(b []byte) bool {
	panic("TODO slice 1")
}
