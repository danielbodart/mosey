// Package client is mosey's client: it bootstraps over SSH, connects over
// UDP, and then runs the session, sending what the user types as a
// userinput.Stream and drawing the screen.Grid the server sends.
//
// It never parses a remote escape sequence (D9). Bytes from the network
// reach the terminal only as a Grid that has been validated by
// screen.Apply and drawn by render.
package client

import (
	"context"
	"log/slog"
	"net"
	"net/netip"

	"github.com/danielbodart/mosey/internal/bootstrap"
	"github.com/danielbodart/mosey/internal/handshake"
	"github.com/danielbodart/mosey/internal/terminal"
)

// Run is `mosey host`: the SSH bootstrap, then Session over a real UDP
// socket, until the shell exits, the user quits, or the session is taken
// over.
func Run(ctx context.Context, ssh bootstrap.SSH, term terminal.Terminal, log *slog.Logger) error {
	panic("TODO slice 1")
}

// Session is the client after the bootstrap: what Run does once it has a
// credential, and what the end-to-end tests run on netsim.
type Session struct {
	Conn       net.PacketConn
	Server     netip.AddrPort
	Credential handshake.Credential
	Key        *handshake.OneShotKey
	Terminal   terminal.Terminal
	Log        *slog.Logger
}

// Run handshakes, then runs SSP and draws until ctx is done or the server
// ends the session. It warns the user, on the status line, when nothing has
// been heard from the server for a while, as Mosh does.
func (s *Session) Run(ctx context.Context) error {
	panic("TODO slice 1")
}
