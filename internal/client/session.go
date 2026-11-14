package client

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"

	"github.com/danielbodart/mosey/internal/handshake"
	"github.com/danielbodart/mosey/internal/render"
	"github.com/danielbodart/mosey/internal/screen"
	"github.com/danielbodart/mosey/internal/ssp"
	"github.com/danielbodart/mosey/internal/terminal"
	"github.com/danielbodart/mosey/internal/transport"
	"github.com/danielbodart/mosey/internal/userinput"
	"github.com/danielbodart/mosey/internal/wire"
)

// The SSP limits the client's endpoint is set up with.
const (
	// maxPayload is transport.MaxPayload (architecture.md §4): a datagram
	// of wire.MaxDatagram less the data packet's 13-byte clear header,
	// its 1-byte frame kind and its 16-byte tag.
	maxPayload = wire.MaxDatagram - 30
	// maxScreenDiff bounds one decompressed screen instruction:
	// screen.MaxDiff, 48 MiB, the largest diff the server can produce at
	// the D23 size clamp (screen.md §5.12).
	maxScreenDiff = 48 << 20
)

// Session is the client after the bootstrap: what Run does once it has a
// credential, and what the end-to-end tests run on netsim.
type Session struct {
	// Conn is the UDP socket, which the transport then owns: a
	// *net.UDPConn in production, a *netsim.Conn in tests.
	Conn       net.PacketConn
	Server     netip.AddrPort
	Credential handshake.Credential
	// Key is the client's one-shot key from the bootstrap. Run wipes it
	// once the handshake is over, whether it succeeded or not.
	Key      *handshake.OneShotKey
	Terminal terminal.Terminal
	Log      *slog.Logger
	// Capabilities is what the local terminal can draw (Capabilities()).
	Capabilities render.Capabilities
	// UTF8 says whether the local locale is UTF-8 (LocaleIsUTF8). The
	// renderer must write no byte at or above 0x80 when it is not
	// (screen.md §8.3, §11 item 14).
	UTF8 bool
}

// Run handshakes, then runs SSP and draws until ctx is done, the session
// fails, or another client takes it over (*TakenOverError).
//
// The terminal goes raw only once the handshake is done, and is restored
// on every way out.
func (s *Session) Run(ctx context.Context) error {
	log := s.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	conn, err := s.dial(ctx, log)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := s.Terminal.Raw(); err != nil {
		return fail(err, "putting the terminal in raw mode: %v", err)
	}
	defer s.Terminal.Restore()

	// TODO(screen.md §11 item 14): pass s.UTF8 to the renderer once
	// render.Capabilities has its UTF8 field.
	paint := render.New(s.Terminal, s.Capabilities)
	// One stream: the loop appends to it and hands it to Set, and the
	// endpoint starts from the same empty version 0 (ssp.md §10.1).
	input := userinput.NewStream()
	ep := ssp.NewEndpoint(conn, ssp.Config{
		Role:           ssp.Client,
		MaxPayload:     maxPayload,
		MaxRemoteBytes: maxScreenDiff,
	}, input.Clone(), screen.NewGrid(0, 0))
	l := &loop[*userinput.Stream, *screen.Grid]{
		sync:   ep,
		input:  input,
		paint:  paint,
		term:   s.Terminal,
		events: conn.Events(),
		log:    log,
		// TODO(ssp.md §10.1): pause while the input not yet consumed by
		// the server (from Grid.InputConsumed and Endpoint.Acked, which
		// screen and ssp have yet to add) is MaxPendingInput or more.
		// Until then a paste larger than the server's MaxDiffBytes ends
		// the session with a protocol error rather than crossing slowly.
		paused: func() bool { return false },
	}
	return l.run(ctx)
}

// dial runs the handshake (bootstrap.md §7.3) within the credential's
// life: after CredentialTTL the server has forgotten it anyway.
func (s *Session) dial(ctx context.Context, log *slog.Logger) (*transport.Conn, error) {
	defer s.Key.Wipe()
	dctx, cancel := context.WithTimeout(ctx, handshake.CredentialTTL)
	defer cancel()
	log.Info("dialling", "server", s.Server)
	conn, err := transport.Dial(dctx, s.Conn, s.Server, s.Credential, s.Key, log)
	if err == nil {
		log.Info("connected", "server", s.Server)
		return conn, nil
	}
	// With no connection to own it, the socket is still ours to close;
	// closing it twice, if Dial already did, is harmless.
	s.Conn.Close()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return nil, fail(err, "no reply from %s over UDP: is UDP port %d open?", s.Server, s.Server.Port())
	}
	return nil, fail(err, "connecting to %s over UDP: %v", s.Server, err)
}
