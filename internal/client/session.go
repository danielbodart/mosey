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
	// Capabilities is what the local terminal can draw (render.FromEnv),
	// the locale's UTF-8 among it: without it the renderer writes no byte
	// at or above 0x80 (screen.md §8.3).
	Capabilities render.Capabilities
}

// transport.Conn must be an ssp.Chaffer: NewEndpoint only chaffs over
// Datagrams that are, and would otherwise quietly send no cover traffic,
// switching D11's hiding of keystroke timing off (ssp.md §9.1.4).
var _ ssp.Chaffer = (*transport.Conn)(nil)

// Run handshakes, then runs SSP and draws until the server ends the session
// (its shell exited; Run returns nil), ctx is done or the terminal's input
// ends (*DetachedError: the session runs on for a resume), the session
// fails, or another client takes it over (*TakenOverError). Unless the
// server ended it, Run tells the server this client is going before it
// returns.
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

	paint := render.New(s.Terminal, s.Capabilities)
	if cols, rows, err := s.Terminal.Size(); err == nil {
		// The renderer clips to the local size (screen.md §8.3); after
		// this, the loop tells it of every change.
		paint.Resize(cols, rows)
	}
	// One stream: the loop appends to it and hands it to Set, and the
	// endpoint starts from the same empty version 0 (ssp.md §10.1).
	input := userinput.NewStream()
	// The owners' bounds, not copies (architecture.md §4): the largest
	// payload the transport carries, and the largest screen diff the
	// server can make at the D23 clamp (screen.md §5.12).
	ep := ssp.NewEndpoint(conn, ssp.Config{
		Role:           ssp.Client,
		MaxPayload:     transport.MaxPayload,
		FrameOverhead:  transport.FrameOverhead,
		MaxRemoteBytes: screen.MaxDiff,
	}, input.Clone(), screen.NewGrid(0, 0))
	l := &loop[*userinput.Stream, *screen.Grid]{
		sync:   ep,
		input:  input,
		paint:  paint,
		term:   s.Terminal,
		events: conn.Events(),
		log:    log,
		paused: func() bool { return pendingInput(ep, input) >= userinput.MaxPendingInput },
	}
	err = l.run(ctx)
	if errors.Is(err, errSessionEnded) {
		return nil
	}
	// This client is going away, or failed: tell the server, which keeps
	// the session for a resume (bootstrap.md §9.3). A revoked connection
	// is already closed, and End does nothing.
	conn.End(transport.EndDetached)
	if err == nil {
		return &DetachedError{SessionID: s.Credential.SessionID}
	}
	return err
}

// dial runs the handshake (bootstrap.md §7.3) within the credential's
// life: after CredentialTTL the server has forgotten it anyway.
func (s *Session) dial(ctx context.Context, log *slog.Logger) (*transport.Conn, error) {
	// Nothing needs the key or the PSK once the handshake is over, however
	// it went: resume, when it comes, rekeys instead (D8).
	defer s.Key.Wipe()
	defer clear(s.Credential.PSK[:])
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

// pendingInput is the encoded size of the input the server has not yet
// consumed (ssp.md §10.1): from the lesser of the screen's InputConsumed
// and the length of the stream the server has acknowledged, so a server
// that overstates what it consumed cannot make the next diff any bigger.
func pendingInput(ep *ssp.Endpoint[*userinput.Stream, *screen.Grid], input *userinput.Stream) int {
	g, _ := ep.Remote()
	acked, _ := ep.Acked()
	return pendingSince(input, g.InputConsumed, acked.Len())
}

// pendingSince is pendingInput's arithmetic: the encoded size of input from
// the lesser of consumed and ackedLen.
func pendingSince(input *userinput.Stream, consumed, ackedLen uint64) int {
	return input.EncodedSince(min(consumed, ackedLen))
}
