package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/danielbodart/mosey/internal/agent"
	"github.com/danielbodart/mosey/internal/channel"
	"github.com/danielbodart/mosey/internal/handshake"
	"github.com/danielbodart/mosey/internal/predict"
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
	// Agent, if set, forwards the user's agent: the client offers the
	// agent channel and serves the ones the server opens (agent.md §3).
	// Nil is no agent: the channel is not offered, so none can be opened.
	Agent *agent.Forwarder
	// Predict is when predictive local echo is drawn (D12,
	// prediction.md §11.1); the zero value is predict.Adaptive.
	Predict predict.Mode
	// Name is the session's (D8 R2), for the messages it ends with.
	Name string
	// Reconnect, if set, is R3 (bootstrap.md §9.2.2): after
	// ReconnectAfter of silence the session calls it, in the background,
	// for a fresh bootstrap that resumes this same session naming holder,
	// the credential its transport was made with, and dials what it
	// returns. It must never ask the user anything. Its errors
	// ErrSessionGone and *TakenOverError end the session; any other is
	// tried again after the backoff. Nil is no reconnect.
	Reconnect func(ctx context.Context, holder [8]byte) (*Reattach, error)
}

// Reattach is what one R3 try's bootstrap gives: a new socket and
// credential for the same session, a fresh one-shot key, and the agent
// forwarding that login set up, or nil.
type Reattach struct {
	Conn       net.PacketConn
	Server     netip.AddrPort
	Credential handshake.Credential
	Key        *handshake.OneShotKey
	Agent      *agent.Forwarder
}

// R3's timing (bootstrap.md §9.2.2, PLAN O13).
const (
	// ReconnectAfter is how long the client hears nothing authentic before
	// it starts resuming its own session over SSH [D: five of D11's 3 s
	// heartbeats; the server's SilentAfter is the same].
	ReconnectAfter = 15 * time.Second
	// ReconnectTry bounds one try, its bootstrap and its handshake [D:
	// twice the credential TTL, the longest a healthy try can need].
	ReconnectTry = 60 * time.Second
	// reconnectFirst and reconnectMax are the backoff between failed
	// tries: 2 s, doubling, at most 60 s [D: a try is one SSH login; 60 s
	// keeps a day-long outage to about 1440 of them, and a working
	// session at most a minute after the network returns].
	reconnectFirst = 2 * time.Second
	reconnectMax   = 60 * time.Second
)

// reconnectBackoff is the wait after the n-th failed try (from 0).
func reconnectBackoff(n int) time.Duration {
	d := reconnectFirst
	for range n {
		if d >= reconnectMax/2 {
			return reconnectMax
		}
		d *= 2
	}
	return d
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
	conn, err := dial(ctx, log, s.Conn, s.Server, &s.Credential, s.Key, s.Agent != nil)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	first := s.newLink(ctx, conn, s.Agent, log)

	if err := s.Terminal.Raw(); err != nil {
		first.retire()
		return fail(err, "putting the terminal in raw mode: %v", err)
	}
	defer s.Terminal.Restore()

	paint := render.New(s.Terminal, s.Capabilities)
	if cols, rows, err := s.Terminal.Size(); err == nil {
		// The renderer clips to the local size (screen.md §8.3); after
		// this, the loop tells it of every change.
		paint.Resize(cols, rows)
	}
	l := &loop[*userinput.Stream, *screen.Grid]{
		paint:          paint,
		term:           s.Terminal,
		log:            log,
		reconnectAfter: ReconnectAfter,
		backoff:        reconnectBackoff,
	}
	l.adopt(first)
	if s.Reconnect != nil {
		l.reconnect = s.reconnect(log)
	}
	err = l.run(ctx)
	if errors.Is(err, errSessionEnded) {
		l.retire()
		return nil
	}
	// This client is going away, or failed: tell the server, which keeps
	// the session for a resume (bootstrap.md §9.3). A revoked connection
	// is already closed, and End does nothing.
	l.end(transport.EndDetached)
	l.retire()
	var taken *TakenOverError
	if errors.As(err, &taken) {
		taken.Name = s.Name
	}
	if errors.Is(err, ErrSessionGone) {
		return &GoneError{Name: s.Name}
	}
	if err == nil {
		return &DetachedError{Name: s.Name}
	}
	return err
}

// newLink is everything the loop runs over conn: the agent's channels if
// it carries them, the SSP endpoint, the input stream it sends, and
// prediction, each from scratch (ssp.md §1.3).
func (s *Session) newLink(ctx context.Context, conn *transport.Conn, fwd *agent.Forwarder, log *slog.Logger) link[*userinput.Stream, *screen.Grid] {
	lctx, stop := context.WithCancel(ctx)
	if fwd != nil {
		if conn.Carries(handshake.ChannelAgent) {
			mux := channel.NewMux(conn, channel.Config{Role: channel.Client, Accept: fwd.Accept, Log: log})
			go mux.Run(lctx)
		} else {
			log.Warn("the server does not forward an agent")
		}
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
	engine := predict.New(predict.Config{Mode: s.Predict})
	began := time.Now()
	return link[*userinput.Stream, *screen.Grid]{
		sync:    ep,
		input:   input,
		events:  conn.Events(),
		paused:  func() bool { return pendingInput(ep, input) >= userinput.MaxPendingInput },
		predict: engine,
		rtt:     func() time.Duration { return ep.Stats().SRTT },
		heard: func() time.Time {
			if h := ep.Stats().LastHeard; h.After(began) {
				return h
			}
			return began
		},
		holder: conn.CredentialID(),
		retire: func() {
			stop()
			conn.Close()
			log.Info("prediction", "mode", s.Predict, "stats", fmt.Sprintf("%+v", engine.Stats()))
		},
		end: func(r transport.EndReason) { conn.End(r) },
	}
}

// reconnect is the loop's R3 try (bootstrap.md §9.2.2): Session.Reconnect's
// bootstrap, then, unless the old link has been heard meanwhile, the
// handshake, all within ReconnectTry.
func (s *Session) reconnect(log *slog.Logger) func(context.Context, [8]byte, func() bool) (link[*userinput.Stream, *screen.Grid], error) {
	return func(ctx context.Context, holder [8]byte, ok func() bool) (link[*userinput.Stream, *screen.Grid], error) {
		tctx, cancel := context.WithTimeout(ctx, ReconnectTry)
		defer cancel()
		r, err := s.Reconnect(tctx, holder)
		if err != nil {
			return link[*userinput.Stream, *screen.Grid]{}, err
		}
		if !ok() {
			r.Key.Wipe()
			clear(r.Credential.PSK[:])
			r.Conn.Close()
			return link[*userinput.Stream, *screen.Grid]{}, errAbandoned
		}
		conn, err := dial(tctx, log, r.Conn, r.Server, &r.Credential, r.Key, r.Agent != nil)
		if err != nil {
			return link[*userinput.Stream, *screen.Grid]{}, err
		}
		return s.newLink(ctx, conn, r.Agent, log), nil
	}
}

// dial runs the handshake (bootstrap.md §7.3) within the credential's
// life: after CredentialTTL the server has forgotten it anyway. It offers
// the agent channel when the client forwards one.
func dial(ctx context.Context, log *slog.Logger, pc net.PacketConn, server netip.AddrPort, cred *handshake.Credential, key *handshake.OneShotKey, agent bool) (*transport.Conn, error) {
	// Nothing needs the key or the PSK once the handshake is over, however
	// it went: a resume makes new ones (D8).
	defer key.Wipe()
	defer clear(cred.PSK[:])
	dctx, cancel := context.WithTimeout(ctx, handshake.CredentialTTL)
	defer cancel()
	log.Info("dialling", "server", server)
	var offer []handshake.ChannelType
	if agent {
		offer = append(offer, handshake.ChannelAgent)
	}
	conn, err := transport.DialOffering(dctx, pc, server, *cred, key, offer, log)
	if err == nil {
		log.Info("connected", "server", server)
		return conn, nil
	}
	// With no connection to own it, the socket is still ours to close;
	// closing it twice, if Dial already did, is harmless.
	pc.Close()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return nil, fail(err, "no reply from %s over UDP: is UDP port %d open?", server, server.Port())
	}
	return nil, fail(err, "connecting to %s over UDP: %v", server, err)
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
