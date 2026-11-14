package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/danielbodart/mosey/internal/channel"
	"github.com/danielbodart/mosey/internal/handshake"
)

// DialTimeout bounds the client's connection to the user's agent, the
// replayed bind and its reply, for each channel (agent.md §3) [choice].
const DialTimeout = 5 * time.Second

// Forwarder is the client's side of agent forwarding: it serves each agent
// channel the server opens by connecting to the user's agent, replaying
// the captured bind, and relaying (agent.md §3). Its Accept is a
// channel.Accept.
type Forwarder struct {
	// Dial connects to the user's agent: the socket bootstrap.md §5 chose.
	Dial func(ctx context.Context) (net.Conn, error)
	Bind Bind
	Log  *slog.Logger
}

// DialUnix is a Forwarder.Dial for the agent socket at path.
func DialUnix(path string) func(ctx context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", path)
	}
}

// Accept takes an agent channel: anything else is refused. The agent
// connection is made, and the bind replayed and answered, before the
// channel is accepted, so a channel that is accepted reaches an agent.
func (f *Forwarder) Accept(ctx context.Context, typ uint8) (func(*channel.Stream), error) {
	if typ != uint8(handshake.ChannelAgent) || f.Bind.IsZero() {
		return nil, channel.ErrRefused
	}
	ctx, cancel := context.WithTimeout(ctx, DialTimeout)
	defer cancel()
	conn, err := f.Dial(ctx)
	if err != nil {
		f.log().Warn("connecting to the agent", "err", err)
		return nil, fmt.Errorf("connecting to the agent: %w", err)
	}
	if err := Replay(ctx, conn, f.Bind); err != nil {
		conn.Close()
		f.log().Warn("replaying the session-bind", "err", err)
		return nil, err
	}
	return func(s *channel.Stream) { Relay(conn, s) }, nil
}

func (f *Forwarder) log() *slog.Logger {
	if f.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return f.Log
}

// Replay writes the captured bind to a fresh agent connection and reads,
// and drops, the one reply (agent.md §3): success, or a failure from an
// agent that does not know the extension, which ssh -A also carries on
// past.
func Replay(ctx context.Context, conn net.Conn, b Bind) error {
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
		defer conn.SetDeadline(time.Time{})
	}
	if _, err := conn.Write(b.Frame()); err != nil {
		return fmt.Errorf("writing the session-bind: %w", err)
	}
	if _, err := readFrame(conn, MaxBindReply); err != nil {
		return fmt.Errorf("reading the agent's answer to the session-bind: %w", err)
	}
	return nil
}

// closeWriter is a connection whose sending direction can end on its own:
// a unix socket, which takes shutdown(SHUT_WR).
type closeWriter interface{ CloseWrite() error }

// Relay copies local to s and s to local until both directions have ended,
// then closes both (agent.md §4.2, §5.6). The peer's end of stream reaches
// local as a half-close where local can take one (the client's agent
// connection, as ssh does with a channel EOF), and otherwise, once
// everything before it is written, as a close (proto's fds, which it
// cannot shut down). A reset stream closes local at once.
func Relay(local io.ReadWriteCloser, s *channel.Stream) {
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		_, err := io.Copy(s, local)
		// The other direction closing local (proto cannot half-close) ends
		// this one cleanly, not as a failure.
		if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
			s.Close() // the local end failed: reset, not a clean end
			return
		}
		s.CloseWrite()
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		_, err := io.Copy(local, s)
		if cw, ok := local.(closeWriter); ok && err == nil {
			if cw.CloseWrite() == nil {
				return
			}
		}
		local.Close()
	}()
	<-done
	<-done
	local.Close()
	s.Close()
}

// Serve is proto's side for one local agent connection: open an agent
// channel on m and relay, or close conn if the channel cannot be opened
// (agent.md §4.2).
func Serve(ctx context.Context, m *channel.Mux, conn io.ReadWriteCloser, log *slog.Logger) {
	s, err := m.Open(ctx, uint8(handshake.ChannelAgent))
	if err != nil {
		if log != nil {
			log.Info("an agent connection was not forwarded", "err", err)
		}
		conn.Close()
		return
	}
	Relay(conn, s)
}
