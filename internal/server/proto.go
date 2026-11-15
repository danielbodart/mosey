package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/danielbodart/mosey/internal/agent"
	"github.com/danielbodart/mosey/internal/channel"
	"github.com/danielbodart/mosey/internal/emu"
	"github.com/danielbodart/mosey/internal/handshake"
	"github.com/danielbodart/mosey/internal/ipc"
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

// Timings of server.md §7 and §8.
const (
	// ptyReadChunk is how much of the pty proto reads at once, which is
	// also ipc.MaxOutput: one read, one emu request.
	ptyReadChunk = ipc.MaxOutput
	// T5 bounds the drain after the spawner says the shell has exited: a
	// job the shell left behind may hold the pty's slave open, so EIO may
	// never come [derived].
	T5 = time.Second
	// T6 bounds the delivery of the final screen: until the client
	// acknowledges it, or one D11 heartbeat [derived].
	T6 = 3 * time.Second
)

// ErrNoClient is the end of a session nobody connected to: every
// credential minted for it expired unconfirmed before any client attached,
// so nothing can ever connect (server.md §2.4).
var ErrNoClient = errors.New("server: no client confirmed a credential")

// errShellExited is the normal end of a session; Run returns nil for it.
var errShellExited = errors.New("server: the shell exited")

// Terminal is the shell's pty as proto sees it.
type Terminal interface {
	io.ReadWriter
	// Resize sets the window size, after the clamp.
	Resize(cols, rows int) error
	// EchoOff is the D12 echo-off bit: !ECHO && ICANON on the slave.
	EchoOff() (bool, error)
}

// flusher is an Emulator that must be asked again to release a screen it
// held under synchronised output: the emu process, which never speaks
// unasked (screen.md §6.3). The in-process emulator releases on its own
// next Snapshot.
type flusher interface{ Flush() }

// rebuilder is an Emulator whose screen can change without a Write: a new
// emu after a rebuild (server.md §3.6).
type rebuilder interface{ Changed() <-chan struct{} }

// Session is everything proto runs for one terminal session.
//
// Its threads of control are server.md §7's: a pty reader that feeds the
// emulator and never writes the pty, one pty writer for keystrokes and
// then replies, the SSP endpoint of the attached client, and timers for
// synchronised output. The pty and the emulator live as long as the
// shell; clients come and go (D8): each connection the listener accepts
// gets an SSP endpoint of its own, the newest replacing any other (the
// listener has revoked it, D26), and a client that leaves leaves the
// session running for the next. The zero value plus the exported fields is
// ready to Run.
type Session struct {
	Listener *transport.Listener
	Terminal Terminal
	// Emulator is the emu process over IPC in production, or an in-process
	// one in tests.
	Emulator emu.Emulator
	Log      *slog.Logger
	// Attached, if set, is called each time a client confirms a
	// credential, and again when a client reported silent is heard, with
	// the id of the credential its connection was made with and its
	// validated address or the zero AddrPort while it has none: the first
	// stops the spawner's backstop (bootstrap.md §4.5), and each is what
	// the attach socket's greeting says.
	Attached func(peer netip.AddrPort, credential [8]byte)
	// Detached, if set, is called when the attached client goes and no
	// other takes its place, or has been silent for SilentAfter: the
	// session waits for a resume (bootstrap.md §9.2).
	Detached func()
	// SilentAfter is how long the attached client may go unheard before
	// it counts as detached; zero is the package's SilentAfter.
	SilentAfter time.Duration
	// Ending, if set, is called once with what Run will return, after the
	// client has been told and before the session lets go of the
	// emulator and the terminal. proto tells the spawner the session is
	// over here and waits for its answer, so that emu's socket closing
	// (which ends emu) never reaches the spawner before the session's
	// end does: emu exiting is never a reason to end a session, and a
	// spawner that heard it first would log a death and restart emu
	// (server.md §2.4, §5.2).
	Ending func(err error)

	once      sync.Once
	em        emu.Emulator
	repliesIn chan struct{}
	// switched wakes the pty writer when the attached endpoint changes.
	switched  chan struct{}
	minted    chan struct{}
	shellExit chan struct{}
	exitOnce  sync.Once
	closeOnce sync.Once
	done      chan struct{}

	// publishMu orders snapshots with the versions SSP numbers them as, so
	// an older screen is never set after a newer one.
	publishMu sync.Mutex
	// sizeMu serialises resizes: the client's and a repaint's.
	sizeMu sync.Mutex

	mu sync.Mutex
	// ep is the attached client's endpoint, or nil while none is.
	ep *ssp.Endpoint[*screen.Grid, *userinput.Stream]
	// consumed is how many of ep's input events the pty has taken: per
	// connection, since each client's stream starts at 0 (ssp.md §1.3).
	consumed uint64
	// echo is ep's echo ack and applied count, published the screen
	// before published, and echoTimer the echo-ack publish owed
	// (prediction.md §3.1), all per connection like consumed.
	echo      echoTracker
	published *screen.Grid
	echoTimer *time.Timer
	echoArmed bool
	replies   []byte
	dropped   int
	cols      int
	rows      int
	holding   bool
	// broken is an endpoint whose client broke the input protocol, for
	// the main loop to drop.
	broken chan *ssp.Endpoint[*screen.Grid, *userinput.Stream]
	// mux is the attached connection's agent channels, or nil while no
	// client that negotiated the agent is attached (agent.md §4.2).
	mux *channel.Mux
	// agentIn carries local agent connections to serveAgents.
	agentIn chan io.ReadWriteCloser
	// firstAttach closes when the first client attaches, so serveAgents
	// can stop holding connections made before it (agent.md §4.2).
	firstAttach chan struct{}
}

// SilentAfter is how long proto hears nothing authentic from the attached
// client before it tells the spawner the session is detached, so that a
// plain `mosey DEST` takes it after the client's machine crashed or
// rebooted (D8 R1, R3; bootstrap.md §9.2) [D: five of D11's 3 s
// heartbeats, the same as the client's ReconnectAfter]. The connection
// is kept: the client may only be in a dead spot.
const SilentAfter = 15 * time.Second

// silencePoll is how often proto looks for a silent client's return once
// it has said it is detached [choice: well inside a heartbeat].
const silencePoll = time.Second

// AgentStartupHold is how long an agent connection made before any client
// has attached waits for one, rather than being refused at once
// (agent.md §4.2). The shell starts before the client has finished its
// handshake, and a login rc that runs `ssh-add -l` or keychain would
// otherwise find no agent where ssh -A gives one from the first line. It
// covers the client's handshake over a slow, lossy path with room to
// spare [choice].
const AgentStartupHold = 10 * time.Second

func (s *Session) init() {
	s.once.Do(func() {
		if s.Log == nil {
			s.Log = slog.New(slog.DiscardHandler)
		}
		s.em = s.Emulator
		if _, ok := s.em.(*ipcEmulator); !ok {
			// tuios is not safe for concurrent use, and the reader, the
			// writer and the hold timer all reach the emulator. The IPC
			// emulator serialises its own requests, and must not be held
			// under one lock: its Write waits while emu is down, and a
			// resize must not wait with it (server.md §3.6).
			s.em = &lockedEmulator{e: s.Emulator}
		}
		s.repliesIn = make(chan struct{}, 1)
		s.switched = make(chan struct{}, 1)
		s.minted = make(chan struct{}, 1)
		s.broken = make(chan *ssp.Endpoint[*screen.Grid, *userinput.Stream], 1)
		s.shellExit = make(chan struct{})
		s.done = make(chan struct{})
		s.agentIn = make(chan io.ReadWriteCloser, channel.MaxStreams)
		s.firstAttach = make(chan struct{})
	})
}

// AgentConn hands the session a connection to its agent socket (server.md
// §2.7): it is carried to the attached client over an agent channel, or
// closed if no attached client forwards an agent, or too many are open
// (agent.md §4.2).
func (s *Session) AgentConn(c io.ReadWriteCloser) {
	s.init()
	select {
	case s.agentIn <- c:
	case <-s.done:
		c.Close()
	default:
		c.Close() // a backlog this deep is already over the limit
	}
}

// serveAgents serves each agent connection over the current client's
// agent channels, until ctx is done. Until the first client attaches, or
// AgentStartupHold has passed, it holds connections instead, up to
// MaxStreams of them, and serves them once that client is attached.
func (s *Session) serveAgents(ctx context.Context) error {
	var held []io.ReadWriteCloser
	first := s.firstAttach
	hold := time.NewTimer(AgentStartupHold)
	defer hold.Stop()
	serve := func(c io.ReadWriteCloser) {
		s.mu.Lock()
		m := s.mux
		s.mu.Unlock()
		if m == nil || m.Live() >= channel.MaxStreams {
			s.Log.Info("refusing an agent connection: no attached client forwards an agent, or too many are open")
			c.Close()
			return
		}
		go agent.Serve(ctx, m, c, s.Log)
	}
	for {
		select {
		case <-ctx.Done():
			for _, c := range held {
				c.Close()
			}
			for {
				select {
				case c := <-s.agentIn:
					c.Close()
				default:
					return nil
				}
			}
		case <-first:
			first = nil
			hold.Stop()
			for _, c := range held {
				serve(c)
			}
			held = nil
		case <-hold.C:
			if first == nil {
				continue
			}
			first = nil
			if len(held) > 0 {
				s.Log.Info("refusing agent connections made before any client attached", "count", len(held))
			}
			for _, c := range held {
				c.Close()
			}
			held = nil
		case c := <-s.agentIn:
			if first != nil && len(held) < channel.MaxStreams {
				held = append(held, c)
				continue
			}
			serve(c)
		}
	}
}

// ShellExited tells the session the spawner saw the login shell exit. The
// pty reader normally sees EIO first; if a job the shell left behind holds
// the slave open, the session ends T5 later all the same.
func (s *Session) ShellExited() {
	s.init()
	s.exitOnce.Do(func() { close(s.shellExit) })
}

// Minted tells the session a credential was minted for a resume. Until a
// client has attached, the session ends only once every credential it
// minted has expired, so this restarts that wait (server.md §2.4).
func (s *Session) Minted() {
	s.init()
	select {
	case s.minted <- struct{}{}:
	default:
	}
}

// attachment is one client's connection and the SSP endpoint on it.
type attachment struct {
	conn *transport.Conn
	ep   *ssp.Endpoint[*screen.Grid, *userinput.Stream]
	stop context.CancelFunc
	// sspDone closes when the endpoint's Run has returned; gone carries
	// why the client went, once.
	sspDone chan struct{}
	gone    chan error
	quit    chan struct{}
	mux     *channel.Mux
	// at is when it attached: the start of its silence until SSP has
	// heard from it.
	at time.Time
}

// lastHeard is when the client last sent anything authentic, or when it
// attached if it has sent nothing yet.
func (a *attachment) lastHeard() time.Time {
	if h := a.ep.Stats().LastHeard; h.After(a.at) {
		return h
	}
	return a.at
}

// Run serves the session: it moves output from the terminal through the
// emulator into the screen, and keystrokes from the attached client to the
// terminal, and takes each client the listener accepts, until the shell
// exits or ctx is done. It returns nil when the shell exited, ErrNoClient
// when no client ever attached in time, and otherwise why it stopped. It
// closes the emulator, and the terminal if it is an io.Closer.
func (s *Session) Run(ctx context.Context) error {
	s.init()
	defer close(s.done)
	defer s.closeAll()

	parent := ctx
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	var wg sync.WaitGroup
	run := func(f func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := f(ctx); err != nil {
				cancel(err)
			}
		}()
	}
	run(s.readPTY)
	run(s.writePTY)
	run(s.watch)
	run(s.serveAgents)
	conns := make(chan *transport.Conn)
	run(func(ctx context.Context) error { return s.accept(ctx, conns) })

	// Until a client attaches, the session lives as long as a credential
	// minted for it could still be confirmed (server.md §2.4).
	noClient := time.NewTimer(handshake.CredentialTTL)
	defer noClient.Stop()
	attachedOnce := false
	var cur *attachment
	var gone <-chan error
	// The attached client's silence (bootstrap.md §9.2): check fires when
	// it may have gone silent, or, once it has, to look for its return.
	silentAfter := s.SilentAfter
	if silentAfter == 0 {
		silentAfter = SilentAfter
	}
	var check <-chan time.Time
	silent := false
	var silentSince time.Time
	arm := func() {
		switch {
		case cur == nil:
			check = nil
		case silent:
			check = time.After(silencePoll)
		default:
			check = time.After(time.Until(cur.lastHeard().Add(silentAfter)))
		}
	}
	for ctx.Err() == nil {
		select {
		case <-check:
			last := cur.lastHeard()
			switch {
			case !silent && time.Since(last) >= silentAfter:
				silent, silentSince = true, last
				s.Log.Info("the client is silent; the session counts as detached", "for", time.Since(last).Round(time.Millisecond))
				if s.Detached != nil {
					s.Detached()
				}
			case silent && last.After(silentSince):
				silent = false
				s.Log.Info("the silent client is heard again")
				if s.Attached != nil {
					s.Attached(cur.conn.Peer(), cur.conn.CredentialID())
				}
			}
			arm()
		case <-ctx.Done():
		case <-noClient.C:
			if !attachedOnce {
				cancel(ErrNoClient)
			}
		case <-s.minted:
			if !attachedOnce {
				noClient.Reset(handshake.CredentialTTL)
			}
		case c := <-conns:
			// The listener revoked the old connection as it confirmed this
			// one (D26): drop it without a Detached, since a client is in
			// its place.
			if cur != nil {
				s.drop(cur)
			}
			cur = s.attach(parent, c)
			gone = cur.gone
			if !attachedOnce {
				close(s.firstAttach)
			}
			attachedOnce = true
			noClient.Stop()
			silent = false
			arm()
			if s.Attached != nil {
				s.Attached(c.Peer(), c.CredentialID())
			}
		case ep := <-s.broken:
			if cur == nil || cur.ep != ep {
				continue
			}
			s.Log.Warn("the client broke the input protocol; dropping it")
			s.drop(cur)
			cur, gone = nil, nil
			arm()
			if !silent && s.Detached != nil {
				s.Detached()
			}
			silent = false
		case err := <-gone:
			revoked := errors.Is(err, transport.ErrRevoked)
			s.Log.Info("the client went", "why", err)
			s.drop(cur)
			cur, gone = nil, nil
			arm()
			// A revoked connection has a confirmed one in its place, which
			// Accept is about to hand over; a silent one was reported
			// detached already.
			if !revoked && !silent && s.Detached != nil {
				s.Detached()
			}
			silent = false
		}
	}
	cause := context.Cause(ctx)
	if errors.Is(cause, errShellExited) && cur != nil {
		s.deliverFinal(cur)
		// Then say so, so the client exits now rather than waiting on a
		// silent network (server.md §2.4, §11 item 7).
		cur.conn.End(transport.EndShellExited)
	}
	if cur != nil {
		s.drop(cur)
	}
	err := runResult(cause, parent)
	if s.Ending != nil {
		s.Ending(err)
	}
	// Release whatever is parked: the emulator (a Write waiting for emu),
	// and the pty reader and writer (closing the master wakes the poller).
	s.closeAll()
	wg.Wait()
	s.mu.Lock()
	if s.echoTimer != nil {
		s.echoTimer.Stop()
	}
	s.mu.Unlock()
	return err
}

// runResult is what Run returns for why its context ended.
func runResult(cause error, parent context.Context) error {
	switch {
	case errors.Is(cause, errShellExited):
		return nil
	case errors.Is(cause, ErrNoClient):
		return ErrNoClient
	case parent.Err() != nil:
		return parent.Err()
	}
	return cause
}

// accept hands over every connection the listener confirms.
func (s *Session) accept(ctx context.Context, conns chan<- *transport.Conn) error {
	for {
		c, err := s.Listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accepting a client: %w", err)
		}
		select {
		case conns <- c:
		case <-ctx.Done():
			c.Close()
			return nil
		}
	}
}

// transport.Conn must be an ssp.Chaffer: NewEndpoint only chaffs over
// Datagrams that are, and would otherwise quietly send no cover traffic,
// switching D11's hiding of keystroke timing off (ssp.md §9.1.4).
var _ ssp.Chaffer = (*transport.Conn)(nil)

// attach starts an SSP endpoint on c and makes it the one the screen goes
// to and keystrokes come from. SSP starts from scratch on every connection
// (ssp.md §1.3), so its first diff to the new client is the whole screen.
// The endpoint runs on parent, not the session's context: when the shell
// exits, SSP must still carry the final screen (server.md §2.4).
func (s *Session) attach(parent context.Context, c *transport.Conn) *attachment {
	s.Log.Info("client attached", "peer", c.Peer())
	// MaxRemoteBytes is the largest diff a client may send (ssp.md §10.1).
	ep := ssp.NewEndpoint(c, ssp.Config{
		Role:           ssp.Server,
		MaxPayload:     transport.MaxPayload,
		FrameOverhead:  transport.FrameOverhead,
		MaxRemoteBytes: userinput.MaxDiffBytes,
	}, screen.NewGrid(0, 0), userinput.NewStream())
	sctx, stop := context.WithCancel(parent)
	a := &attachment{conn: c, ep: ep, stop: stop, sspDone: make(chan struct{}), gone: make(chan error, 1), quit: make(chan struct{}), at: time.Now()}
	// The agent's channels, if this client forwards an agent (agent.md
	// §4.2). They end with the connection: detach or takeover resets
	// every one, and the far programs see their connections close.
	if c.Carries(handshake.ChannelAgent) {
		a.mux = channel.NewMux(c, channel.Config{Role: channel.Server, Log: s.Log})
		go a.mux.Run(sctx)
	}
	s.mu.Lock()
	s.ep, s.consumed = ep, 0
	s.echo, s.published = echoTracker{}, nil
	s.mux = a.mux
	s.mu.Unlock()
	s.wake(s.switched)
	go func() {
		defer close(a.sspDone)
		err := ep.Run(sctx)
		if sctx.Err() == nil {
			a.leave(fmt.Errorf("ssp: %w", err))
		}
	}()
	go func() {
		for {
			select {
			case ev := <-c.Events():
				s.Log.Info("transport", "event", fmt.Sprintf("%T", ev), "detail", fmt.Sprintf("%+v", ev))
				if e, ok := ev.(transport.Ended); ok {
					a.leave(fmt.Errorf("%w: %s", transport.ErrEnded, e.Reason))
				}
			case <-a.quit:
				return
			}
		}
	}()
	s.publish()
	return a
}

// leave reports why the client went, once.
func (a *attachment) leave(err error) {
	select {
	case a.gone <- err:
	default:
	}
}

// drop stops a's endpoint and closes its connection, which erases its
// keys, and detaches it from the screen and the pty writer.
func (s *Session) drop(a *attachment) {
	a.stop()
	a.conn.Close()
	<-a.sspDone
	close(a.quit)
	s.mu.Lock()
	if s.ep == a.ep {
		s.ep = nil
	}
	if a.mux != nil && s.mux == a.mux {
		s.mux = nil
	}
	s.mu.Unlock()
	s.wake(s.switched)
}

func (s *Session) wake(c chan struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}

// closeAll closes the emulator, and the terminal if it can be closed, once.
func (s *Session) closeAll() {
	s.closeOnce.Do(func() {
		s.em.Close()
		if c, ok := s.Terminal.(io.Closer); ok {
			c.Close()
		}
	})
}

// watch republishes when a rebuilt emulator has a new screen, and ends
// the session T5 after the spawner says the shell exited.
func (s *Session) watch(ctx context.Context) error {
	var changed <-chan struct{}
	if r, ok := s.em.(rebuilder); ok {
		changed = r.Changed()
	}
	shellExit := s.shellExit
	var drained <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-changed:
			s.publish()
		case <-shellExit:
			shellExit = nil
			drained = time.After(T5)
		case <-drained:
			return errShellExited
		}
	}
}

// deliverFinal lets a's SSP, still running, deliver the last screen: until
// the client has acknowledged that very screen, SSP has stopped, or T6
// (server.md §2.4). The pty reader has stopped, so the screen published
// here is the last; if the client already had it, this returns at once.
func (s *Session) deliverFinal(a *attachment) {
	final := s.publish()
	ep, sspDone := a.ep, a.sspDone
	deadline := time.After(T6)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		// The echo-ack publish may still follow the final screen by up to
		// EchoAckDelay (prediction.md §3.1): the screen to see acknowledged
		// is whichever was published last.
		s.mu.Lock()
		if s.ep == ep && s.published != nil {
			final = s.published
		}
		s.mu.Unlock()
		if acked, _ := ep.Acked(); final != nil && acked.Equal(final) {
			return
		}
		select {
		case <-sspDone:
			return
		case <-deadline:
			s.Log.Info("the client did not acknowledge the final screen", "within", T6)
			return
		case <-tick.C:
		}
	}
}

// publish hands SSP the screen as it is now, with proto's own fields:
// the echo-off bit, the echo ack and the applied count (D12,
// prediction.md §3.1) and the input consumed (ssp.md §10.1). If the
// emulator held the screen under synchronised output, it asks again once
// SyncHold has passed (screen.md §6.3), so a program that opens mode 2026
// and never closes it freezes its screen only briefly. It returns the
// screen it set, or nil before a client has attached.
func (s *Session) publish() *screen.Grid {
	ep := s.endpoint()
	if ep == nil {
		// No client yet: the first publish, once one attaches, carries
		// whatever happened meanwhile.
		return nil
	}
	s.publishMu.Lock()
	defer s.publishMu.Unlock()
	g := screen.NewGrid(0, 0)
	held := snapshot(s.em, g)
	if off, err := s.Terminal.EchoOff(); err == nil {
		g.EchoOff = off
	}
	s.mu.Lock()
	g.InputConsumed = s.consumed
	if s.ep == ep {
		// EchoApplied is read after the snapshot, so it may count an
		// event written in between: an upper bound, which is the safe
		// side for the client's horizon (prediction.md §3).
		s.echo.fields(g, s.published, time.Now())
		s.published = g
	}
	s.cols, s.rows = g.Size()
	arm := held && !s.holding
	if arm {
		s.holding = true
	}
	s.mu.Unlock()
	ep.Set(g)
	if arm {
		time.AfterFunc(emu.SyncHold, s.release)
	}
	return g
}

func (s *Session) endpoint() *ssp.Endpoint[*screen.Grid, *userinput.Stream] {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ep
}

// release is the SyncHold timer: ask a flusher again, then publish what
// it now has.
func (s *Session) release() {
	s.mu.Lock()
	s.holding = false
	s.mu.Unlock()
	select {
	case <-s.done:
		return
	default:
	}
	if f, ok := s.em.(flusher); ok {
		f.Flush()
	}
	s.publish()
}

// readPTY is the pty reader. It never writes to the pty: S2 measured the
// design that did deadlocking against a program that never reads its input
// (server.md §4.3). Any error, EIO above all, means every slave fd has
// closed: the shell is gone.
func (s *Session) readPTY(ctx context.Context) error {
	buf := make([]byte, ptyReadChunk)
	for {
		n, err := s.Terminal.Read(buf)
		if n > 0 {
			s.em.Write(buf[:n])
			s.queueReplies(s.em.TakeReplies())
			s.publish()
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errShellExited
		}
	}
}

// queueReplies puts the replies that pass the grammar on the bounded queue
// the writer drains. The IPC emulator has already applied the grammar and
// the reply allowance (server.md §4.1); checking again costs nothing and
// holds for any Emulator.
func (s *Session) queueReplies(r []byte) {
	if len(r) == 0 {
		return
	}
	tokens, err := SplitReplies(r)
	s.mu.Lock()
	if err != nil {
		s.dropped++
	}
	for _, t := range tokens {
		if !ValidReply(t) || len(s.replies)+len(t) > ReplyQueue {
			s.dropped++
			continue
		}
		s.replies = append(s.replies, t...)
	}
	s.mu.Unlock()
	select {
	case s.repliesIn <- struct{}{}:
	default:
	}
}

// writePTY is the one writer of the pty (server.md §4.3). Keystrokes go
// first and have no queue of their own: the attached client's stream is
// the queue, one event at a time leaves it, and applied advances only once
// the pty has taken the whole event. A program that never reads its input
// therefore holds applied, InputConsumed with it, and the client stops
// reading its terminal: a bounded stall, not a bug.
//
// Each client has a stream of its own, so when another attaches the writer
// starts again from its event 0 (ssp.md §1.3); while none is attached it
// writes only replies.
func (s *Session) writePTY(ctx context.Context) error {
	var (
		ep, dead    *ssp.Endpoint[*screen.Grid, *userinput.Stream]
		applied     uint64
		unpublished int
	)
	for {
		if cur := s.endpoint(); cur != ep {
			ep, applied, unpublished = cur, 0, 0
		}
		if ep != nil && ep != dead {
			stream, _ := ep.Remote()
			events := stream.Since(applied)
			if first := stream.Len() - uint64(len(events)); first > applied {
				// The stream has forgotten events not yet written: the
				// client ran past RetainBytes, ignoring InputConsumed.
				// Nothing is skipped silently (ssp.md §10.1): that client
				// is dropped, and the session waits for another.
				dead = ep
				select {
				case s.broken <- ep:
				default:
				}
				continue
			}
			if len(events) > 0 {
				ev := events[0]
				if len(ev.Keys) > 0 {
					s.echoOffChanged(ep)
					if _, err := s.Terminal.Write(ev.Keys); err != nil {
						if ctx.Err() != nil {
							return nil
						}
						return errShellExited
					}
				} else if ev.Resize != (userinput.Size{}) {
					s.resize(ev.Resize.Cols, ev.Resize.Rows)
				}
				applied++
				s.wrote(ep, applied)
				unpublished += encodedLen(ev)
				// Published once it has moved ConsumedStep, so ordinary
				// typing never costs a frame of its own (ssp.md §10.1).
				if unpublished >= userinput.ConsumedStep {
					unpublished = 0
					s.mu.Lock()
					if s.ep == ep {
						s.consumed = applied
					}
					s.mu.Unlock()
					s.publish()
				}
				continue
			}
		}
		s.mu.Lock()
		r := s.replies
		s.replies = nil
		s.mu.Unlock()
		if len(r) > 0 {
			if _, err := s.Terminal.Write(r); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return errShellExited
			}
			continue
		}
		var changed <-chan struct{}
		if ep != nil && ep != dead {
			changed = ep.RemoteChanged()
		}
		select {
		case <-ctx.Done():
			return nil
		case <-changed:
		case <-s.repliesIn:
		case <-s.switched:
		}
	}
}

// wrote notes that the pty has taken ep's first applied events, for the
// echo ack, and owes an echo-ack publish EchoAckDelay from now
// (prediction.md §3.1 rules 1 and 3).
func (s *Session) wrote(ep *ssp.Endpoint[*screen.Grid, *userinput.Stream], applied uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ep != ep {
		return
	}
	s.echo.wrote(applied, time.Now())
	if !s.echoArmed {
		s.armEcho()
	}
}

// armEcho sets the timer for the next echo-ack publish, if one is owed.
// The caller holds mu.
func (s *Session) armEcho() {
	d, ok := s.echo.due(time.Now())
	if !ok {
		return
	}
	s.echoArmed = true
	if s.echoTimer == nil {
		s.echoTimer = time.AfterFunc(d, s.echoTick)
		return
	}
	s.echoTimer.Reset(d)
}

// echoTick is the echo-ack publish (rule 3): the ack moves, unless echo is
// off (rule 4), and with it the screen SSP has to send. Then the next one
// is armed, if more writes are waiting their 50 ms.
func (s *Session) echoTick() {
	select {
	case <-s.done:
		return
	default:
	}
	s.mu.Lock()
	s.echoArmed = false
	s.mu.Unlock()
	s.publish()
	s.mu.Lock()
	if !s.echoArmed {
		s.armEcho()
	}
	s.mu.Unlock()
}

// echoOffChanged publishes before a key is written if the pty's echo-off
// bit is not the one last published: a program may turn echo off after
// the screen with its prompt was taken, and the client must stop
// predicting before the password, not after (prediction.md §3.1 rule 6).
func (s *Session) echoOffChanged(ep *ssp.Endpoint[*screen.Grid, *userinput.Stream]) {
	off, err := s.Terminal.EchoOff()
	if err != nil {
		return
	}
	s.mu.Lock()
	stale := s.ep == ep && s.published != nil && s.published.EchoOff != off
	s.mu.Unlock()
	if stale {
		s.publish()
	}
}

// encodedLen is an event's size in the stream's diff (ssp.md §10.1), the
// unit consumption is published in.
func encodedLen(ev userinput.Event) int {
	if len(ev.Keys) > 0 {
		return 1 + uvarintLen(uint64(len(ev.Keys))) + len(ev.Keys)
	}
	return 1 + uvarintLen(uint64(ev.Resize.Cols)) + uvarintLen(uint64(ev.Resize.Rows))
}

func uvarintLen(v uint64) int {
	n := 1
	for v >= 0x80 {
		v >>= 7
		n++
	}
	return n
}

// resize is the one resize path (server.md §7): clamped, the emulator
// first, then the pty, so the output the kernel's SIGWINCH prompts reaches
// an emulator already at the new size.
func (s *Session) resize(cols, rows int) {
	s.sizeMu.Lock()
	defer s.sizeMu.Unlock()
	c, r := screen.ClampSize(cols, rows)
	s.em.Resize(c, r)
	if err := s.Terminal.Resize(c, r); err != nil {
		s.Log.Warn("resizing the pty", "err", err)
	}
	s.publish()
}

// Repaint makes the shell's foreground program draw its screen again after
// an emulator rebuild, with the one mechanism screen.md §7.3 names: a size
// change and back through the normal resize path. The kernel sends SIGWINCH
// on each real change, so even a program that ignores a same-size SIGWINCH
// repaints (server.md §5.2).
func (s *Session) Repaint() {
	s.init()
	s.mu.Lock()
	cols, rows := s.cols, s.rows
	s.mu.Unlock()
	if cols < 1 || rows < 1 {
		return
	}
	other := rows - 1
	if rows == 1 {
		other = 2
	}
	s.resize(cols, other)
	s.resize(cols, rows)
}

// heldSnapshotter is an Emulator that takes its snapshot and says whether
// it held in one step, under its own lock.
type heldSnapshotter interface {
	snapshotHeld(g *screen.Grid) bool
}

// snapshot copies e's screen into g and says whether e held it under
// synchronised output (emu.Holder, screen.md §6.3). An Emulator that never
// holds says no.
func snapshot(e emu.Emulator, g *screen.Grid) (held bool) {
	if h, ok := e.(heldSnapshotter); ok {
		return h.snapshotHeld(g)
	}
	e.Snapshot(g)
	if h, ok := e.(emu.Holder); ok {
		return h.Held()
	}
	return false
}

// lockedEmulator serialises an Emulator that is not safe for concurrent
// use.
type lockedEmulator struct {
	mu     sync.Mutex
	e      emu.Emulator
	closed bool
}

func (l *lockedEmulator) Write(p []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.e.Write(p)
}

func (l *lockedEmulator) Resize(cols, rows int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.e.Resize(cols, rows)
}

func (l *lockedEmulator) Snapshot(g *screen.Grid) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.e.Snapshot(g)
}

func (l *lockedEmulator) snapshotHeld(g *screen.Grid) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return snapshot(l.e, g)
}

func (l *lockedEmulator) TakeReplies() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.e.TakeReplies()
}

func (l *lockedEmulator) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	return l.e.Close()
}
