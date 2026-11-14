package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

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

// ErrNoClient is the end of a session nobody connected to: the credential
// minted for it expired unconfirmed, so nothing can ever connect
// (server.md §2.4).
var ErrNoClient = errors.New("server: no client confirmed a credential")

// ErrClientClosed is the end of a session the client ended: its user quit
// and it said so with an END frame (transport.md §8.4). With no resume in
// slice 1 nothing can reach the shell again, so the session ends
// (server.md §2.4).
var ErrClientClosed = errors.New("server: the client ended the session")

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
// then replies, the SSP endpoint, and timers for synchronised output. The
// zero value plus the exported fields is ready to Run.
type Session struct {
	Listener *transport.Listener
	Terminal Terminal
	// Emulator is the emu process over IPC in production, or an in-process
	// one in tests.
	Emulator emu.Emulator
	Log      *slog.Logger
	// Attached, if set, is called once, when a client first confirms a
	// credential, so the spawner can stop its backstop (bootstrap.md
	// §4.5).
	Attached func()

	once      sync.Once
	em        emu.Emulator
	ep        *ssp.Endpoint[*screen.Grid, *userinput.Stream]
	repliesIn chan struct{}
	shellExit chan struct{}
	exitOnce  sync.Once
	closeOnce sync.Once
	done      chan struct{}

	// publishMu orders snapshots with the versions SSP numbers them as, so
	// an older screen is never set after a newer one.
	publishMu sync.Mutex
	// sizeMu serialises resizes: the client's and a repaint's.
	sizeMu sync.Mutex

	mu       sync.Mutex
	consumed uint64
	replies  []byte
	dropped  int
	cols     int
	rows     int
	holding  bool
}

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
		s.shellExit = make(chan struct{})
		s.done = make(chan struct{})
	})
}

// ShellExited tells the session the spawner saw the login shell exit. The
// pty reader normally sees EIO first; if a job the shell left behind holds
// the slave open, the session ends T5 later all the same.
func (s *Session) ShellExited() {
	s.init()
	s.exitOnce.Do(func() { close(s.shellExit) })
}

// Run serves the session: it accepts the client's connection, then moves
// keystrokes from SSP to the terminal, output from the terminal through the
// emulator into the screen SSP sends, and well-formed replies back to the
// terminal, until the shell exits or ctx is done. It returns nil when the
// shell exited, ErrNoClient when nobody connected in time, ErrClientClosed
// when the client ended the session, and otherwise
// why it stopped. It closes the emulator, and the terminal if it is an
// io.Closer.
//
// Resume and agent channels are later slices: Run takes one client and the
// session ends with it, but nothing in the listener or SSP assumes that.
func (s *Session) Run(ctx context.Context) error {
	s.init()
	defer close(s.done)
	defer s.closeAll()

	// One credential is minted per session, so once it has expired
	// unconfirmed nothing can ever connect (server.md §2.4).
	actx, cancelAccept := context.WithTimeout(ctx, handshake.CredentialTTL)
	conn, err := s.Listener.Accept(actx)
	cancelAccept()
	if err != nil {
		if ctx.Err() == nil && errors.Is(err, context.DeadlineExceeded) {
			return ErrNoClient
		}
		return fmt.Errorf("accepting the client: %w", err)
	}
	defer conn.Close()
	if s.Attached != nil {
		s.Attached()
	}
	s.Log.Info("client attached", "peer", conn.Peer())

	ep := ssp.NewEndpoint(conn, ssp.Config{
		Role:           ssp.Server,
		MaxPayload:     transport.MaxPayload,
		// The largest diff a client may send (ssp.md §10.1).
		MaxRemoteBytes: userinput.MaxDiffBytes,
	}, screen.NewGrid(0, 0), userinput.NewStream())
	s.mu.Lock()
	s.ep = ep
	s.mu.Unlock()

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
	s.publish()
	// SSP runs on a context of its own, which outlives ctx: when the shell
	// exits, ctx ends the pty reader and writer, but SSP must still carry
	// the final screen to the client and read its acks (server.md §2.4).
	sctx, stopSSP := context.WithCancel(parent)
	defer stopSSP()
	sspDone := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(sspDone)
		if err := s.ep.Run(sctx); sctx.Err() == nil {
			cancel(fmt.Errorf("ssp: %w", err))
		}
	}()
	run(s.readPTY)
	run(s.writePTY)
	run(func(ctx context.Context) error { return s.watch(ctx, conn) })

	<-ctx.Done()
	cause := context.Cause(ctx)
	if errors.Is(cause, errShellExited) {
		s.deliverFinal(sspDone)
		// Then say so, so the client exits now rather than waiting on a
		// silent network (server.md §2.4, §11 item 7).
		conn.End(transport.EndShellExited)
	}
	// Release whatever is parked: SSP, the transport (Recv), the emulator
	// (a Write waiting for emu), and the pty reader and writer (closing the
	// master wakes the poller).
	stopSSP()
	conn.Close()
	s.closeAll()
	wg.Wait()
	switch {
	case errors.Is(cause, errShellExited):
		return nil
	case errors.Is(cause, ErrClientClosed), errors.Is(cause, transport.ErrEnded):
		// The END frame closes the connection as it reports the event, so
		// SSP's Recv may see it first.
		return ErrClientClosed
	case parent.Err() != nil:
		return parent.Err()
	}
	return cause
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

// watch logs the transport's events, republishes when a rebuilt emulator
// has a new screen, and ends the session T5 after the spawner says the
// shell exited.
func (s *Session) watch(ctx context.Context, conn *transport.Conn) error {
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
		case ev := <-conn.Events():
			s.Log.Info("transport", "event", fmt.Sprintf("%T", ev), "detail", fmt.Sprintf("%+v", ev))
			if _, ok := ev.(transport.Ended); ok {
				return ErrClientClosed
			}
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

// deliverFinal lets SSP, still running, deliver the last screen: until the
// client has acknowledged that very screen, SSP has stopped, or T6
// (server.md §2.4). The pty reader has stopped, so the screen published
// here is the last; if the client already had it, this returns at once.
func (s *Session) deliverFinal(sspDone <-chan struct{}) {
	final := s.publish()
	ep := s.endpoint()
	deadline := time.After(T6)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
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
// the echo-off bit (D12) and the input consumed (ssp.md §10.1). If the
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
// first and have no queue of their own: the client's stream is the queue,
// one event at a time leaves it, and applied advances only once the pty has
// taken the whole event. A program that never reads its input therefore
// holds applied, InputConsumed with it, and the client stops reading its
// terminal: a bounded stall, not a bug.
func (s *Session) writePTY(ctx context.Context) error {
	var applied uint64
	var unpublished int
	ep := s.endpoint()
	for {
		stream, _ := ep.Remote()
		events := stream.Since(applied)
		if first := stream.Len() - uint64(len(events)); first > applied {
			// The stream has forgotten events not yet written: the client
			// ran past RetainBytes, ignoring InputConsumed. Nothing is
			// skipped silently (ssp.md §10.1).
			return fmt.Errorf("%w: input flow control ignored", ssp.ErrProtocol)
		}
		if len(events) > 0 {
			ev := events[0]
			if len(ev.Keys) > 0 {
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
			unpublished += encodedLen(ev)
			// Published once it has moved ConsumedStep, so ordinary typing
			// never costs a frame of its own (ssp.md §10.1).
			if unpublished >= userinput.ConsumedStep {
				unpublished = 0
				s.mu.Lock()
				s.consumed = applied
				s.mu.Unlock()
				s.publish()
			}
			continue
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
		select {
		case <-ctx.Done():
			return nil
		case <-ep.RemoteChanged():
		case <-s.repliesIn:
		}
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
