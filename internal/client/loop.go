package client

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/danielbodart/mosey/internal/terminal"
	"github.com/danielbodart/mosey/internal/transport"
	"github.com/danielbodart/mosey/internal/userinput"
)

// MaxRead is the most the client reads from its terminal at once
// (ssp.md §10.1): it bounds what one read adds to the input stream, which
// is what makes the server's bound on one input diff derivable.
const MaxRead = 16 << 10

// The loop is written against these small interfaces rather than the
// concrete SSP endpoint, input stream and renderer, so its logic (what
// happens on a keystroke, a resize, a new screen, a revocation) is tested
// with fakes; Session.Run plugs in the real ones.

// syncer is the part of an ssp.Endpoint the loop drives: L is the local
// object (the input stream), R the remote one (the screen).
type syncer[L, R any] interface {
	Run(ctx context.Context) error
	Set(local L)
	Remote() (R, uint64)
	RemoteChanged() <-chan struct{}
}

// inputLog is the part of userinput.Stream the loop writes to.
type inputLog interface {
	Type(keys []byte)
	Resize(size userinput.Size)
	// Len numbers the events, for prediction's echo ack (prediction.md
	// §2).
	Len() uint64
}

// predictor is the part of predict.Engine the loop drives: it is told each
// event and each screen, and gives back the screen to draw.
type predictor[R any] interface {
	Key(n uint64, b []byte)
	Skip(n uint64)
	Frame(g R)
	SetRTT(d time.Duration)
	Overlay() R
}

// painter is the part of render.Renderer the loop draws with.
type painter[R any] interface {
	Render(g R) error
	Invalidate()
	Enter() error
	Leave() error
	// Resize tells it the local terminal's size, which it clips to.
	Resize(cols, rows int)
}

// loop is the client's session once the transport is up: keystrokes
// become input events, size changes become resize events, new screens are
// drawn, and the transport's events end it or are logged. With reconnect
// set it also carries out R3 (bootstrap.md §9.2.2): after reconnectAfter
// of silence it resumes its own session over a fresh SSH login, in the
// background, and swaps the new transport in without leaving raw mode.
type loop[L inputLog, R any] struct {
	// The current link: one transport's SSP endpoint, the input stream it
	// sends, its events, and what is drawn over it (link).
	sync   syncer[L, R]
	input  L
	paint  painter[R]
	term   terminal.Terminal
	events <-chan transport.Event
	log    *slog.Logger
	// paused says whether input flow control (ssp.md §10.1) holds reading
	// back: the server has not yet consumed enough of what was sent. It
	// is asked before each read and again whenever a screen arrives.
	paused func() bool
	// predict, if set, is predictive local echo (D12): what is drawn is
	// its overlay of the screen, with rtt the round trip it is told
	// before each draw (prediction.md §11).
	predict predictor[R]
	rtt     func() time.Duration
	// heard is when the current link last heard anything authentic;
	// holder is the credential it was made with; retire closes it.
	heard  func() time.Time
	holder [8]byte
	retire func()
	end    func(transport.EndReason)

	// reconnect, if set, is one R3 try: a fresh bootstrap that resumes
	// this session naming holder, then, if dial still says go, the
	// handshake, and the new link. reconnectAfter is how long a silence
	// must last before the first try, and backoff the wait after the
	// n-th failed one.
	reconnect      func(ctx context.Context, holder [8]byte, dial func() bool) (link[L, R], error)
	reconnectAfter time.Duration
	backoff        func(n int) time.Duration
	// dialing is set while a try's handshake is in flight: a REVOKED or a
	// failure on the old link then is the try's own doing (§9.2.2).
	dialing atomic.Bool
}

// link is what loop runs over one transport, all of which a reconnect
// replaces at once.
type link[L inputLog, R any] struct {
	sync    syncer[L, R]
	input   L
	events  <-chan transport.Event
	paused  func() bool
	predict predictor[R]
	rtt     func() time.Duration
	heard   func() time.Time
	holder  [8]byte
	retire  func()
	end     func(transport.EndReason)
}

// adopt makes lk the current link.
func (l *loop[L, R]) adopt(lk link[L, R]) {
	l.sync, l.input, l.events, l.paused = lk.sync, lk.input, lk.events, lk.paused
	l.predict, l.rtt, l.heard, l.holder, l.retire, l.end = lk.predict, lk.rtt, lk.heard, lk.holder, lk.retire, lk.end
}

// errAbandoned is a reconnect that found the old link alive again before
// it dialled: roaming won, and nothing changes.
var errAbandoned = errors.New("the old transport is heard again")

// attempt is how one reconnect try ended.
type attempt[L inputLog, R any] struct {
	lk  link[L, R]
	err error
}

// typed appends keys to the input, and tells prediction the event it
// became: one read is one event, unless it is long enough to be split,
// which only a paste is (prediction.md §2).
func (l *loop[L, R]) typed(b []byte) {
	before := l.input.Len()
	l.input.Type(b)
	if l.predict == nil {
		return
	}
	switch after := l.input.Len(); {
	case after == before+1:
		l.predict.Key(after, b)
	case after > before:
		l.predict.Skip(after)
	}
}

// resized appends a resize event, which prediction can't replay.
func (l *loop[L, R]) resized(size userinput.Size) {
	l.input.Resize(size)
	if l.predict != nil {
		l.predict.Skip(l.input.Len())
	}
}

// draw renders screen, or prediction's overlay of it.
func (l *loop[L, R]) draw(screen R) error {
	if l.predict != nil {
		if l.rtt != nil {
			l.predict.SetRTT(l.rtt())
		}
		screen = l.predict.Overlay()
	}
	if err := l.paint.Render(screen); err != nil {
		return fail(err, "drawing: %v", err)
	}
	return nil
}

// errSessionEnded is run's report that the server ended the session (its
// shell exited): the normal way out, which Session.Run turns into nil.
var errSessionEnded = errors.New("the server ended the session")

func (l *loop[L, R]) run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := l.paint.Enter(); err != nil {
		return fail(err, "setting up the terminal: %v", err)
	}
	defer l.paint.Leave()

	// Each link's SSP runs on a context of its own, so a swap stops the
	// old one; its result arrives on a channel of its own, which the loop
	// stops reading at the swap.
	var runErr chan error
	var stopLink context.CancelFunc
	runLink := func() {
		lctx, stop := context.WithCancel(ctx)
		ch := make(chan error, 1)
		go func(s syncer[L, R]) { ch <- s.Run(lctx) }(l.sync)
		runErr, stopLink = ch, stop
	}
	runLink()
	defer func() { stopLink() }()

	// The reader reads only when asked, so flow control can stop reading
	// the terminal outright, leaving a paste in the user's terminal rather
	// than in this process's memory.
	reads := make(chan []byte)
	readErr := make(chan error, 1)
	ask := make(chan struct{}, 1)
	go readTerminal(ctx, l.term, ask, reads, readErr)
	reading := false
	askRead := func() {
		if !reading && !l.paused() {
			reading = true
			ask <- struct{}{}
		}
	}

	// The size is sent again as the first event, in case it changed
	// during the bootstrap (bootstrap.md §6.2).
	size, _ := l.size(userinput.Size{})
	l.resized(size)
	l.sync.Set(l.input)
	var heldSize *userinput.Size // a resize that came while paused
	askRead()

	var (
		screen  R
		haveOne bool
	)

	// R3 (bootstrap.md §9.2.2): wake is when to look at the silence again;
	// tries counts failed tries since the link was last heard, notBefore
	// is the backoff's earliest next try, and pending is what the old
	// link said while a try was dialling (its REVOKED, or its failure),
	// to act on only if the try fails.
	var (
		wake      <-chan time.Time
		tries     int
		notBefore time.Time
		lastFail  time.Time
		trying    bool
		results   = make(chan attempt[L, R], 1)
		pending   error
	)
	arm := func() {
		if l.reconnect == nil || l.heard == nil || trying {
			wake = nil
			return
		}
		at := l.heard().Add(l.reconnectAfter)
		if at.Before(notBefore) {
			at = notBefore
		}
		wake = time.After(time.Until(at))
	}
	defer func() {
		if trying {
			// A try still running when the session ends: whatever it
			// makes is closed, never used.
			go func() {
				if a := <-results; a.err == nil && a.lk.retire != nil {
					a.lk.retire()
				}
			}()
		}
	}()
	arm()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-wake:
			wake = nil
			heard := l.heard()
			if heard.After(lastFail) {
				tries = 0 // heard since the last failure: start the backoff again
			}
			if time.Since(heard) < l.reconnectAfter || time.Now().Before(notBefore) {
				arm()
				continue
			}
			trying = true
			l.log.Info("no word from the server; reconnecting in the background", "silent", time.Since(heard).Round(time.Millisecond), "try", tries+1)
			heardFn, holder := l.heard, l.holder
			go func() {
				// dial is asked just before the handshake: a try whose old
				// link has been heard since it began is dropped.
				dial := func() bool {
					if heardFn().After(heard) {
						return false
					}
					l.dialing.Store(true)
					return true
				}
				lk, err := l.reconnect(ctx, holder, dial)
				results <- attempt[L, R]{lk, err}
			}()
		case a := <-results:
			trying = false
			l.dialing.Store(false)
			switch {
			case a.err == nil:
				l.log.Info("reconnected: a new transport for the same session")
				pending = nil
				stopLink()
				if l.retire != nil {
					l.retire()
				}
				l.adopt(a.lk)
				runLink()
				tries, notBefore = 0, time.Time{}
				// SSP starts afresh on the new transport (ssp.md §1.3): the
				// size goes first again, and the whole screen comes back.
				heldSize = nil
				l.resized(size)
				l.sync.Set(l.input)
				l.paint.Invalidate()
				haveOne = false // prediction starts afresh, with no frame yet
				// A read may be outstanding; if not, the new link's flow
				// control may let one go.
				askRead()
			case errors.Is(a.err, errAbandoned):
				l.log.Info("the server is heard again; dropping the reconnect")
				tries, notBefore = 0, time.Time{}
			case isFinal(a.err):
				return a.err
			default:
				lastFail = time.Now()
				notBefore = lastFail.Add(l.backoff(tries))
				tries++
				l.log.Warn("reconnecting failed; trying again", "err", a.err, "after", time.Until(notBefore).Round(time.Millisecond))
			}
			if a.err != nil && pending != nil {
				return pending
			}
			arm()
		case err := <-runErr:
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, transport.ErrEnded) {
				// The END frame closes the transport as it reports the
				// event, so SSP may see it first.
				return errSessionEnded
			}
			if l.dialing.Load() {
				// The try's own takeover closed the old link; if the try
				// fails after all, this is how the session ended (unless
				// a REVOKED already said so).
				if pending == nil {
					pending = fail(err, "the session failed: %v", err)
				}
				runErr = nil
				continue
			}
			return fail(err, "the session failed: %v", err)
		case err := <-readErr:
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fail(err, "reading the terminal: %v", err)
		case b := <-reads:
			reading = false
			if len(b) > 0 {
				l.typed(b)
			}
			if heldSize != nil && !l.paused() {
				l.resized(*heldSize)
				heldSize = nil
			}
			l.sync.Set(l.input)
			if len(b) > 0 && haveOne && l.predict != nil {
				// The point of prediction: the key is on screen now, not a
				// round trip from now.
				if err := l.draw(screen); err != nil {
					return err
				}
			}
			askRead()
		case <-l.term.Resized():
			next, changed := l.size(size)
			// Redraw in full either way: a SIGCONT means the screen may
			// have been drawn over while stopped.
			l.paint.Invalidate()
			l.paint.Resize(next.Cols, next.Rows)
			if changed {
				size = next
				if l.paused() {
					heldSize = &next // coalesced to the newest (ssp.md §10.1)
				} else {
					l.resized(next)
					l.sync.Set(l.input)
				}
			}
			if haveOne {
				if err := l.draw(screen); err != nil {
					return err
				}
			}
		case <-l.sync.RemoteChanged():
			screen, _ = l.sync.Remote()
			haveOne = true
			if l.predict != nil {
				l.predict.Frame(screen)
			}
			if err := l.draw(screen); err != nil {
				return err
			}
			if heldSize != nil && !l.paused() {
				l.resized(*heldSize)
				heldSize = nil
				l.sync.Set(l.input)
			}
			askRead()
		case ev := <-l.events:
			switch ev := ev.(type) {
			case transport.Revoked:
				if l.dialing.Load() {
					// Very likely this client's own new transport (D26);
					// a takeover only if that dial fails.
					pending = &TakenOverError{By: ev.By, At: ev.At}
					l.events = nil // the old link has nothing more to say
					continue
				}
				return &TakenOverError{By: ev.By, At: ev.At}
			case transport.Ended:
				l.log.Info("the server ended the session", "reason", ev.Reason)
				return errSessionEnded
			case transport.PeerChanged:
				l.log.Info("server path changed", "from", ev.From, "to", ev.To)
			case transport.Rekeyed:
				l.log.Debug("rekeyed", "epoch", ev.Epoch)
			}
		}
	}
}

// isFinal is a reconnect that must not be tried again: the session has
// gone, or another client holds it (bootstrap.md §9.2.2).
func isFinal(err error) bool {
	var taken *TakenOverError
	return errors.Is(err, ErrSessionGone) || errors.As(err, &taken)
}

// size is the terminal's size now, and whether it differs from was. A
// terminal that says 0 is taken as 80x24, the VT100's (bootstrap.md
// §6.2); one that fails to say keeps was.
func (l *loop[L, R]) size(was userinput.Size) (userinput.Size, bool) {
	cols, rows, err := l.term.Size()
	if err != nil {
		l.log.Debug("terminal size", "err", err)
		if was == (userinput.Size{}) {
			return defaultSize, true
		}
		return was, false
	}
	s := clampSize(cols, rows)
	return s, s != was
}

var defaultSize = userinput.Size{Cols: 80, Rows: 24}

// clampSize keeps a local size within what a ClientLine and a resize
// event can carry; the server applies its own, smaller clamp (D23).
func clampSize(cols, rows int) userinput.Size {
	if cols <= 0 || rows <= 0 {
		return defaultSize
	}
	return userinput.Size{Cols: min(cols, 65535), Rows: min(rows, 65535)}
}

// readTerminal reads the terminal once per ask, MaxRead bytes at most,
// and hands each read over as a slice of its own.
func readTerminal(ctx context.Context, t io.Reader, ask <-chan struct{}, reads chan<- []byte, readErr chan<- error) {
	buf := make([]byte, MaxRead)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ask:
		}
		n, err := t.Read(buf)
		if n > 0 {
			select {
			case reads <- append([]byte(nil), buf[:n]...):
			case <-ctx.Done():
				return
			}
		}
		if err != nil {
			select {
			case readErr <- err:
			default:
			}
			return
		}
		if n == 0 {
			// Nothing read and no error: ask again rather than stall.
			select {
			case reads <- nil:
			case <-ctx.Done():
				return
			}
		}
	}
}
