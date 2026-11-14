package client

import (
	"context"
	"errors"
	"io"
	"log/slog"

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
}

// painter is the part of render.Renderer the loop draws with.
type painter[R any] interface {
	Render(g R) error
	Invalidate()
	Enter() error
	Leave() error
}

// loop is the client's session once the transport is up: keystrokes
// become input events, size changes become resize events, new screens are
// drawn, and the transport's events end it or are logged.
type loop[L inputLog, R any] struct {
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
}

func (l *loop[L, R]) run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := l.paint.Enter(); err != nil {
		return fail(err, "setting up the terminal: %v", err)
	}
	defer l.paint.Leave()

	runErr := make(chan error, 1)
	go func() { runErr <- l.sync.Run(ctx) }()

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
	l.input.Resize(size)
	l.sync.Set(l.input)
	var heldSize *userinput.Size // a resize that came while paused
	askRead()

	var (
		screen  R
		haveOne bool
	)
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-runErr:
			if ctx.Err() != nil {
				return nil
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
				l.input.Type(b)
			}
			if heldSize != nil && !l.paused() {
				l.input.Resize(*heldSize)
				heldSize = nil
			}
			l.sync.Set(l.input)
			askRead()
		case <-l.term.Resized():
			next, changed := l.size(size)
			// Redraw in full either way: a SIGCONT means the screen may
			// have been drawn over while stopped.
			l.paint.Invalidate()
			if r, ok := any(l.paint).(interface{ Resize(cols, rows int) }); ok {
				r.Resize(next.Cols, next.Rows)
			}
			if changed {
				size = next
				if l.paused() {
					heldSize = &next // coalesced to the newest (ssp.md §10.1)
				} else {
					l.input.Resize(next)
					l.sync.Set(l.input)
				}
			}
			if haveOne {
				if err := l.paint.Render(screen); err != nil {
					return fail(err, "drawing: %v", err)
				}
			}
		case <-l.sync.RemoteChanged():
			screen, _ = l.sync.Remote()
			haveOne = true
			if err := l.paint.Render(screen); err != nil {
				return fail(err, "drawing: %v", err)
			}
			if heldSize != nil && !l.paused() {
				l.input.Resize(*heldSize)
				heldSize = nil
				l.sync.Set(l.input)
			}
			askRead()
		case ev := <-l.events:
			switch ev := ev.(type) {
			case transport.Revoked:
				return &TakenOverError{By: ev.By, At: ev.At}
			case transport.PeerChanged:
				l.log.Info("server path changed", "from", ev.From, "to", ev.To)
			case transport.Rekeyed:
				l.log.Debug("rekeyed", "epoch", ev.Epoch)
			}
		}
	}
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
