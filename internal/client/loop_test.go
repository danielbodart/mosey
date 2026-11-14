package client

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/danielbodart/mosey/internal/transport"
	"github.com/danielbodart/mosey/internal/userinput"
)

// fakeInput records the events the loop appends.
type fakeInput struct{ events []userinput.Event }

func (f *fakeInput) Type(keys []byte) {
	f.events = append(f.events, userinput.Event{Keys: append([]byte(nil), keys...)})
}
func (f *fakeInput) Resize(s userinput.Size) { f.events = append(f.events, userinput.Event{Resize: s}) }

// fakeScreen stands for a screen.Grid: the loop never looks inside one.
type fakeScreen struct{ text string }

// fakeSync is an SSP endpoint: it records how many events each Set
// carried, and serves screens the test puts in.
type fakeSync struct {
	sets    []int
	remote  *fakeScreen
	changed chan struct{}
	fail    chan error
}

func newFakeSync() *fakeSync {
	return &fakeSync{changed: make(chan struct{}, 1), fail: make(chan error)}
}

func (f *fakeSync) Run(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-f.fail:
		return err
	}
}
func (f *fakeSync) Set(l *fakeInput)               { f.sets = append(f.sets, len(l.events)) }
func (f *fakeSync) Remote() (*fakeScreen, uint64)  { return f.remote, 0 }
func (f *fakeSync) RemoteChanged() <-chan struct{} { return f.changed }
func (f *fakeSync) show(text string)               { f.remote = &fakeScreen{text}; f.changed <- struct{}{} }
func (f *fakeSync) lastSet() int                   { return f.sets[len(f.sets)-1] }

// fakePaint records what the loop draws.
type fakePaint struct {
	drawn       []string
	invalidated int
	entered     bool
	left        bool
	size        [2]int
}

func (p *fakePaint) Render(g *fakeScreen) error { p.drawn = append(p.drawn, g.text); return nil }
func (p *fakePaint) Invalidate()                { p.invalidated++ }
func (p *fakePaint) Enter() error               { p.entered = true; return nil }
func (p *fakePaint) Leave() error               { p.left = true; return nil }
func (p *fakePaint) Resize(cols, rows int)      { p.size = [2]int{cols, rows} }

// fakeTerm is the user's terminal: what the test types arrives through
// keys, and its size is whatever the test sets.
type fakeTerm struct {
	keys       chan []byte
	closed     bool
	cols, rows int
	resized    chan struct{}
	out        strings.Builder
}

func newFakeTerm(cols, rows int) *fakeTerm {
	return &fakeTerm{keys: make(chan []byte), cols: cols, rows: rows, resized: make(chan struct{}, 1)}
}

func (t *fakeTerm) Read(p []byte) (int, error) {
	k, ok := <-t.keys
	if !ok {
		return 0, io.EOF
	}
	return copy(p, k), nil
}
func (t *fakeTerm) Write(p []byte) (int, error)       { return t.out.Write(p) }
func (t *fakeTerm) Size() (cols, rows int, err error) { return t.cols, t.rows, nil }
func (t *fakeTerm) Resized() <-chan struct{}          { return t.resized }
func (t *fakeTerm) Raw() error                        { return nil }
func (t *fakeTerm) Restore() error                    { return nil }

func (t *fakeTerm) close() {
	if !t.closed {
		t.closed = true
		close(t.keys)
	}
}

type harness struct {
	sync   *fakeSync
	input  *fakeInput
	paint  *fakePaint
	term   *fakeTerm
	events chan transport.Event
	paused bool
	done   chan error
	cancel context.CancelFunc
}

// start runs a loop with fakes all round, inside the test's bubble.
func start(t *testing.T) *harness {
	h := &harness{
		sync:   newFakeSync(),
		input:  &fakeInput{},
		paint:  &fakePaint{},
		term:   newFakeTerm(100, 30),
		events: make(chan transport.Event, 4),
		done:   make(chan error, 1),
	}
	l := &loop[*fakeInput, *fakeScreen]{
		sync:   h.sync,
		input:  h.input,
		paint:  h.paint,
		term:   h.term,
		events: h.events,
		log:    slog.New(slog.DiscardHandler),
		paused: func() bool { return h.paused },
	}
	ctx, cancel := context.WithCancel(t.Context())
	h.cancel = cancel
	go func() { h.done <- l.run(ctx) }()
	// The reader blocks in Read when the loop ends, as it does in mosey,
	// where the process then exits; here the terminal is closed instead.
	t.Cleanup(h.term.close)
	synctest.Wait()
	return h
}

func (h *harness) stop(t *testing.T) error {
	t.Helper()
	h.cancel()
	synctest.Wait()
	select {
	case err := <-h.done:
		return err
	default:
		t.Fatal("the loop did not end")
		return nil
	}
}

func TestTheFirstEventIsTheWindowSize(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := start(t)
		if !h.paint.entered {
			t.Error("the renderer was not entered")
		}
		want := []userinput.Event{{Resize: userinput.Size{Cols: 100, Rows: 30}}}
		if !slices.EqualFunc(h.input.events, want, eventEqual) || h.sync.lastSet() != 1 {
			t.Errorf("events %v, sets %v", h.input.events, h.sync.sets)
		}
		if err := h.stop(t); err != nil {
			t.Error(err)
		}
		if !h.paint.left {
			t.Error("the renderer was not left")
		}
	})
}

func TestKeystrokesBecomeInputEventsInOrder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := start(t)
		h.term.keys <- []byte("ls")
		h.term.keys <- []byte("\r")
		synctest.Wait()
		if len(h.input.events) != 3 || string(h.input.events[1].Keys) != "ls" || string(h.input.events[2].Keys) != "\r" {
			t.Errorf("events %v", h.input.events)
		}
		if h.sync.lastSet() != 3 {
			t.Errorf("SSP was last given %d events", h.sync.lastSet())
		}
		h.stop(t)
	})
}

func TestEachNewScreenIsDrawn(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := start(t)
		h.sync.show("$ ")
		synctest.Wait()
		h.sync.show("$ ls")
		synctest.Wait()
		if !slices.Equal(h.paint.drawn, []string{"$ ", "$ ls"}) {
			t.Errorf("drew %q", h.paint.drawn)
		}
		h.stop(t)
	})
}

func TestAResizeIsSentAndTheScreenRedrawnInFull(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := start(t)
		h.sync.show("$ ")
		synctest.Wait()
		h.term.cols, h.term.rows = 120, 40
		h.term.resized <- struct{}{}
		synctest.Wait()
		last := h.input.events[len(h.input.events)-1]
		if last.Resize != (userinput.Size{Cols: 120, Rows: 40}) || h.sync.lastSet() != 2 {
			t.Errorf("events %v", h.input.events)
		}
		if h.paint.invalidated != 1 || len(h.paint.drawn) != 2 || h.paint.size != [2]int{120, 40} {
			t.Errorf("invalidated %d, drew %q, size %v", h.paint.invalidated, h.paint.drawn, h.paint.size)
		}
		// A SIGCONT with no size change redraws, but sends nothing.
		h.term.resized <- struct{}{}
		synctest.Wait()
		if len(h.input.events) != 2 || h.paint.invalidated != 2 || len(h.paint.drawn) != 3 {
			t.Errorf("events %v, invalidated %d, drew %d", h.input.events, h.paint.invalidated, len(h.paint.drawn))
		}
		h.stop(t)
	})
}

func TestATerminalOfNoSizeIsTakenAsEightyByTwentyFour(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		if s := clampSize(0, 0); s != (userinput.Size{Cols: 80, Rows: 24}) {
			t.Errorf("%v", s)
		}
		if s := clampSize(70000, 3); s != (userinput.Size{Cols: 65535, Rows: 3}) {
			t.Errorf("%v", s)
		}
	})
}

func TestRevocationEndsTheSessionAsTakenOver(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := start(t)
		at := time.Date(2026, 11, 14, 9, 30, 12, 0, time.UTC)
		by := netip.MustParseAddrPort("198.51.100.4:41000")
		h.events <- transport.PeerChanged{}
		h.events <- transport.Revoked{By: by, At: at}
		synctest.Wait()
		err := <-h.done
		var taken *TakenOverError
		if !errors.As(err, &taken) || taken.By != by || !taken.At.Equal(at) || ExitStatus(err) != StatusTakenOver {
			t.Fatalf("%v", err)
		}
		if !h.paint.left {
			t.Error("the terminal was not put back before exiting")
		}
	})
}

func TestTheTakenOverMessageSaysWhoAndWhen(t *testing.T) {
	at := time.Date(2026, 11, 14, 9, 30, 12, 0, time.FixedZone("", 0))
	e := &TakenOverError{By: netip.MustParseAddrPort("[2001:db8::1]:60001"), At: at}
	want := "session taken over from [2001:db8::1]:60001 at " + at.Local().Format("2006-01-02T15:04:05-07:00")
	if e.Error() != want {
		t.Errorf("%q", e.Error())
	}
	if !strings.Contains(want, "T") || strings.HasSuffix(want, "Z") {
		t.Errorf("not RFC 3339 with a numeric zone: %q", want)
	}
}

// Flow control (ssp.md §10.1): while paused the terminal is not read, and
// a resize waits, coalesced, until reading resumes.
func TestAPausedClientStopsReadingAndHoldsResizes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := start(t)
		h.paused = true
		h.term.keys <- []byte("paste part 1") // the read already asked for
		synctest.Wait()
		sent := make(chan struct{})
		go func() { h.term.keys <- []byte("paste part 2"); close(sent) }()
		synctest.Wait()
		select {
		case <-sent:
			t.Fatal("the terminal was read while paused")
		default:
		}
		h.term.cols, h.term.rows = 90, 20
		h.term.resized <- struct{}{}
		synctest.Wait()
		h.term.cols, h.term.rows = 91, 21
		h.term.resized <- struct{}{}
		synctest.Wait()
		if n := len(h.input.events); n != 2 {
			t.Fatalf("events while paused: %v", h.input.events)
		}
		// A screen saying the server has caught up resumes reading.
		h.paused = false
		h.sync.show("consumed")
		synctest.Wait()
		<-sent
		synctest.Wait()
		ev := h.input.events
		if len(ev) != 4 || ev[2].Resize != (userinput.Size{Cols: 91, Rows: 21}) || string(ev[3].Keys) != "paste part 2" {
			t.Errorf("events after resuming: %v", ev)
		}
		h.stop(t)
	})
}

func TestASessionFailureIsReported(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := start(t)
		boom := errors.New("ssp: protocol error: bad fragment")
		h.sync.fail <- boom
		synctest.Wait()
		err := <-h.done
		var f *Failure
		if !errors.As(err, &f) || !errors.Is(err, boom) || ExitStatus(err) != StatusFailed {
			t.Errorf("%v", err)
		}
	})
}

func TestTheEndOfTheTerminalEndsTheSession(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := start(t)
		h.term.close()
		synctest.Wait()
		if err := <-h.done; err != nil {
			t.Errorf("%v", err)
		}
	})
}

func eventEqual(a, b userinput.Event) bool {
	return string(a.Keys) == string(b.Keys) && a.Resize == b.Resize
}
