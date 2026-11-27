package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"syscall"
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
func (f *fakeInput) Len() uint64             { return uint64(len(f.events)) }

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
	mu          sync.Mutex // for a test that reads drawn while the loop still draws
	drawn       []string
	invalidated int
	entered     bool
	left        bool
	size        [2]int
}

func (p *fakePaint) Render(g *fakeScreen) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.drawn = append(p.drawn, g.text)
	return nil
}

// drawnSoFar is a copy of drawn, safe while the loop runs.
func (p *fakePaint) drawnSoFar() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.drawn)
}

func (p *fakePaint) Invalidate()           { p.invalidated++ }
func (p *fakePaint) Enter() error          { p.entered = true; return nil }
func (p *fakePaint) Leave() error          { p.left = true; return nil }
func (p *fakePaint) Resize(cols, rows int) { p.size = [2]int{cols, rows} }

// fakeTerm is the user's terminal: what the test types arrives through
// keys, and its size is whatever the test sets.
type fakeTerm struct {
	keys       chan []byte
	closed     bool
	endErr     error // what Read says once closed; io.EOF if nil
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
		if t.endErr != nil {
			return 0, t.endErr
		}
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
func start(t *testing.T) *harness { return startWith(t, nil) }

// startWith is start with a predictor, if pr is not nil.
func startWith(t *testing.T, pr *fakePredict) *harness {
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
	if pr != nil {
		l.predict = pr
		l.rtt = func() time.Duration { return 123 * time.Millisecond }
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
		h.events <- transport.Revoked{By: by, Host: "blade", At: at}
		synctest.Wait()
		err := <-h.done
		var taken *TakenOverError
		if !errors.As(err, &taken) || taken.By != by || taken.Host != "blade" || !taken.At.Equal(at) || ExitStatus(err) != StatusTakenOver {
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

// A new client that claimed a name is shown by it, with the address the
// server saw beside it, loopback the same as any other (bootstrap.md §9.1).
func TestTheTakenOverMessageNamesTheNewClientsHostBesideItsAddress(t *testing.T) {
	at := time.Date(2026, 11, 27, 10, 0, 0, 0, time.FixedZone("", 0))
	when := at.Local().Format("2006-01-02T15:04:05-07:00")
	for by, want := range map[string]string{
		"192.168.1.20:41234": "session taken over from blade (192.168.1.20) at " + when,
		"127.0.0.1:60001":    "session taken over from blade (127.0.0.1) at " + when,
	} {
		e := &TakenOverError{By: netip.MustParseAddrPort(by), Host: "blade", At: at}
		if e.Error() != want {
			t.Errorf("%q, want %q", e.Error(), want)
		}
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

// The server's END (its shell exited) is the normal way out, whichever of
// the event and SSP's closed Recv the loop sees first.
func TestTheServerEndingTheSessionIsANormalExit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := start(t)
		h.events <- transport.Ended{Reason: transport.EndShellExited}
		synctest.Wait()
		if err := <-h.done; !errors.Is(err, errSessionEnded) {
			t.Errorf("after Ended: %v", err)
		}
		if !h.paint.left {
			t.Error("the terminal was not put back before exiting")
		}
	})
	synctest.Test(t, func(t *testing.T) {
		h := start(t)
		h.sync.fail <- fmt.Errorf("ssp: receiving: %w", transport.ErrEnded)
		synctest.Wait()
		if err := <-h.done; !errors.Is(err, errSessionEnded) {
			t.Errorf("after ErrEnded: %v", err)
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

// Closing the window can make the terminal's read fail with EIO before
// the SIGHUP arrives; it is the same detach, so -close-if-idle still runs.
func TestAHungUpTerminalEndsTheSessionLikeItsEnd(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := start(t)
		h.term.endErr = &fs.PathError{Op: "read", Path: "/dev/stdin", Err: syscall.EIO}
		h.term.close()
		synctest.Wait()
		if err := <-h.done; err != nil {
			t.Errorf("%v", err)
		}
	})
}

func TestAnyOtherTerminalErrorFailsTheSession(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := start(t)
		h.term.endErr = &fs.PathError{Op: "read", Path: "/dev/stdin", Err: syscall.EBADF}
		h.term.close()
		synctest.Wait()
		if err := <-h.done; err == nil {
			t.Error("an EBADF read ended the session cleanly")
		}
	})
}

func eventEqual(a, b userinput.Event) bool {
	return string(a.Keys) == string(b.Keys) && a.Resize == b.Resize
}

// fakePredict records what the loop tells prediction, and overlays the
// keys it was told on the newest screen.
type fakePredict struct {
	keys  []uint64
	skips []uint64
	typed string
	frame *fakeScreen
	rtt   time.Duration
}

func (f *fakePredict) Key(n uint64, b []byte) { f.keys = append(f.keys, n); f.typed += string(b) }
func (f *fakePredict) Skip(n uint64)          { f.skips = append(f.skips, n) }
func (f *fakePredict) Frame(g *fakeScreen)    { f.frame, f.typed = g, "" }
func (f *fakePredict) SetRTT(d time.Duration) { f.rtt = d }
func (f *fakePredict) Overlay() *fakeScreen   { return &fakeScreen{f.frame.text + f.typed} }

func TestAPredictedKeyIsDrawnAtOnceNotARoundTripLater(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pr := &fakePredict{}
		h := startWith(t, pr)
		h.sync.show("$ ")
		synctest.Wait()
		h.term.keys <- []byte("l")
		synctest.Wait()
		if got := h.paint.drawn[len(h.paint.drawn)-1]; got != "$ l" {
			t.Fatalf("drawn %q after the key, before any screen", got)
		}
		if pr.rtt != 123*time.Millisecond {
			t.Errorf("prediction was told an RTT of %v", pr.rtt)
		}
		// Events are numbered as the stream numbers them: the window size
		// is event 1, and not a key.
		if !slices.Equal(pr.skips, []uint64{1}) || !slices.Equal(pr.keys, []uint64{2}) {
			t.Errorf("skips %v keys %v", pr.skips, pr.keys)
		}
		h.stop(t)
	})
}

func TestAResizeIsAnEventPredictionCannotReplay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pr := &fakePredict{}
		h := startWith(t, pr)
		h.sync.show("$ ")
		synctest.Wait()
		h.term.cols = 120
		h.term.resized <- struct{}{}
		synctest.Wait()
		h.term.keys <- []byte("l")
		synctest.Wait()
		if !slices.Equal(pr.skips, []uint64{1, 2}) || !slices.Equal(pr.keys, []uint64{3}) {
			t.Errorf("skips %v keys %v", pr.skips, pr.keys)
		}
		h.stop(t)
	})
}
