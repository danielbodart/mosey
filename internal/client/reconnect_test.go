package client

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/danielbodart/mosey/internal/transport"
	"github.com/danielbodart/mosey/internal/userinput"
)

// R3, the client's own reconnect (bootstrap.md §9.2.2), on the loop with
// fakes, in virtual time: when it tries, how it backs off, how it swaps a
// new transport in, and how it ends.

// fakeLink is one transport's worth of fakes, and when it last heard.
type fakeLink struct {
	sync    *fakeSync
	input   *fakeInput
	events  chan transport.Event
	mu      sync.Mutex
	last    time.Time
	retired bool
	ended   []transport.EndReason
}

func newFakeLink() *fakeLink {
	return &fakeLink{sync: newFakeSync(), input: &fakeInput{}, events: make(chan transport.Event, 4), last: time.Now()}
}

func (f *fakeLink) heard() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.last }
func (f *fakeLink) hear()            { f.mu.Lock(); f.last = time.Now(); f.mu.Unlock() }
func (f *fakeLink) isRetired() bool  { f.mu.Lock(); defer f.mu.Unlock(); return f.retired }

func (f *fakeLink) link(holder byte) link[*fakeInput, *fakeScreen] {
	return link[*fakeInput, *fakeScreen]{
		sync: f.sync, input: f.input, events: f.events,
		paused: func() bool { return false },
		heard:  f.heard,
		holder: [8]byte{holder},
		retire: func() { f.mu.Lock(); f.retired = true; f.mu.Unlock() },
		end:    func(r transport.EndReason) { f.ended = append(f.ended, r) },
	}
}

// try is one call of the reconnect, as the fake saw it.
type try struct {
	at     time.Time
	holder [8]byte
}

type rcHarness struct {
	first *fakeLink
	paint *fakePaint
	term  *fakeTerm
	tries []try
	done  chan error
}

// startReconnecting runs a loop over a first fake link whose reconnect
// answers with each of answers in turn (each may use dial).
func startReconnecting(t *testing.T, answers ...func(dial func() bool) (link[*fakeInput, *fakeScreen], error)) *rcHarness {
	return startReconnectingFrom(t, newFakeLink(), answers...)
}

// startReconnectingFrom is startReconnecting over first, made beforehand
// so an answer can use it.
func startReconnectingFrom(t *testing.T, first *fakeLink, answers ...func(dial func() bool) (link[*fakeInput, *fakeScreen], error)) *rcHarness {
	h := &rcHarness{first: first, paint: &fakePaint{}, term: newFakeTerm(100, 30), done: make(chan error, 1)}
	l := &loop[*fakeInput, *fakeScreen]{
		paint:          h.paint,
		term:           h.term,
		log:            slog.New(slog.DiscardHandler),
		reconnectAfter: ReconnectAfter,
		backoff:        reconnectBackoff,
		status:         func(s *fakeScreen, text string) *fakeScreen { return &fakeScreen{s.text + "|" + text} },
	}
	l.adopt(h.first.link(1))
	var mu sync.Mutex
	n := 0
	l.reconnect = func(ctx context.Context, holder [8]byte, dial func() bool) (link[*fakeInput, *fakeScreen], error) {
		mu.Lock()
		h.tries = append(h.tries, try{time.Now(), holder})
		i := n
		n++
		mu.Unlock()
		if i >= len(answers) {
			<-ctx.Done()
			return link[*fakeInput, *fakeScreen]{}, ctx.Err()
		}
		return answers[i](dial)
	}
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { h.done <- l.run(ctx) }()
	t.Cleanup(h.term.close)
	synctest.Wait()
	return h
}

func fails(dial func() bool) (link[*fakeInput, *fakeScreen], error) {
	return link[*fakeInput, *fakeScreen]{}, errors.New("ssh: connect to host far port 22: Network is unreachable")
}

func succeeds(next *fakeLink) func(dial func() bool) (link[*fakeInput, *fakeScreen], error) {
	return func(dial func() bool) (link[*fakeInput, *fakeScreen], error) {
		if !dial() {
			return link[*fakeInput, *fakeScreen]{}, errAbandoned
		}
		next.hear() // a new link begins heard, as newLink's does
		return next.link(2), nil
	}
}

// The backoff between failed tries: 2 s, doubling, at most 60 s (§9.2.2).
func TestTheReconnectBackoffDoublesFromTwoSecondsToAMinute(t *testing.T) {
	want := []time.Duration{2, 4, 8, 16, 32, 60, 60, 60}
	for n, w := range want {
		if got := reconnectBackoff(n); got != w*time.Second {
			t.Errorf("after try %d: %v, want %v", n+1, got, w*time.Second)
		}
	}
}

// A client that hears nothing for ReconnectAfter tries, by itself, to
// resume its session naming the credential it holds; a failed try is
// tried again after the backoff; the one that works is swapped in without
// leaving the screen: the new transport gets the window size first and
// the screen is redrawn whole, and the old one is closed (D8 R3).
func TestASilentLinkIsReplacedByAReconnectThatKeepsTheScreen(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		next := newFakeLink()
		h := startReconnecting(t, fails, fails, succeeds(next))
		time.Sleep(ReconnectAfter + 2*time.Second + 4*time.Second + time.Second)
		synctest.Wait()
		if len(h.tries) != 3 {
			t.Fatalf("%d tries", len(h.tries))
		}
		for i, wantAt := range []time.Duration{ReconnectAfter, ReconnectAfter + 2*time.Second, ReconnectAfter + 6*time.Second} {
			if got := h.tries[i].at.Sub(start); got != wantAt {
				t.Errorf("try %d at %v, want %v", i+1, got, wantAt)
			}
			if h.tries[i].holder != [8]byte{1} {
				t.Errorf("try %d named %x", i+1, h.tries[i].holder)
			}
		}
		if !h.first.isRetired() {
			t.Error("the old transport was not closed")
		}
		if len(next.input.events) != 1 || next.input.events[0].Resize != (userinput.Size{Cols: 100, Rows: 30}) || next.sync.lastSet() != 1 {
			t.Errorf("the new transport's first input: %+v, sets %v", next.input.events, next.sync.sets)
		}
		if h.paint.left || h.paint.invalidated == 0 {
			t.Errorf("left the screen %v, invalidated %d", h.paint.left, h.paint.invalidated)
		}
		// Keys and screens now go over the new transport.
		h.term.keys <- []byte("x")
		next.sync.show("after")
		synctest.Wait()
		if got := next.input.events[len(next.input.events)-1]; string(got.Keys) != "x" {
			t.Errorf("a key after the swap went to %+v", got)
		}
		if h.paint.drawn[len(h.paint.drawn)-1] != "after" {
			t.Errorf("drew %v", h.paint.drawn)
		}
		select {
		case err := <-h.done:
			t.Fatalf("the loop ended: %v", err)
		default:
		}
	})
}

// A link that keeps hearing from the server is never reconnected: a dead
// spot shorter than ReconnectAfter is roaming's alone.
func TestALinkThatIsHeardIsNeverReconnected(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := startReconnecting(t, fails)
		for range 30 {
			time.Sleep(ReconnectAfter - time.Second)
			h.first.hear()
		}
		synctest.Wait()
		if len(h.tries) != 0 {
			t.Errorf("%d tries while the server was heard", len(h.tries))
		}
	})
}

// A try that finds the old link heard again before it dials is dropped,
// and the old link stays (roaming won).
func TestAReconnectWhoseOldLinkIsHeardAgainIsDropped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first, next := newFakeLink(), newFakeLink()
		h := startReconnectingFrom(t, first, func(dial func() bool) (link[*fakeInput, *fakeScreen], error) {
			first.hear()
			return succeeds(next)(dial)
		})
		time.Sleep(ReconnectAfter + time.Second)
		synctest.Wait()
		if len(h.tries) != 1 || h.first.isRetired() {
			t.Errorf("%d tries; old link retired %v", len(h.tries), h.first.isRetired())
		}
	})
}

// A session found gone ends the client with ErrSessionGone; one held by
// another client ends it as taken over (§9.2.2).
func TestAReconnectThatFindsTheSessionGoneOrTakenEndsTheClient(t *testing.T) {
	at := time.Unix(1794650000, 0)
	for name, c := range map[string]struct {
		err  error
		want func(error) bool
	}{
		"gone":  {ErrSessionGone, func(err error) bool { return errors.Is(err, ErrSessionGone) }},
		"taken": {&TakenOverError{At: at}, func(err error) bool { var e *TakenOverError; return errors.As(err, &e) && e.At.Equal(at) }},
	} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h := startReconnecting(t, func(func() bool) (link[*fakeInput, *fakeScreen], error) {
					return link[*fakeInput, *fakeScreen]{}, c.err
				})
				time.Sleep(ReconnectAfter + time.Second)
				synctest.Wait()
				select {
				case err := <-h.done:
					if !c.want(err) {
						t.Errorf("ended with %v", err)
					}
				default:
					t.Fatal("the loop did not end")
				}
			})
		})
	}
}

// The new transport's confirmation revokes the old one (D26), so a
// REVOKED on the old link while this client's own try is dialling is not
// a takeover; it is one only if the try then fails.
func TestARevocationWhileDiallingIsTheReconnectsOwnUnlessItFails(t *testing.T) {
	for _, succeed := range []bool{true, false} {
		synctest.Test(t, func(t *testing.T) {
			first, next := newFakeLink(), newFakeLink()
			by := netip.MustParseAddrPort("192.0.2.9:41000")
			h := startReconnectingFrom(t, first, func(dial func() bool) (link[*fakeInput, *fakeScreen], error) {
				if !dial() {
					return link[*fakeInput, *fakeScreen]{}, errAbandoned
				}
				first.events <- transport.Revoked{By: by, At: time.Now()}
				synctest.Wait()
				if !succeed {
					return link[*fakeInput, *fakeScreen]{}, errors.New("no reply over UDP")
				}
				return next.link(2), nil
			})
			time.Sleep(ReconnectAfter + time.Second)
			synctest.Wait()
			var taken *TakenOverError
			select {
			case err := <-h.done:
				if succeed || !errors.As(err, &taken) || taken.By != by {
					t.Errorf("succeed %v: ended with %v", succeed, err)
				}
			default:
				if !succeed {
					t.Error("a revocation and a failed dial left the loop running")
				}
			}
		})
	}
}

// While R3 tries and fails, the screen says so, with how long the server
// has been silent and why the last try failed, and says nothing again
// once the server is heard: a reconnect that cannot succeed (a host that
// wants a password, which BatchMode cannot give) is never just a frozen
// screen (D8 R3).
func TestAFailingReconnectIsShownOnTheScreenUntilTheServerIsHeard(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := startReconnecting(t, fails)
		h.first.sync.show("shell")
		synctest.Wait()
		last := func() string { d := h.paint.drawnSoFar(); return d[len(d)-1] }
		time.Sleep(ReconnectAfter)
		synctest.Wait()
		trying := "shell|mosey: no contact for 15s; reconnecting over ssh"
		failed := trying + " (last try: ssh: connect to host far port 22: Network is unreachable)"
		if d := h.paint.drawnSoFar(); !slices.Contains(d, trying) || last() != failed {
			t.Fatalf("drew %q; want %q then %q", d, trying, failed)
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if want := "shell|mosey: no contact for 16s; reconnecting over ssh (last try: ssh: connect to host far port 22: Network is unreachable)"; last() != want {
			t.Errorf("a second later drew %q, want %q", last(), want)
		}
		h.first.hear()
		time.Sleep(time.Second)
		synctest.Wait()
		if last() != "shell" {
			t.Errorf("once the server was heard again drew %q, want the screen alone", last())
		}
	})
}

// The notice quotes the failure's first line only, as printable ASCII, and
// at most MaxNoticeErr bytes of it: it may hold whatever ssh printed.
func TestTheReconnectNoticeQuotesOnlyAPrintableLineOfTheFailure(t *testing.T) {
	got := reconnectNotice(61500*time.Millisecond, "ssh: \x1b]0;evil\x07denied\nsecond line")
	if want := "mosey: no contact for 1m2s; reconnecting over ssh (last try: ssh: ]0;evildenied)"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	long := reconnectNotice(time.Second, strings.Repeat("x", 500))
	if n := strings.Count(long, "x"); n != MaxNoticeErr {
		t.Errorf("quoted %d bytes of the failure, want %d", n, MaxNoticeErr)
	}
}
