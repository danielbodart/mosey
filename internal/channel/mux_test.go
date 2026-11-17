package channel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

const typeAgent = 1

// echo is an Accept that serves every stream by sending back what it
// reads, then ending its direction.
func echo(context.Context, uint8) (func(*Stream), error) {
	return func(s *Stream) {
		io.Copy(s, s)
		s.CloseWrite()
		s.Close()
	}, nil
}

// roundTrip opens a stream, writes data, ends its direction, and returns
// everything read back.
func roundTrip(t *testing.T, m *Mux, data []byte) []byte {
	t.Helper()
	s, err := m.Open(context.Background(), typeAgent)
	if err != nil {
		t.Error(err)
		return nil
	}
	var got []byte
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		got, err = io.ReadAll(s)
		if err != nil {
			t.Error(err)
		}
	}()
	if _, err := s.Write(data); err != nil {
		t.Error(err)
	}
	s.CloseWrite()
	wg.Wait()
	s.Close()
	return got
}

func random(seed uint64, n int) []byte {
	r := rand.New(rand.NewPCG(seed, 1))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return b
}

// Many streams at once, over a path that loses, duplicates and reorders,
// each carry exactly the bytes written, in order, both ways (agent.md
// §5.3–§5.5).
func TestStreamsDeliverEveryByteInOrderOverALossyPath(t *testing.T) {
	for _, c := range []struct {
		name            string
		loss, dup       float64
		delay, jitter   time.Duration
		streams, length int
	}{
		{"clean", 0, 0, 20 * time.Millisecond, 0, 4, 300 << 10},
		{"lossy", 0.15, 0.05, 40 * time.Millisecond, 30 * time.Millisecond, MaxStreams, 40 << 10},
		{"awful", 0.4, 0.1, 150 * time.Millisecond, 100 * time.Millisecond, 3, 8 << 10},
	} {
		t.Run(c.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				l := newLink(7, c.delay)
				l.loss, l.dup, l.jitter = c.loss, c.dup, c.jitter
				p := newPair(l, echo)
				defer p.stop()
				var wg sync.WaitGroup
				for i := range c.streams {
					wg.Add(1)
					go func() {
						defer wg.Done()
						data := random(uint64(i), c.length+i)
						if got := roundTrip(t, p.server, data); !bytes.Equal(got, data) {
							t.Errorf("stream %d: %d bytes back, want %d, equal prefix %v", i, len(got), len(data), bytes.HasPrefix(data, got))
						}
					}()
				}
				wg.Wait()
				// Both ends finish every stream, once the last ACKs are
				// in: nothing is left live.
				time.Sleep(5 * time.Second)
				synctest.Wait()
				if n := p.server.Live() + p.client.Live(); n != 0 {
					t.Errorf("%d streams still live", n)
				}
			})
		})
	}
}

// A reader that does not read holds the writer to the windows: the
// receiver buffers at most RecvBuffer and the sender SendBuffer, and the
// writer waits (agent.md §5.3, §5.4). Reading then delivers everything.
func TestASlowReaderHoldsTheWriterToTheWindows(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		streams := make(chan *Stream, 1)
		p := newPair(newLink(1, 10*time.Millisecond), func(context.Context, uint8) (func(*Stream), error) {
			return func(s *Stream) { streams <- s }, nil
		})
		defer p.stop()
		s, err := p.server.Open(context.Background(), typeAgent)
		if err != nil {
			t.Fatal(err)
		}
		far := <-streams
		data := random(3, 1<<20)
		wrote := make(chan struct{})
		go func() {
			defer close(wrote)
			if _, err := far.Write(data); err != nil {
				t.Error(err)
			}
			far.CloseWrite()
		}()
		time.Sleep(10 * time.Second)
		synctest.Wait()
		select {
		case <-wrote:
			t.Fatal("a megabyte was written to a reader that reads nothing")
		default:
		}
		p.client.mu.Lock()
		sent := len(far.sbuf)
		p.client.mu.Unlock()
		p.server.mu.Lock()
		held := len(s.rbuf)
		p.server.mu.Unlock()
		if held != RecvBuffer || sent != SendBuffer {
			t.Errorf("held %d (want %d) and buffered %d to send (want %d)", held, RecvBuffer, sent, SendBuffer)
		}
		got, err := io.ReadAll(s)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("read %d bytes, err %v", len(got), err)
		}
		<-wrote
	})
}

// A type the far side does not serve is refused, and Open says so.
func TestOpeningATypeThePeerDoesNotServeIsRefused(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPair(newLink(1, 10*time.Millisecond), func(context.Context, uint8) (func(*Stream), error) {
			return nil, ErrRefused
		})
		defer p.stop()
		if _, err := p.server.Open(context.Background(), 9); !errors.Is(err, ErrRefused) {
			t.Fatalf("Open: %v, want ErrRefused", err)
		}
		if p.server.Live() != 0 || p.client.Live() != 0 {
			t.Error("a refused stream is still live")
		}
	})
}

// A local end that cannot be reached is a RESET unavailable, not a hang.
func TestAnUnreachableFarEndFailsTheOpen(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPair(newLink(1, 10*time.Millisecond), func(context.Context, uint8) (func(*Stream), error) {
			return nil, errors.New("no agent")
		})
		defer p.stop()
		_, err := p.server.Open(context.Background(), typeAgent)
		var re *ResetError
		if !errors.As(err, &re) || re.Reason != ReasonUnavailable || !re.Remote {
			t.Fatalf("Open: %v", err)
		}
	})
}

// An OPEN nobody answers is given up after OpenTimeout.
func TestAnOpenNobodyAnswersGivesUp(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := newLink(1, 10*time.Millisecond)
		l.loss = 1
		p := newPair(l, echo)
		defer p.stop()
		start := time.Now()
		if _, err := p.server.Open(context.Background(), typeAgent); err == nil {
			t.Fatal("an unanswered open succeeded")
		}
		if took := time.Since(start); took != OpenTimeout {
			t.Errorf("gave up after %v, want %v", took, OpenTimeout)
		}
		if p.server.Live() != 0 {
			t.Error("the abandoned stream is still live")
		}
	})
}

// A side has at most MaxStreams live; the next Open is refused locally.
func TestNoMoreThanMaxStreamsAreLive(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hold := make(chan struct{})
		p := newPair(newLink(1, 10*time.Millisecond), func(context.Context, uint8) (func(*Stream), error) {
			return func(s *Stream) { <-hold; s.Close() }, nil
		})
		defer p.stop()
		defer close(hold)
		for i := range MaxStreams {
			if _, err := p.server.Open(context.Background(), typeAgent); err != nil {
				t.Fatalf("stream %d: %v", i, err)
			}
		}
		if _, err := p.server.Open(context.Background(), typeAgent); !errors.Is(err, ErrLimit) {
			t.Fatalf("stream %d: %v, want ErrLimit", MaxStreams, err)
		}
	})
}

// rawPeer is a Mux on one end of a link, with the test speaking frames
// directly on the other.
type rawPeer struct {
	m      *Mux
	end    *linkEnd
	cancel context.CancelFunc
	done   chan struct{}
}

func newRawPeer(role Role, accept Accept) *rawPeer {
	l := newLink(1, time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	r := &rawPeer{m: NewMux(l.end[0], Config{Role: role, Accept: accept}), end: l.end[1], cancel: cancel, done: make(chan struct{})}
	go func() { defer close(r.done); r.m.Run(ctx) }()
	return r
}

func (r *rawPeer) stop() { r.cancel(); <-r.done }

func (r *rawPeer) send(t *testing.T, f Frame) {
	t.Helper()
	if err := r.end.SendChannel(Marshal(f)); err != nil {
		t.Fatal(err)
	}
	// Frames due at the same instant may arrive in either order; these
	// tests mean them in the order sent.
	time.Sleep(time.Millisecond)
}

// replies is every frame the mux sent back, once things have settled.
func (r *rawPeer) replies(t *testing.T) []Frame {
	t.Helper()
	time.Sleep(10 * time.Millisecond)
	synctest.Wait()
	var out []Frame
	for {
		select {
		case b := <-r.end.q:
			f, err := ParseFrame(b)
			if err != nil {
				t.Fatalf("the mux sent a frame it cannot parse: %v", err)
			}
			out = append(out, f)
		default:
			return out
		}
	}
}

// The peer cannot open more than MaxStreams at this side, nor an id of the
// wrong parity, nor a type the owner refuses; each is a RESET with its
// reason and creates nothing.
func TestOpensBeyondTheRulesAreResetWithTheirReason(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hold := make(chan struct{})
		r := newRawPeer(Client, func(_ context.Context, typ uint8) (func(*Stream), error) {
			if typ != typeAgent {
				return nil, ErrRefused
			}
			return func(*Stream) { <-hold }, nil
		})
		defer r.stop()
		defer close(hold)
		r.send(t, Frame{Stream: 2, Op: OpOpen, Type: typeAgent}) // the client's own parity
		r.send(t, Frame{Stream: 1, Op: OpOpen, Type: 7})
		got := r.replies(t)
		if len(got) != 2 || got[0].Reason != ReasonRefused || got[1].Reason != ReasonRefused {
			t.Fatalf("replies %+v", got)
		}
		for i := range MaxStreams + 1 {
			r.send(t, Frame{Stream: uint32(2*i + 3), Op: OpOpen, Type: typeAgent, Window: RecvBuffer})
		}
		got = r.replies(t)
		var accepts, limits int
		for _, f := range got {
			switch {
			case f.Op == OpAccept:
				accepts++
			case f.Op == OpReset && f.Reason == ReasonLimit:
				limits++
			}
		}
		if accepts != MaxStreams || limits != 1 {
			t.Errorf("%d accepted and %d refused for the limit; want %d and 1", accepts, limits, MaxStreams)
		}
	})
}

// A frame for a stream the mux does not know is answered with RESET gone,
// and a RESET is never answered, so two forgetful sides cannot bounce
// RESETs for ever. Neither creates anything.
func TestFramesForUnknownStreamsAreResetButResetsAreNot(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newRawPeer(Client, echo)
		defer r.stop()
		r.send(t, Frame{Stream: 5, Op: OpData, Data: []byte("x")})
		r.send(t, Frame{Stream: 7, Op: OpReset, Reason: ReasonGone})
		got := r.replies(t)
		if len(got) != 1 || got[0].Stream != 5 || got[0].Op != OpReset || got[0].Reason != ReasonGone {
			t.Fatalf("replies %+v", got)
		}
		if r.m.Live() != 0 || len(r.m.streams) != 0 {
			t.Error("a frame for an unknown stream created one")
		}
	})
}

// A frame of an op a later release defined is dropped, touching nothing,
// when its op says it may be ignored; with the mark clear it is malformed,
// and the stream it names is reset (agent.md §5.1, versioning.md §3).
func TestAFrameOfALaterOpIsDroppedUnlessCritical(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		streams := make(chan *Stream, 1)
		r := newRawPeer(Client, func(context.Context, uint8) (func(*Stream), error) {
			return func(s *Stream) { streams <- s }, nil
		})
		defer r.stop()
		r.send(t, Frame{Stream: 1, Op: OpOpen, Type: typeAgent, Window: RecvBuffer})
		<-streams
		r.replies(t)
		if err := r.end.SendChannel([]byte{1, 0, 0, 0, 0x90, 7, 7, 7}); err != nil {
			t.Fatal(err)
		}
		got := r.replies(t)
		r.m.mu.Lock()
		ignored, dropped := r.m.ignored, r.m.dropped
		r.m.mu.Unlock()
		if len(got) != 0 || r.m.Live() != 1 || ignored != 1 || dropped != 0 {
			t.Fatalf("an ignorable op: replies %+v, %d live", got, r.m.Live())
		}
		if err := r.end.SendChannel([]byte{1, 0, 0, 0, 0x10, 7, 7, 7}); err != nil {
			t.Fatal(err)
		}
		got = r.replies(t)
		if len(got) != 1 || got[0].Op != OpReset || got[0].Reason != ReasonProtocol || r.m.Live() != 0 {
			t.Fatalf("a critical op: replies %+v, %d live", got, r.m.Live())
		}
	})
}

// Bytes past the peer's FIN, a second FIN elsewhere, or an ACK of bytes
// never sent break the stream rules: the stream is reset, as a protocol
// violation.
func TestBreakingTheStreamRulesResetsTheStream(t *testing.T) {
	for _, c := range []struct {
		name  string
		after []Frame
	}{
		{"data past the FIN", []Frame{{Op: OpData, Offset: 0, Data: []byte("ab"), Fin: true}, {Op: OpData, Offset: 2, Data: []byte("c")}}},
		{"a second FIN elsewhere", []Frame{{Op: OpData, Offset: 0, Data: []byte("ab"), Fin: true}, {Op: OpData, Offset: 0, Data: []byte("a"), Fin: true}}},
		{"an ACK of bytes never sent", []Frame{{Op: OpAck, Offset: 10, Window: RecvBuffer}}},
		{"an ACK of a FIN never sent", []Frame{{Op: OpAck, Offset: 0, Window: RecvBuffer, Fin: true}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				streams := make(chan *Stream, 1)
				r := newRawPeer(Client, func(context.Context, uint8) (func(*Stream), error) {
					return func(s *Stream) { streams <- s }, nil
				})
				defer r.stop()
				r.send(t, Frame{Stream: 1, Op: OpOpen, Type: typeAgent, Window: RecvBuffer})
				s := <-streams
				r.replies(t)
				for _, f := range c.after {
					f.Stream = 1
					r.send(t, f)
				}
				got := r.replies(t)
				if last := got[len(got)-1]; last.Op != OpReset || last.Reason != ReasonProtocol {
					t.Fatalf("replies %+v", got)
				}
				if _, err := io.ReadAll(s); err == nil {
					t.Error("the stream still reads")
				}
				if r.m.Live() != 0 {
					t.Error("the stream is still live")
				}
			})
		})
	}
}

// A finished stream answers a resent DATA with an ACK for Linger, then is
// forgotten.
func TestAFinishedStreamLingersAndIsThenForgotten(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPair(newLink(1, 10*time.Millisecond), echo)
		defer p.stop()
		if got := roundTrip(t, p.server, []byte("ping")); string(got) != "ping" {
			t.Fatalf("got %q", got)
		}
		time.Sleep(time.Second)
		synctest.Wait()
		p.client.mu.Lock()
		lingering := len(p.client.lingering)
		p.client.mu.Unlock()
		if lingering != 1 {
			t.Fatalf("%d lingering on the client, want 1", lingering)
		}
		time.Sleep(Linger + time.Second)
		synctest.Wait()
		for _, m := range []*Mux{p.server, p.client} {
			m.mu.Lock()
			n := len(m.streams)
			m.mu.Unlock()
			if n != 0 {
				t.Errorf("%d streams remembered after Linger", n)
			}
		}
	})
}

// Closing a stream before both directions ended resets it, and the peer
// reads the reset, not an EOF.
func TestClosingEarlyResetsThePeer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		streams := make(chan *Stream, 1)
		p := newPair(newLink(1, 10*time.Millisecond), func(context.Context, uint8) (func(*Stream), error) {
			return func(s *Stream) { streams <- s }, nil
		})
		defer p.stop()
		s, err := p.server.Open(context.Background(), typeAgent)
		if err != nil {
			t.Fatal(err)
		}
		far := <-streams
		s.Close()
		_, err = io.ReadAll(far)
		var re *ResetError
		if !errors.As(err, &re) || re.Reason != ReasonAborted || !re.Remote {
			t.Fatalf("the peer read %v", err)
		}
	})
}

// When the connection under the mux goes, every stream fails and a
// blocked reader or writer wakes.
func TestTheConnectionGoingFailsEveryStream(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		streams := make(chan *Stream, 1)
		p := newPair(newLink(1, 10*time.Millisecond), func(context.Context, uint8) (func(*Stream), error) {
			return func(s *Stream) { streams <- s }, nil
		})
		s, err := p.server.Open(context.Background(), typeAgent)
		if err != nil {
			t.Fatal(err)
		}
		far := <-streams
		read := make(chan error, 1)
		go func() { _, err := io.ReadAll(far); read <- err }()
		synctest.Wait()
		p.stop()
		if err := <-read; !errors.Is(err, ErrClosed) {
			t.Errorf("the far reader got %v", err)
		}
		if _, err := s.Write([]byte("x")); !errors.Is(err, ErrClosed) {
			t.Errorf("a write after the end: %v", err)
		}
		if _, err := p.server.Open(context.Background(), typeAgent); !errors.Is(err, ErrClosed) {
			t.Errorf("an open after the end: %v", err)
		}
	})
}

// The RTO follows the path's round trip (RFC 6298): after traffic on a
// 300 ms path it sits near it, never under MinRTO nor over MaxRTO.
func TestTheRetransmissionTimerFollowsTheRoundTrip(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPair(newLink(1, 150*time.Millisecond), echo)
		defer p.stop()
		for i := range 5 {
			roundTrip(t, p.server, []byte(fmt.Sprint("ping ", i)))
		}
		p.server.mu.Lock()
		rto, srtt := p.server.rto, p.server.srtt
		p.server.mu.Unlock()
		if srtt != 300*time.Millisecond || rto < 300*time.Millisecond || rto > MaxRTO {
			t.Errorf("srtt %v, rto %v", srtt, rto)
		}
	})
}
