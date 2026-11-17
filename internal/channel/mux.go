package channel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Limits and timers of agent.md §5 and §6.
const (
	// MaxStreams is how many streams may be live on one connection [choice].
	MaxStreams = 16
	// SendBuffer and RecvBuffer bound each stream's unacknowledged and
	// undelivered bytes [choice], so a connection holds at most
	// MaxStreams × 128 KiB.
	SendBuffer = 64 << 10
	RecvBuffer = 64 << 10
	// MaxInFlight bounds the bytes sent and not acknowledged across a
	// connection's streams: a burst of at most 28 datagrams beside the
	// terminal's [choice].
	MaxInFlight = 32 << 10
	// InitialRTO, MinRTO and MaxRTO are the retransmission timer's (RFC
	// 6298 §2 for the first; the floor sits above D11's effective ~150 ms
	// because this peer acks at once, and the cap is ours).
	InitialRTO = time.Second
	MinRTO     = 200 * time.Millisecond
	MaxRTO     = 4 * time.Second
	// OpenTimeout is how long an OPEN may go unanswered [choice: above the
	// client's 5 s agent dial, with room for a lossy path].
	OpenTimeout = 30 * time.Second
	// Linger is how long a finished stream still answers resent DATA, and
	// MaxLinger how many such streams are kept [choice].
	Linger    = 10 * time.Second
	MaxLinger = 64
)

// Role says which stream ids a side opens: the server odd ones, the client
// even ones (agent.md §5.1, RFC 9000 §2.1).
type Role uint8

const (
	Client Role = iota
	Server
)

// Datagrams is what a Mux runs over: *transport.Conn's SendChannel and
// RecvChannel. A body that SendChannel holds back or loses is resent on
// the RTO.
type Datagrams interface {
	SendChannel(body []byte) error
	RecvChannel(ctx context.Context) ([]byte, error)
}

// Accept decides about a stream the peer opened, of type typ. It runs in a
// goroutine of its own, so it may take its time (the client's connects to
// the user's agent). It returns the function that serves the stream once
// it is accepted, or an error to refuse it: ErrRefused refuses the type,
// anything else says the local end is unavailable.
type Accept func(ctx context.Context, typ uint8) (serve func(*Stream), err error)

// Config is a Mux's.
type Config struct {
	Role Role
	// Accept is asked about every stream the peer opens; nil refuses them
	// all.
	Accept Accept
	Log    *slog.Logger
}

var (
	// ErrRefused is an Accept's answer for a type it does not serve, and
	// what Open fails with when the peer refused.
	ErrRefused = errors.New("channel: refused")
	// ErrLimit is Open's error when MaxStreams are already live.
	ErrLimit = errors.New("channel: too many streams")
	// ErrClosed is what a stream fails with once its mux has stopped.
	ErrClosed = fmt.Errorf("channel: the connection is gone: %w", net.ErrClosed)
)

// ResetError is a stream's error once it was reset, by either side.
type ResetError struct {
	Reason Reason
	// Remote says the peer reset it.
	Remote bool
}

func (e *ResetError) Error() string {
	if e.Remote {
		return "channel: the peer reset the stream: " + e.Reason.String()
	}
	return "channel: stream reset: " + e.Reason.String()
}

// Mux is the streams of one connection.
type Mux struct {
	d   Datagrams
	cfg Config
	log *slog.Logger

	mu      sync.Mutex
	streams map[uint32]*Stream
	nextID  uint32
	live    int
	// lingering is the finished streams still answering, oldest first.
	lingering []*Stream
	stopped   bool
	ctx       context.Context

	// The retransmission timer (RFC 6298), one for the connection.
	srtt, rttvar time.Duration
	sampled      bool
	rto          time.Duration

	wake chan struct{}
	done chan struct{}
	// dropped counts frames that did not parse, and ignored those of an
	// op a later release defined that may be ignored, for tests and the
	// log.
	dropped, ignored int
}

// NewMux makes the streams' mux over d. Nothing moves until Run.
func NewMux(d Datagrams, cfg Config) *Mux {
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	m := &Mux{
		d: d, cfg: cfg, log: log,
		streams: map[uint32]*Stream{},
		rto:     InitialRTO,
		wake:    make(chan struct{}, 1),
		done:    make(chan struct{}),
		ctx:     context.Background(),
	}
	if cfg.Role == Server {
		m.nextID = 1
	} else {
		m.nextID = 2
	}
	return m
}

// Run reads frames and drives the timers until ctx is done or the
// connection under it fails. Every stream then fails with ErrClosed.
func (m *Mux) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	m.mu.Lock()
	m.ctx = ctx
	m.mu.Unlock()
	go m.timers(ctx)
	defer m.stop()
	for {
		body, err := m.d.RecvChannel(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		m.receive(body)
	}
}

// Done is closed once Run has returned.
func (m *Mux) Done() <-chan struct{} { return m.done }

// Live is how many streams are open or opening.
func (m *Mux) Live() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.live
}

func (m *Mux) stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopped {
		return
	}
	m.stopped = true
	for _, s := range m.streams {
		s.fail(ErrClosed)
	}
	clear(m.streams)
	m.lingering = nil
	m.live = 0
	close(m.done)
}

// Open opens a stream of type typ and waits until the peer accepts it,
// refuses it (an error wrapping ErrRefused or a *ResetError), OpenTimeout
// passes, or ctx is done.
func (m *Mux) Open(ctx context.Context, typ uint8) (*Stream, error) {
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return nil, ErrClosed
	}
	if m.live >= MaxStreams {
		m.mu.Unlock()
		return nil, ErrLimit
	}
	id := m.nextID
	m.nextID += 2
	now := time.Now()
	s := m.newStream(id, typ, stateOpening)
	s.openBy = now.Add(OpenTimeout)
	m.send(Frame{Stream: id, Op: OpOpen, Type: typ, Window: RecvBuffer})
	s.rtoAt = now.Add(m.rto)
	m.mu.Unlock()
	m.poke()

	select {
	case <-s.opened:
	case <-ctx.Done():
		s.Close()
		return nil, ctx.Err()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.err != nil {
		var re *ResetError
		if errors.As(s.err, &re) && re.Reason == ReasonRefused {
			return nil, fmt.Errorf("%w: %w", ErrRefused, s.err)
		}
		return nil, s.err
	}
	return s, nil
}

func (m *Mux) newStream(id uint32, typ uint8, st state) *Stream {
	s := &Stream{
		m: m, id: id, typ: typ, state: st,
		opened:   make(chan struct{}),
		readable: make(chan struct{}, 1),
		writable: make(chan struct{}, 1),
	}
	m.streams[id] = s
	m.live++
	return s
}

// send marshals and sends f. A send the connection holds back or fails
// is a loss, which the RTO repairs. The caller holds the lock.
func (m *Mux) send(f Frame) {
	if err := m.d.SendChannel(Marshal(f)); err != nil {
		m.log.Debug("channel frame not sent", "op", f.Op, "stream", f.Stream, "err", err)
	}
}

func (m *Mux) poke() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// peerOpens says whether id is one the peer may open.
func (m *Mux) peerOpens(id uint32) bool {
	if id == 0 {
		return false
	}
	odd := id%2 == 1
	return odd == (m.cfg.Role == Client)
}

// receive handles one body from the peer. A body that does not parse
// changes nothing, save that a stream it names is reset (agent.md §5.7).
func (m *Mux) receive(body []byte) {
	f, err := ParseFrame(body)
	m.mu.Lock()
	defer m.mu.Unlock()
	defer m.poke()
	if m.stopped {
		return
	}
	if errors.Is(err, ErrIgnored) {
		// A later release's op that may be ignored: dropped and counted,
		// and no stream is touched (agent.md §5.1).
		m.ignored++
		m.log.Debug("dropped a channel frame of an op this build does not know", "op", body[4])
		return
	}
	if err != nil {
		m.dropped++
		m.log.Debug("dropped a malformed channel frame", "bytes", len(body))
		if len(body) >= 4 {
			id := uint32(body[0]) | uint32(body[1])<<8 | uint32(body[2])<<16 | uint32(body[3])<<24
			if s := m.streams[id]; s != nil && s.state != stateDone {
				m.reset(s, ReasonProtocol)
			}
		}
		return
	}
	s := m.streams[f.Stream]
	if s == nil {
		switch f.Op {
		case OpOpen:
			m.onOpen(f)
		case OpReset:
			// Never answered: two sides that have both forgotten a
			// stream would otherwise bounce RESETs for ever.
		default:
			m.send(Frame{Stream: f.Stream, Op: OpReset, Reason: ReasonGone})
		}
		return
	}
	switch f.Op {
	case OpOpen:
		// A resend: answer again once accepted; while the owner decides,
		// or for a finished stream, nothing.
		if s.state == stateOpen && m.peerOpens(s.id) {
			m.send(Frame{Stream: s.id, Op: OpAccept, Window: s.window()})
		}
	case OpAccept:
		m.onAccept(s, f)
	case OpData:
		m.onData(s, f)
	case OpAck:
		m.onAck(s, f)
	case OpReset:
		if s.state == stateDone {
			m.forget(s)
			return
		}
		m.drop(s, &ResetError{Reason: f.Reason, Remote: true})
	}
}

func (m *Mux) onOpen(f Frame) {
	switch {
	case !m.peerOpens(f.Stream) || m.cfg.Accept == nil:
		m.send(Frame{Stream: f.Stream, Op: OpReset, Reason: ReasonRefused})
		return
	case m.live >= MaxStreams:
		m.send(Frame{Stream: f.Stream, Op: OpReset, Reason: ReasonLimit})
		return
	}
	s := m.newStream(f.Stream, f.Type, stateAccepting)
	s.peerLimit = uint64(f.Window)
	ctx := m.ctx
	go func() {
		serve, err := m.cfg.Accept(ctx, f.Type)
		m.mu.Lock()
		if s.state != stateAccepting {
			m.mu.Unlock()
			return // reset, or the mux stopped, while the owner decided
		}
		if err != nil {
			reason := ReasonUnavailable
			if errors.Is(err, ErrRefused) {
				reason = ReasonRefused
			}
			m.log.Info("refused a channel", "stream", s.id, "type", s.typ, "err", err)
			m.reset(s, reason)
			m.mu.Unlock()
			return
		}
		s.state = stateOpen
		close(s.opened)
		m.send(Frame{Stream: s.id, Op: OpAccept, Window: s.window()})
		s.advertised = s.window()
		m.flush(s, time.Now())
		m.mu.Unlock()
		m.poke()
		go serve(s)
	}()
}

func (m *Mux) onAccept(s *Stream, f Frame) {
	if s.state != stateOpening {
		return // a resent ACCEPT
	}
	s.state = stateOpen
	s.peerLimit = uint64(f.Window)
	s.advertised = RecvBuffer
	s.rtoAt = time.Time{}
	close(s.opened)
	m.flush(s, time.Now())
}

// onData is the receiving half of agent.md §5.4. It answers every DATA
// with an ACK, a duplicate or out-of-order one included.
func (m *Mux) onData(s *Stream, f Frame) {
	if s.state == stateDone {
		m.ack(s)
		return
	}
	if s.state == stateAccepting {
		// The peer opened this stream and is not yet accepted, so it has
		// sent no ACCEPT to justify data; it has no business sending any.
		m.reset(s, ReasonProtocol)
		return
	}
	end := f.Offset + uint64(len(f.Data))
	if s.rFin && (end > s.rFinAt || f.Fin && end != s.rFinAt) {
		m.reset(s, ReasonProtocol)
		return
	}
	if f.Fin {
		if s.rNext > end {
			m.reset(s, ReasonProtocol)
			return
		}
		s.rFin, s.rFinAt = true, end
	}
	if f.Offset <= s.rNext && s.rNext < end {
		take := f.Data[s.rNext-f.Offset:]
		take = take[:min(len(take), RecvBuffer-len(s.rbuf))]
		s.rbuf = append(s.rbuf, take...)
		s.rNext += uint64(len(take))
		s.signal(s.readable)
	} else if f.Fin && s.rNext == s.rFinAt {
		s.signal(s.readable)
	}
	m.ack(s)
}

// ack tells the peer what this side has received and will take.
func (m *Mux) ack(s *Stream) {
	w := s.window()
	m.send(Frame{Stream: s.id, Op: OpAck, Offset: s.rNext, Window: w, Fin: s.rFin && s.rNext == s.rFinAt})
	s.advertised = w
}

// onAck is the sending half's bookkeeping (agent.md §5.3, §5.5).
func (m *Mux) onAck(s *Stream, f Frame) {
	if s.state != stateOpen {
		if s.state == stateOpening {
			// An ACK before the ACCEPT is a peer that is ahead of us: its
			// ACCEPT was lost. Its window is as good as the ACCEPT's.
			m.onAccept(s, Frame{Window: 0})
		} else {
			return
		}
	}
	next := f.Offset
	if next > s.sMax || f.Fin && !(s.finSent && next == s.end()) {
		m.reset(s, ReasonProtocol)
		return
	}
	if next < s.sUna {
		return // older than what we know: reordered
	}
	now := time.Now()
	if next > s.sUna {
		if s.timing && next >= s.timeEnd {
			m.sample(now.Sub(s.timeAt))
			s.timing = false
		}
		s.sbuf = s.sbuf[next-s.sUna:]
		s.sUna = next
		s.sNxt = max(s.sNxt, next)
		m.backoffReset()
		s.signal(s.writable)
	}
	s.peerLimit = next + uint64(f.Window)
	if f.Fin {
		s.finAcked = true
	}
	if s.outstanding() {
		s.rtoAt = now.Add(m.rto)
	} else {
		s.rtoAt = time.Time{}
	}
	m.flushAll(now)
	m.maybeDone(s, now)
}

// flushAll lets every open stream send what the windows now allow.
func (m *Mux) flushAll(now time.Time) {
	for _, s := range m.streams {
		if s.state == stateOpen {
			m.flush(s, now)
		}
	}
}

// inFlight is the bytes sent and not acknowledged, across the streams.
func (m *Mux) inFlight() uint64 {
	var n uint64
	for _, s := range m.streams {
		n += s.sNxt - s.sUna
	}
	return n
}

// flush sends what s may send now (agent.md §5.3): data within the peer's
// window and the connection's in-flight cap, and the FIN.
func (m *Mux) flush(s *Stream, now time.Time) {
	if s.state != stateOpen {
		return
	}
	for {
		end := s.end()
		if s.sNxt < end {
			lim := min(end, s.peerLimit, s.sNxt+MaxData)
			if lim <= s.sNxt {
				return // the peer's window is shut: the timer probes it
			}
			room := uint64(MaxInFlight) - min(m.inFlight(), MaxInFlight)
			n := min(lim-s.sNxt, room)
			if n == 0 {
				return // another stream's ACK will make room
			}
			fin := s.finQueued && s.sNxt+n == end
			data := s.sbuf[s.sNxt-s.sUna : s.sNxt-s.sUna+n]
			m.send(Frame{Stream: s.id, Op: OpData, Offset: s.sNxt, Data: data, Fin: fin})
			if !s.timing && s.sNxt >= s.sMax {
				// Karn: time only bytes sent for the first time.
				s.timing, s.timeEnd, s.timeAt = true, s.sNxt+n, now
			}
			s.sNxt += n
			s.sMax = max(s.sMax, s.sNxt)
			if fin {
				s.finSent = true
			}
			if s.rtoAt.IsZero() {
				s.rtoAt = now.Add(m.rto)
			}
			continue
		}
		if s.finQueued && !s.finSent {
			m.send(Frame{Stream: s.id, Op: OpData, Offset: end, Fin: true})
			s.finSent = true
			if s.rtoAt.IsZero() {
				s.rtoAt = now.Add(m.rto)
			}
		}
		return
	}
}

// sample takes a round-trip time measurement into the RTO (RFC 6298 §2).
func (m *Mux) sample(r time.Duration) {
	if !m.sampled {
		m.srtt, m.rttvar, m.sampled = r, r/2, true
	} else {
		d := m.srtt - r
		if d < 0 {
			d = -d
		}
		m.rttvar = (3*m.rttvar + d) / 4
		m.srtt = (7*m.srtt + r) / 8
	}
	m.backoffReset()
}

// backoffReset recomputes the RTO from the estimates, ending any
// doubling (RFC 6298 §5.7).
func (m *Mux) backoffReset() {
	if !m.sampled {
		m.rto = InitialRTO
		return
	}
	m.rto = min(max(m.srtt+4*m.rttvar, MinRTO), MaxRTO)
}

// timers resends on the RTO, expires OPENs, probes shut windows and
// forgets lingering streams, until ctx is done.
func (m *Mux) timers(ctx context.Context) {
	t := time.NewTimer(time.Hour)
	defer t.Stop()
	for {
		m.mu.Lock()
		if m.stopped {
			m.mu.Unlock()
			return
		}
		now := time.Now()
		m.tick(now)
		next := m.nextDeadline()
		m.mu.Unlock()
		if next.IsZero() {
			t.Stop()
		} else {
			t.Reset(max(next.Sub(now), 0))
		}
		select {
		case <-t.C:
		case <-m.wake:
		case <-ctx.Done():
			return
		}
	}
}

func (m *Mux) tick(now time.Time) {
	for len(m.lingering) > 0 && !now.Before(m.lingering[0].lingerUntil) {
		m.forget(m.lingering[0])
	}
	for _, s := range m.streams {
		switch s.state {
		case stateOpening:
			if !now.Before(s.openBy) {
				m.log.Info("a channel open went unanswered", "stream", s.id)
				m.drop(s, fmt.Errorf("channel: no answer to the open in %v", OpenTimeout))
				continue
			}
			if !now.Before(s.rtoAt) {
				m.send(Frame{Stream: s.id, Op: OpOpen, Type: s.typ, Window: RecvBuffer})
				m.backoff()
				s.rtoAt = now.Add(m.rto)
			}
		case stateOpen:
			if s.rtoAt.IsZero() || now.Before(s.rtoAt) {
				continue
			}
			if s.outstanding() {
				// Go back to the oldest unacknowledged byte (agent.md §5.5).
				s.sNxt, s.finSent, s.timing = s.sUna, false, false
				m.backoff()
				s.rtoAt = time.Time{}
				m.flush(s, now)
				if s.rtoAt.IsZero() && s.outstanding() {
					s.rtoAt = now.Add(m.rto)
				}
			}
			if s.sNxt < s.end() && s.peerLimit <= s.sNxt {
				// A shut window: a zero-length DATA asks for an ACK.
				m.send(Frame{Stream: s.id, Op: OpData, Offset: s.sNxt})
				m.backoff()
				s.rtoAt = now.Add(m.rto)
			} else if !s.outstanding() {
				s.rtoAt = time.Time{}
			}
		}
	}
}

func (m *Mux) backoff() { m.rto = min(2*m.rto, MaxRTO) }

func (m *Mux) nextDeadline() time.Time {
	var next time.Time
	consider := func(t time.Time) {
		if !t.IsZero() && (next.IsZero() || t.Before(next)) {
			next = t
		}
	}
	if len(m.lingering) > 0 {
		consider(m.lingering[0].lingerUntil)
	}
	for _, s := range m.streams {
		switch s.state {
		case stateOpening:
			consider(s.rtoAt)
			consider(s.openBy)
		case stateOpen:
			if s.sNxt < s.end() && s.peerLimit <= s.sNxt && s.rtoAt.IsZero() {
				s.rtoAt = time.Now().Add(m.rto)
			}
			consider(s.rtoAt)
		}
	}
	return next
}

// maybeDone finishes s once both directions have ended (agent.md §5.6):
// this side's FIN acknowledged, and the peer's received and read.
func (m *Mux) maybeDone(s *Stream, now time.Time) {
	if s.state != stateOpen || !s.finAcked || !s.eofRead {
		return
	}
	s.state = stateDone
	s.lingerUntil = now.Add(Linger)
	s.rtoAt = time.Time{}
	m.live--
	m.lingering = append(m.lingering, s)
	if len(m.lingering) > MaxLinger {
		m.forget(m.lingering[0])
	}
	s.wakeAll()
}

// forget removes a finished stream for good.
func (m *Mux) forget(s *Stream) {
	if m.streams[s.id] == s {
		delete(m.streams, s.id)
	}
	for i, l := range m.lingering {
		if l == s {
			m.lingering = append(m.lingering[:i], m.lingering[i+1:]...)
			break
		}
	}
}

// reset sends RESET for s and drops it.
func (m *Mux) reset(s *Stream, why Reason) {
	m.send(Frame{Stream: s.id, Op: OpReset, Reason: why})
	m.drop(s, &ResetError{Reason: why})
}

// drop ends s with err and forgets it.
func (m *Mux) drop(s *Stream, err error) {
	if s.state != stateDone {
		m.live--
	}
	s.fail(err)
	m.forget(s)
}
