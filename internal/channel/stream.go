package channel

import (
	"errors"
	"io"
	"time"
)

type state uint8

const (
	// stateOpening: this side sent OPEN and waits for the answer.
	stateOpening state = iota
	// stateAccepting: the peer sent OPEN and the owner is deciding.
	stateAccepting
	stateOpen
	// stateDone: both directions ended; the stream lingers (agent.md §5.6).
	stateDone
	// stateFailed: reset by either side, or its mux stopped.
	stateFailed
)

// Stream is one reliable byte stream (agent.md §5). Read and Write may be
// called from different goroutines, each from one at a time; Close and
// CloseWrite from any.
type Stream struct {
	m     *Mux
	id    uint32
	typ   uint8
	state state
	err   error

	opened   chan struct{}
	readable chan struct{}
	writable chan struct{}

	// The sending half: sbuf holds the bytes from sUna, the oldest not
	// acknowledged, to the end of what was written. sNxt is the next to
	// send (it goes back to sUna on a timeout), sMax the highest ever sent.
	sbuf             []byte
	sUna, sNxt, sMax uint64
	peerLimit        uint64
	finQueued        bool
	finSent          bool
	finAcked         bool
	rtoAt            time.Time
	openBy           time.Time
	// One RTT measurement at a time, on bytes sent once (Karn).
	timing  bool
	timeEnd uint64
	timeAt  time.Time

	// The receiving half: rbuf holds bytes received and not yet read,
	// rNext the next expected, and rFinAt the end once the FIN is in.
	rbuf       []byte
	rNext      uint64
	rFin       bool
	rFinAt     uint64
	eofRead    bool
	advertised uint32

	lingerUntil time.Time
}

// ID is the stream's id; Type the channel type it was opened with.
func (s *Stream) ID() uint32  { return s.id }
func (s *Stream) Type() uint8 { return s.typ }

func (s *Stream) end() uint64 { return s.sUna + uint64(len(s.sbuf)) }

// outstanding says whether anything sent is waiting for an ACK.
func (s *Stream) outstanding() bool {
	return s.sNxt > s.sUna || s.finSent && !s.finAcked
}

func (s *Stream) window() uint32 { return uint32(RecvBuffer - len(s.rbuf)) }

func (s *Stream) signal(c chan struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}

func (s *Stream) wakeAll() {
	s.signal(s.readable)
	s.signal(s.writable)
}

// fail ends the stream with err and wakes everything waiting on it. The
// caller holds the mux's lock.
func (s *Stream) fail(err error) {
	if s.state == stateFailed {
		return
	}
	wasOpening := s.state == stateOpening || s.state == stateAccepting
	s.state, s.err = stateFailed, err
	s.sbuf = nil
	if wasOpening {
		close(s.opened)
	}
	s.wakeAll()
}

// Read reads what the peer sent. It returns io.EOF once the peer's FIN
// has been read, and the stream's error once it was reset or its mux
// stopped.
func (s *Stream) Read(p []byte) (int, error) {
	m := s.m
	for {
		m.mu.Lock()
		if len(s.rbuf) > 0 {
			n := copy(p, s.rbuf)
			s.rbuf = s.rbuf[n:]
			if len(s.rbuf) == 0 {
				s.rbuf = nil
			}
			// A window update once a good part of the buffer is free, or
			// a shut window opens (agent.md §5.4).
			w := s.window()
			if s.state == stateOpen && (w >= s.advertised+RecvBuffer/2 || s.advertised < MaxData && w >= MaxData) {
				m.ack(s)
			}
			m.mu.Unlock()
			m.poke()
			return n, nil
		}
		switch {
		case s.state == stateFailed:
			err := s.err
			m.mu.Unlock()
			return 0, err
		case s.rFin && s.rNext == s.rFinAt:
			if !s.eofRead {
				s.eofRead = true
				m.maybeDone(s, time.Now())
			}
			m.mu.Unlock()
			m.poke()
			return 0, io.EOF
		case s.state == stateDone:
			m.mu.Unlock()
			return 0, io.EOF
		}
		m.mu.Unlock()
		<-s.readable
	}
}

// ErrWriteClosed is Write's error after CloseWrite.
var ErrWriteClosed = errors.New("channel: write after CloseWrite")

// Write queues p to send, waiting while the stream's SendBuffer is full:
// the back-pressure into whatever feeds it.
func (s *Stream) Write(p []byte) (int, error) {
	m := s.m
	written := 0
	for written < len(p) {
		m.mu.Lock()
		switch {
		case s.state == stateFailed:
			err := s.err
			m.mu.Unlock()
			return written, err
		case s.finQueued || s.state == stateDone:
			m.mu.Unlock()
			return written, ErrWriteClosed
		}
		room := SendBuffer - len(s.sbuf)
		if room == 0 {
			m.mu.Unlock()
			<-s.writable
			continue
		}
		n := min(room, len(p)-written)
		s.sbuf = append(s.sbuf, p[written:written+n]...)
		written += n
		m.flush(s, time.Now())
		m.mu.Unlock()
		m.poke()
	}
	return written, nil
}

// CloseWrite ends this side's direction: the peer reads EOF after what was
// written.
func (s *Stream) CloseWrite() error {
	m := s.m
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.state == stateFailed {
		return s.err
	}
	if !s.finQueued {
		s.finQueued = true
		m.flush(s, time.Now())
		m.poke()
	}
	return nil
}

// Close ends the stream. After CloseWrite and a read to EOF it lets the
// stream finish by itself (its FIN may still need resending); otherwise it
// resets it (agent.md §5.6).
func (s *Stream) Close() error {
	m := s.m
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case s.state == stateFailed || s.state == stateDone:
		return nil
	case s.finQueued && s.eofRead:
		return nil
	}
	if !m.stopped {
		m.reset(s, ReasonAborted)
		m.poke()
	}
	return nil
}
