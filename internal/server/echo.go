package server

import (
	"time"

	"github.com/danielbodart/mosey/internal/screen"
)

// Prediction's half on the server (D12, prediction.md §3.1).
const (
	// EchoAckDelay is how long the program must have had an input event
	// before the echo ack covers it: its echo, if it makes one, should be
	// on the screen by then. The wait is on the server so that network
	// jitter never enters the client's judgement [paper §3.2].
	EchoAckDelay = 50 * time.Millisecond
	// echoLogCap bounds the write log under a paste. When it is full the
	// newest entry is moved to the newest write instead, which can only
	// make the echo ack later, never early [prediction.md §3.1].
	echoLogCap = 64
)

// echoWrite is the writer's count of events the pty has taken, and when
// it reached it.
type echoWrite struct {
	n  uint64
	at time.Time
}

// echoTracker keeps one client's echo ack (prediction.md §3.1 rules 1, 2
// and 4). It is per connection, like the count it follows (ssp.md §1.3).
// The zero value is a client that has typed nothing.
type echoTracker struct {
	// log is ascending; once pruned, at most its first entry is
	// EchoAckDelay old.
	log []echoWrite
	// settled is the count of the newest entry ever found EchoAckDelay
	// old: the echo ack while echo is on.
	settled uint64
	// ack is what was last published as EchoAck. It stands still while
	// echo is off (rule 4).
	ack uint64
	// applied is the writer's count now: EchoApplied.
	applied uint64
}

// wrote notes that the pty has now taken n events.
func (t *echoTracker) wrote(n uint64, now time.Time) {
	t.applied = n
	t.prune(now)
	if len(t.log) == echoLogCap {
		t.log[len(t.log)-1] = echoWrite{n, now}
		return
	}
	t.log = append(t.log, echoWrite{n, now})
}

// prune drops every entry but the newest that is EchoAckDelay old,
// raising settled to it.
func (t *echoTracker) prune(now time.Time) {
	old := 0
	for old < len(t.log) && now.Sub(t.log[old].at) >= EchoAckDelay {
		old++
	}
	if old == 0 {
		return
	}
	t.settled = max(t.settled, t.log[old-1].n)
	t.log = append(t.log[:0], t.log[old-1:]...)
}

// fields sets g's EchoAck and EchoApplied for a publish at now, with g's
// EchoOff already read. last is the grid published before, or nil: rule 5
// keeps EchoApplied as it was when nothing else in g differs from last,
// so the count never causes a frame of its own.
func (t *echoTracker) fields(g, last *screen.Grid, now time.Time) {
	t.prune(now)
	if !g.EchoOff {
		t.ack = t.settled
	}
	g.EchoAck = t.ack
	g.EchoApplied = t.applied
	if last != nil && t.applied != last.EchoApplied {
		g.EchoApplied = last.EchoApplied
		if !g.Equal(last) {
			g.EchoApplied = t.applied
		}
	}
}

// due is how long until the next write becomes EchoAckDelay old, and
// whether one is waiting at all: when the echo-ack publish (rule 3) is
// next owed.
func (t *echoTracker) due(now time.Time) (time.Duration, bool) {
	t.prune(now)
	for _, w := range t.log {
		if w.n > t.settled {
			return w.at.Add(EchoAckDelay).Sub(now), true
		}
	}
	return 0, false
}
