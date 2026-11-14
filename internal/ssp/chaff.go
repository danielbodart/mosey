package ssp

import (
	"math/rand/v2"
	"time"
)

// Chaffer is what Datagrams implements when it can send cover traffic
// (docs/spec/ssp.md §9.1.4). An Endpoint over one chaffs while the user
// types, as D11 requires; over Datagrams that are not, it sends exactly
// what §6 says and nothing more. transport.Conn is one.
type Chaffer interface {
	// SendChaff sends one CHAFF frame whose sealed plaintext, frame kind
	// included, is size bytes. An error is a loss, as for Send.
	SendChaff(size int) error
	// ChaffArrived is signalled, without blocking, when a CHAFF frame from
	// the peer authenticates. One signal may stand for several.
	ChaffArrived() <-chan struct{}
}

// The chaff schedule (§9.1). Each value cites where it comes from.
const (
	// chaffTick is T, the interval of the tick grid both ends send on
	// while chaffing (§9.1.5, O10).
	chaffTick = 20 * time.Millisecond

	// clientLingerMin and clientLingerSpread are how long the client goes
	// on chaffing after an input: uniformly from 1 to 2 s, drawn afresh
	// each time, so the end of the chaff does not mark the last key, and
	// at least 1 s, more than all but one gap in 2000 between keys in S5's
	// typist model (§9.1.1) [D].
	clientLingerMin    = time.Second
	clientLingerSpread = time.Second

	// serverLinger is how long the server goes on chaffing after the last
	// CHAFF frame from the client: more than any profile's jitter but the
	// train's spikes, so a late or lost chaff frame does not end its mode
	// in the middle of a run of typing (§9.1.2) [D].
	serverLinger = time.Second
)

// chaffing is an endpoint's §9.1 state.
type chaffing struct {
	// c is nil when the Datagrams cannot chaff; nothing below is used then.
	c Chaffer
	// tick is chaffTick; tests that measure other ticks set it (§9.1.5).
	tick time.Duration
	// until is when the mode ends: the endpoint chaffs while now is
	// before it.
	until time.Time
	// next is the next instant on the tick grid.
	next time.Time
}

// active says whether the endpoint is chaffing at now.
func (c *chaffing) active(now time.Time) bool {
	return c.c != nil && now.Before(c.until)
}

// extend keeps the endpoint chaffing until at least now+linger, starting
// the tick grid at now if it was not chaffing, so whatever started the
// mode goes at once, as the first key after idle does without chaff
// (§9.1.1).
func (c *chaffing) extend(now time.Time, linger time.Duration) {
	if c.c == nil {
		return
	}
	if !c.active(now) {
		c.next = now
	}
	if until := now.Add(linger); until.After(c.until) {
		c.until = until
	}
}

// due says whether a tick has come.
func (c *chaffing) due(now time.Time) bool {
	return !now.Before(c.next)
}

// advance moves next to the first grid point after now. Ticks missed by a
// late wake-up are skipped, not made up in a burst (§9.1.1).
func (c *chaffing) advance(now time.Time) {
	if c.next.After(now) {
		return
	}
	missed := now.Sub(c.next) / c.tick
	c.next = c.next.Add((missed + 1) * c.tick)
}

// clientLinger is a fresh draw of the client's linger. It need not be
// unpredictable to the peer, only to an observer of the wire, and nothing
// else is drawn from the same source.
func clientLinger() time.Duration {
	return clientLingerMin + rand.N(clientLingerSpread)
}
