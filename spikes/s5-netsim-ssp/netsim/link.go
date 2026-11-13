package netsim

import (
	"math"
	"math/rand/v2"
	"time"
)

// Window is a half-open interval of simulated time, measured from the
// network's epoch (the time the profile is applied).
type Window struct {
	Start, End time.Duration
}

// GilbertElliott is a continuous-time two-state burst-loss model. The chain
// alternates between Good and Bad periods whose lengths are exponentially
// distributed with the given means; a packet sent while in a state is lost
// with that state's probability. Continuous time (rather than the textbook
// per-packet chain) is used because SSP's sending rate changes with
// conditions: a radio fade lasts a length of time, not a number of packets.
type GilbertElliott struct {
	MeanGood, MeanBad time.Duration
	LossGood, LossBad float64
}

// LinkParams describes one direction of a path.
type LinkParams struct {
	// Delay is the fixed one-way propagation delay.
	Delay time.Duration
	// Jitter is the mean of an exponentially distributed extra delay.
	Jitter time.Duration
	// JitterCap bounds a single jitter sample (0 = 10*Jitter).
	JitterCap time.Duration
	// Reorder allows a packet with a smaller jitter sample to overtake an
	// earlier one. When false the link is FIFO (delivery times are clamped
	// to be non-decreasing), as most real bottlenecks are.
	Reorder bool
	// MTU is the largest UDP payload delivered; larger datagrams are
	// silently dropped, as a black-holing path would. 0 = unlimited.
	MTU int
	// Loss is an i.i.d. loss probability applied on top of everything else.
	Loss float64
	// GE, if non-nil, adds burst loss.
	GE *GilbertElliott
	// Outages drop every packet sent during each window.
	Outages []Window
	// Trace, if non-nil, is a Mahimahi-style capacity trace: the packet
	// waits in a FIFO drop-tail queue for delivery opportunities.
	Trace *Trace
	// QueueBytes is the drop-tail limit for the trace queue (0 = unlimited).
	QueueBytes int
	// Spikes, if non-nil, adds occasional large delay spikes (bufferbloat
	// from a competing flow, wifi retries): with probability P a packet gets
	// an extra uniformly distributed delay in [Min, Max].
	Spikes *DelaySpikes
}

// DelaySpikes models occasional large extra delay.
type DelaySpikes struct {
	P        float64
	Min, Max time.Duration
}

// LinkStats counts what a link did.
type LinkStats struct {
	Sent, Delivered                                       int
	DroppedMTU, DroppedLoss, DroppedOutage, DroppedQueue int
	DroppedNoRoute                                        int
	Bytes                                                 int
}

// Link is one direction of a path.
type Link struct {
	id    uint64
	name  string
	seed  uint64
	p     LinkParams
	epoch time.Time
	seq   uint64

	lastDelivery time.Time

	// GE state, a function of time drawn from its own stream.
	geRng   *rand.Rand
	geBad   bool
	geUntil time.Time

	// trace queue
	tq traceQueue

	Stats LinkStats
}

func newLink(id uint64, name string, seed uint64, p LinkParams) *Link {
	l := &Link{id: id, name: name, seed: seed, p: p, epoch: time.Now()}
	l.geRng = rand.New(rand.NewPCG(seed, id<<32|0x6745))
	if p.Trace != nil {
		l.tq = traceQueue{tr: p.Trace, epoch: l.epoch, limit: p.QueueBytes}
	}
	return l
}

// Name returns the link's name ("a->b").
func (l *Link) Name() string { return l.name }

// SetParams replaces the parameters from now on (scripted changes).
func (l *Link) SetParams(p LinkParams) { l.p = p }

func expDur(r *rand.Rand, mean time.Duration) time.Duration {
	if mean <= 0 {
		return 0
	}
	return time.Duration(r.ExpFloat64() * float64(mean))
}

func (l *Link) geState(t time.Time) bool {
	ge := l.p.GE
	if ge == nil {
		return false
	}
	if l.geUntil.IsZero() {
		// Start in the stationary distribution.
		pBad := float64(ge.MeanBad) / float64(ge.MeanGood+ge.MeanBad)
		l.geBad = l.geRng.Float64() < pBad
		if l.geBad {
			l.geUntil = l.epoch.Add(expDur(l.geRng, ge.MeanBad))
		} else {
			l.geUntil = l.epoch.Add(expDur(l.geRng, ge.MeanGood))
		}
	}
	for !t.Before(l.geUntil) {
		l.geBad = !l.geBad
		if l.geBad {
			l.geUntil = l.geUntil.Add(expDur(l.geRng, ge.MeanBad))
		} else {
			l.geUntil = l.geUntil.Add(expDur(l.geRng, ge.MeanGood))
		}
	}
	return l.geBad
}

// admit decides the fate of a packet of size bytes sent at now. It returns
// the link sequence number, the delivery time and a verdict.
func (l *Link) admit(now time.Time, size int) (uint64, time.Time, string) {
	l.seq++
	seq := l.seq
	l.Stats.Sent++
	l.Stats.Bytes += size
	r := rand.New(rand.NewPCG(l.seed^0x9e3779b97f4a7c15, l.id<<40^seq))
	// Draw a fixed number of variates in a fixed order so that changing one
	// parameter does not reshuffle the others.
	uLoss, uGE, uJit, uSpike, uSpikeAmt := r.Float64(), r.Float64(), r.ExpFloat64(), r.Float64(), r.Float64()

	if l.p.MTU > 0 && size > l.p.MTU {
		l.Stats.DroppedMTU++
		return seq, time.Time{}, "drop-mtu"
	}
	off := now.Sub(l.epoch)
	for _, w := range l.p.Outages {
		if off >= w.Start && off < w.End {
			l.Stats.DroppedOutage++
			return seq, time.Time{}, "drop-outage"
		}
	}
	if l.p.GE != nil {
		pl := l.p.GE.LossGood
		if l.geState(now) {
			pl = l.p.GE.LossBad
		}
		if uGE < pl {
			l.Stats.DroppedLoss++
			return seq, time.Time{}, "drop-loss"
		}
	}
	if uLoss < l.p.Loss {
		l.Stats.DroppedLoss++
		return seq, time.Time{}, "drop-loss"
	}
	depart := now
	if l.p.Trace != nil {
		d, ok := l.tq.enqueue(now, size)
		if !ok {
			l.Stats.DroppedQueue++
			return seq, time.Time{}, "drop-queue"
		}
		depart = d
	}
	jit := time.Duration(uJit * float64(l.p.Jitter))
	cap := l.p.JitterCap
	if cap == 0 {
		cap = 10 * l.p.Jitter
	}
	if jit > cap {
		jit = cap
	}
	at := depart.Add(l.p.Delay + jit)
	if s := l.p.Spikes; s != nil && uSpike < s.P {
		at = at.Add(s.Min + time.Duration(uSpikeAmt*float64(s.Max-s.Min)))
	}
	if !l.p.Reorder && at.Before(l.lastDelivery) {
		at = l.lastDelivery
	}
	if at.After(l.lastDelivery) {
		l.lastDelivery = at
	}
	return seq, at, "deliver"
}

// ---- Mahimahi-style trace queue ----

// traceQueue serves a FIFO queue from a trace of delivery opportunities.
// Each opportunity can carry OppBytes bytes (1500 in Mahimahi); bytes left
// over in an opportunity may be used by the next queued packet in the same
// millisecond. Because arrivals on a link are in time order and the queue is
// FIFO, a packet's departure time is fixed at arrival.
type traceQueue struct {
	tr    *Trace
	epoch time.Time
	limit int

	// position of the next unused capacity
	opp      int64 // absolute opportunity index (may exceed len, wraps)
	oppLeft  int   // bytes left in opportunity opp
	started  bool
	inflight []queued
}

type queued struct {
	depart time.Time
	size   int
}

func (q *traceQueue) oppTime(i int64) time.Time {
	n := int64(len(q.tr.Opps))
	cycle := i / n
	ms := int64(q.tr.Opps[i%n]) + cycle*int64(q.tr.Period)
	return q.epoch.Add(time.Duration(ms) * time.Millisecond)
}

func (q *traceQueue) enqueue(now time.Time, size int) (time.Time, bool) {
	// Drop-tail check: bytes still queued at arrival.
	k := 0
	queuedBytes := 0
	for _, e := range q.inflight {
		if e.depart.After(now) {
			q.inflight[k] = e
			k++
			queuedBytes += e.size
		}
	}
	q.inflight = q.inflight[:k]
	if q.limit > 0 && queuedBytes+size > q.limit {
		return time.Time{}, false
	}
	// Opportunities in the past (unused while the queue was empty) are
	// wasted: skip to the first opportunity at or after now.
	next := q.opp
	if q.oppLeft == 0 && q.started {
		next++
	}
	q.started = true
	if q.oppTime(next).Before(now) {
		q.opp = q.firstOppAtOrAfter(now, next)
		q.oppLeft = q.tr.OppBytes
	} else if q.oppLeft == 0 {
		q.opp = next
		q.oppLeft = q.tr.OppBytes
	}
	need := size
	var depart time.Time
	for need > 0 {
		if q.oppLeft == 0 {
			q.opp++
			q.oppLeft = q.tr.OppBytes
		}
		take := min(need, q.oppLeft)
		need -= take
		q.oppLeft -= take
		depart = q.oppTime(q.opp)
	}
	q.inflight = append(q.inflight, queued{depart: depart, size: size})
	return depart, true
}

func (q *traceQueue) firstOppAtOrAfter(t time.Time, from int64) int64 {
	ms := t.Sub(q.epoch).Milliseconds()
	if t.Sub(q.epoch)%time.Millisecond != 0 {
		ms++
	}
	n := int64(len(q.tr.Opps))
	period := int64(q.tr.Period)
	cycle := ms / period
	within := ms % period
	// binary search within the cycle
	lo, hi := 0, len(q.tr.Opps)
	for lo < hi {
		m := (lo + hi) / 2
		if int64(q.tr.Opps[m]) < within {
			lo = m + 1
		} else {
			hi = m
		}
	}
	idx := cycle*n + int64(lo)
	if idx < from {
		idx = from
	}
	return idx
}

var _ = math.Inf
