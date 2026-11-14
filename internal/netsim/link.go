package netsim

import (
	"math/rand/v2"
	"slices"
	"time"
)

// LinkParams is how a one-way link treats packets. The zero value is a
// perfect link: no delay, no loss, no limit.
//
// A packet meets them in this order: the MTU, an outage, burst loss,
// independent loss, the trace's queue, then delay, jitter and spikes. Each
// packet's random draws are made the same way whichever parameters are set,
// so changing one parameter does not reshuffle the others' choices.
type LinkParams struct {
	// Delay is the fixed one-way propagation delay.
	Delay time.Duration
	// Jitter is the mean of an exponential extra delay, capped at
	// JitterCap, which defaults to ten times Jitter.
	Jitter, JitterCap time.Duration
	// Reorder lets a packet overtake an earlier one when jitter says it
	// arrives first. Without it the link is FIFO, as most real paths are:
	// a packet that would overtake waits for the one ahead of it.
	Reorder bool
	// MTU drops, silently, any packet bigger than this. 0 is no limit.
	MTU int
	// Loss is the probability of an independent loss.
	Loss float64
	// GE, if set, adds Gilbert-Elliott burst loss.
	GE *GilbertElliott
	// Outages are windows of total loss: a packet written during one is
	// lost. They may overlap and need not be sorted.
	Outages []Window
	// Spikes, if set, delays a fraction of packets by much more than the
	// jitter, as bufferbloat and wifi retries do.
	Spikes *DelaySpikes
	// Trace, if set, replaces Delay's unlimited capacity with a Mahimahi
	// trace's delivery opportunities, behind a drop-tail queue of
	// QueueBytes (0 is unlimited). Delay is then the propagation delay
	// after the bottleneck.
	Trace      *Trace
	QueueBytes int
}

// GilbertElliott is two-state burst loss in continuous time: fades last a
// time rather than a number of packets, because SSP's send rate changes
// with conditions and a fade must not shorten when it sends less. The time
// in each state is exponential with the given mean, and a packet written
// in a state is lost with that state's probability.
type GilbertElliott struct {
	GoodLoss, BadLoss float64
	// MeanGood and MeanBad are the mean times spent in each state.
	MeanGood, MeanBad time.Duration
}

// Window is a span of simulated time, measured from the network's start:
// from Start, up to but not including End.
type Window struct {
	Start, End time.Duration
}

// DelaySpikes delays a fraction P of packets by a uniform extra delay in
// [Min, Max].
type DelaySpikes struct {
	P        float64
	Min, Max time.Duration
}

// Link is one direction of a path between two hosts.
type Link struct {
	net  *Network
	id   uint64
	name string

	// Guarded by net.mu.
	p       LinkParams
	outages []Window // p.Outages sorted and merged
	seq     uint64
	last    time.Time // the latest delivery so far, which FIFO waits for
	ge      geChain
	queue   *traceQueue
	stats   LinkStats
}

// Name is the link's name, "from->to".
func (l *Link) Name() string { return l.name }

// SetParams changes how the link behaves from now on, for a scripted change
// of conditions. Packets already in flight keep the fate they were given.
// A link that was FIFO stays FIFO across the change: nothing written after
// it overtakes what was written before.
func (l *Link) SetParams(p LinkParams) {
	l.net.mu.Lock()
	defer l.net.mu.Unlock()
	l.setParams(time.Now(), p)
}

// setParams installs p at time now. Burst loss and a trace whose model has
// changed start afresh from now; ones that have not carry on, so a test can
// change the delay without disturbing a fade in progress.
func (l *Link) setParams(now time.Time, p LinkParams) {
	old := l.p
	l.p = p
	l.outages = mergeWindows(p.Outages)
	if p.GE == nil {
		l.ge = geChain{}
	} else if old.GE == nil || *old.GE != *p.GE || l.ge.until.IsZero() {
		l.ge = newGEChain(*p.GE, now, rand.New(rand.NewPCG(mix(l.net.seed, l.id), 0x6745_0000|l.seq)))
	}
	switch {
	case p.Trace == nil:
		l.queue = nil
	case l.queue == nil || l.queue.trace != p.Trace:
		l.queue = newTraceQueue(p.Trace, l.net.start, p.QueueBytes)
	default:
		l.queue.limit = p.QueueBytes
	}
}

// LinkStats counts what a link did with what it was given.
//
// Once nothing is in flight and no Tap is set, Sent is Delivered plus every
// Dropped count. A Tap that overturns a verdict (Tampered) breaks the sum
// by one either way: a packet it resurrects is counted both dropped and
// delivered, and one it drops is counted neither.
type LinkStats struct {
	Sent, Delivered                                      int
	DroppedMTU, DroppedLoss, DroppedOutage, DroppedQueue int
	DroppedNoRoute                                       int
	DroppedReadBuffer                                    int // arrived at a full socket
	Tampered                                             int // fate changed by the Tap
	Bytes                                                int
}

// admit decides the fate of a packet of size bytes written at now: its
// sequence on the link, when it arrives and the verdict. Called with the
// lock held.
func (l *Link) admit(now time.Time, size int) (seq uint64, delivery time.Time, v Verdict) {
	l.seq++
	seq = l.seq
	l.stats.Sent++
	l.stats.Bytes += size

	// Every packet draws the same five numbers in the same order from its
	// own stream, so its fate depends only on the seed, the link, its
	// sequence and the parameters, never on what other packets did.
	r := rand.New(rand.NewPCG(mix(l.net.seed, l.id), seq))
	uLoss, uGE, eJitter, uSpike, uSpikeLen := r.Float64(), r.Float64(), r.ExpFloat64(), r.Float64(), r.Float64()

	p := &l.p
	if p.MTU > 0 && size > p.MTU {
		l.stats.DroppedMTU++
		return seq, time.Time{}, DroppedMTU
	}
	if inWindows(l.outages, now.Sub(l.net.start)) {
		l.stats.DroppedOutage++
		return seq, time.Time{}, DroppedOutage
	}
	if p.GE != nil {
		loss := p.GE.GoodLoss
		if l.ge.bad(now) {
			loss = p.GE.BadLoss
		}
		if uGE < loss {
			l.stats.DroppedLoss++
			return seq, time.Time{}, DroppedLoss
		}
	}
	if uLoss < p.Loss {
		l.stats.DroppedLoss++
		return seq, time.Time{}, DroppedLoss
	}
	depart := now
	if l.queue != nil {
		var ok bool
		if depart, ok = l.queue.enqueue(now, size); !ok {
			l.stats.DroppedQueue++
			return seq, time.Time{}, DroppedQueue
		}
	}
	jitterCap := p.JitterCap
	if jitterCap == 0 {
		jitterCap = 10 * p.Jitter
	}
	jitter := min(time.Duration(eJitter*float64(p.Jitter)), jitterCap)
	delivery = depart.Add(p.Delay + jitter)
	if s := p.Spikes; s != nil && uSpike < s.P {
		delivery = delivery.Add(s.Min + time.Duration(uSpikeLen*float64(s.Max-s.Min)))
	}
	if !p.Reorder && delivery.Before(l.last) {
		delivery = l.last
	}
	if delivery.After(l.last) {
		l.last = delivery
	}
	return seq, delivery, Delivered
}

// geChain is the state of a link's Gilbert-Elliott chain. It is a function
// of time alone, drawn from its own stream, so whether a fade covers an
// instant does not depend on how many packets were sent before it.
type geChain struct {
	params GilbertElliott
	rng    *rand.Rand
	isBad  bool
	until  time.Time // when the current state ends
}

// newGEChain starts a chain at now in its stationary distribution, so a
// test sees typical conditions from the first packet rather than a run of
// good ones.
func newGEChain(p GilbertElliott, now time.Time, rng *rand.Rand) geChain {
	g := geChain{params: p, rng: rng}
	if total := p.MeanGood + p.MeanBad; total > 0 {
		g.isBad = rng.Float64() < float64(p.MeanBad)/float64(total)
	}
	g.until = now.Add(g.stay())
	return g
}

// minGEStay is the shortest time the chain stays in a state. Real fades
// last milliseconds at least, and the floor bounds the walk forward in bad
// however small a test makes the means.
const minGEStay = time.Millisecond

// stay is how long the chain stays in its current state.
func (g *geChain) stay() time.Duration {
	mean := g.params.MeanGood
	if g.isBad {
		mean = g.params.MeanBad
	}
	return max(time.Duration(g.rng.ExpFloat64()*float64(mean)), minGEStay)
}

// bad walks the chain forward to t, which never goes backwards, and says
// whether it is in its bad state then. A state with no mean time is never
// entered.
func (g *geChain) bad(t time.Time) bool {
	switch {
	case g.params.MeanBad <= 0:
		return false
	case g.params.MeanGood <= 0:
		return true
	}
	for !t.Before(g.until) {
		g.isBad = !g.isBad
		g.until = g.until.Add(g.stay())
	}
	return g.isBad
}

// mergeWindows sorts windows and merges those that overlap or touch, so
// inWindows can binary-search them. Empty windows are dropped.
func mergeWindows(ws []Window) []Window {
	var out []Window
	for _, w := range ws {
		if w.End > w.Start {
			out = append(out, w)
		}
	}
	slices.SortFunc(out, func(a, b Window) int {
		switch {
		case a.Start < b.Start:
			return -1
		case a.Start > b.Start:
			return 1
		}
		return 0
	})
	merged := out[:0]
	for _, w := range out {
		if k := len(merged); k > 0 && w.Start <= merged[k-1].End {
			merged[k-1].End = max(merged[k-1].End, w.End)
			continue
		}
		merged = append(merged, w)
	}
	return merged
}

// inWindows says whether t falls in one of ws, which mergeWindows made.
func inWindows(ws []Window, t time.Duration) bool {
	i, _ := slices.BinarySearchFunc(ws, t, func(w Window, t time.Duration) int {
		switch {
		case w.End <= t:
			return -1
		case w.Start > t:
			return 1
		}
		return 0
	})
	return i < len(ws) && ws[i].Start <= t && t < ws[i].End
}

// mix makes a PCG seed for one link from the network's seed and the link's
// id, with SplitMix64's finaliser so that neighbouring seeds and ids give
// unrelated streams.
func mix(seed, id uint64) uint64 {
	z := seed + id*0x9e3779b97f4a7c15
	z = (z ^ z>>30) * 0xbf58476d1ce4e5b9
	z = (z ^ z>>27) * 0x94d049bb133111eb
	return z ^ z>>31
}
