package netsim

import "time"

// LinkParams is how a one-way link treats packets. The zero value is a
// perfect link: no delay, no loss, no limit.
type LinkParams struct {
	// Delay is the fixed one-way propagation delay.
	Delay time.Duration
	// Jitter is the mean of an exponential extra delay, capped at JitterCap.
	Jitter, JitterCap time.Duration
	// Reorder lets a packet overtake an earlier one when jitter says it
	// arrives first. Without it the link is FIFO, as most real paths are.
	Reorder bool
	// MTU drops, silently, any packet bigger than this. 0 is no limit.
	MTU int
	// Loss is the probability of an independent loss.
	Loss float64
	// GE, if set, adds Gilbert-Elliott burst loss.
	GE *GilbertElliott
	// Outages are windows of total loss.
	Outages []Window
	// Spikes, if set, delays a fraction of packets by much more than the
	// jitter, as bufferbloat and wifi retries do.
	Spikes *DelaySpikes
	// Trace, if set, replaces Delay's unlimited capacity with a Mahimahi
	// trace's delivery opportunities, behind a drop-tail queue of
	// QueueBytes.
	Trace      *Trace
	QueueBytes int
}

// GilbertElliott is two-state burst loss in continuous time: fades last a
// time rather than a number of packets, because SSP's send rate changes
// with conditions and a fade must not shorten when it sends less.
type GilbertElliott struct {
	GoodLoss, BadLoss float64
	// MeanGood and MeanBad are the mean times spent in each state.
	MeanGood, MeanBad time.Duration
}

// Window is a span of simulated time, measured from the network's start.
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
type Link struct{}

// Name is the link's name, "from->to".
func (l *Link) Name() string { panic("TODO slice 1") }

// SetParams changes how the link behaves from now on, for a scripted change
// of conditions.
func (l *Link) SetParams(p LinkParams) { panic("TODO slice 1") }

// LinkStats counts what a link did with what it was given.
type LinkStats struct {
	Sent, Delivered                                      int
	DroppedMTU, DroppedLoss, DroppedOutage, DroppedQueue int
	DroppedNoRoute                                       int
	Tampered                                             int // fate changed by the Tap
	Bytes                                                int
}
