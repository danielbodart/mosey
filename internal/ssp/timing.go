package ssp

import "time"

// SSP's timing (D11 as amended; docs/spec/ssp.md §6.2, §7.1). Each value
// cites where it comes from: [P §x] is the Mosh paper (Winstein &
// Balakrishnan, USENIX ATC 2012), [S5 §x] our own netsim measurement in
// docs/spikes/s5-netsim-ssp/FINDINGS.md, [M] black-box measurement of mosh
// 1.4.0, [D] decided in the spec.
const (
	// minFrame is the 50 Hz cap on frames [P §2.3 fn. 1], and the frame
	// interval before the first RTT sample [D, S5].
	minFrame = 20 * time.Millisecond
	// maxFrame is the longest frame interval [P §4 Fig. 3], D11.
	maxFrame = 250 * time.Millisecond
	// localFrame replaces minFrame on a local connection (§6.2.1): Dan
	// decided on 2026-11-27 that a local session drops D11's 50 Hz cap
	// [D: Dan, 2026-11-27]. Some floor stays, so a flood of output (cat of
	// a big file) cannot make the server send a frame per pty read: 4 ms
	// is at most 250 frames a second, and is less than one refresh of the
	// fastest common displays (240 Hz, 4.2 ms), so it costs at most one
	// refresh, and only to the second of two changes within 4 ms. The first
	// change after a pause never waits for it [D].
	localFrame = 4 * time.Millisecond

	// serverCollection is how long the server waits after a change for
	// more output to join it, so writes that follow one another closely go
	// in one instruction [P §2.3, §4], D11. The client waits for nothing:
	// mosh sends the first key after idle at once [M], and sending keys
	// without waiting measured the same [S5 §7].
	serverCollection = 8 * time.Millisecond

	// ackDelay is how long an ack may wait for data to ride on [P §2.3],
	// D11. It is also the peer's MaxAckDelay that the RTO adds, on a local
	// connection too, since this end cannot know the peer's timing.
	ackDelay = 100 * time.Millisecond
	// On a local connection the server does not wait to collect output
	// and an ack goes at once (§6.2.1) [D: Dan, 2026-11-27]: a datagram on
	// loopback costs nothing worth saving, and an ack held back holds back
	// the sender's next multi-fragment frame (§6.3) and the end of a
	// session (server.md §2.4).
	localCollection = 0
	localAckDelay   = 0

	// heartbeat is the longest an endpoint stays silent [P §2.3], measured
	// at 3.00 s both ways [M], D11.
	heartbeat = 3 * time.Second

	// rtoFloor replaces RFC 6298's 1 s minimum [P §2.2], D11.
	rtoFloor = 50 * time.Millisecond
	// granularity is RFC 6298 §2's G: Go's timers resolve about 1 ms on
	// Linux in practice [D].
	granularity = time.Millisecond
	// initialRTO is the RTO before any sample, RFC 6298 §2.1.
	initialRTO = time.Second
	// maxRetransmit caps the doubled retransmit interval and the outage
	// probe interval, D11 as amended [S5 §5].
	maxRetransmit = time.Second

	// silentAfter is how long without a word from the peer before probing
	// in proportion to the silence replaces the retransmit interval, and
	// probeDivisor the proportion: probes go every clamp(silence/8, frame
	// interval, 1 s) [S5 §5, variant o7-resend-prop]. The 300 ms was that
	// variant's parameter and was not swept on its own.
	silentAfter  = 300 * time.Millisecond
	probeDivisor = 8

	// bogusRTT is a sample too long to be a round trip: a wrapped or forged
	// echo [D].
	bogusRTT = time.Minute
)

// Window is the most versions a sender has outstanding past what the peer
// has acknowledged (§6.1) [D]. It bounds what both ends keep, at 17
// versions each, without either evicting anything the other may need.
const Window = 16

// Burst is the most fragments one transmission sends per frame interval
// (§5) [D, provisional: a guess for netsim to measure].
const Burst = 16

// rtt is the RFC 6298 §2 estimator, with α = 1/8, β = 1/4 and K = 4
// [P §2.2].
type rtt struct {
	srtt, rttvar time.Duration
	sampled      bool
	// local is a local connection's: frames have localFrame's floor in
	// place of minFrame's (§6.2.1). The zero value is D11's.
	local bool
}

func (r *rtt) sample(d time.Duration) {
	if !r.sampled {
		r.srtt, r.rttvar, r.sampled = d, d/2, true
		return
	}
	r.rttvar = (3*r.rttvar + (r.srtt - d).Abs()) / 4
	r.srtt = (7*r.srtt + d) / 8
}

// rto is the retransmission timeout before backoff: RFC 6298's, with a
// 50 ms floor instead of 1 s, plus the peer's 100 ms ack delay as QUIC adds
// it (RFC 9002 §6.2.1). Without that, the timer fires before a delayed ack
// can come back, which wasted 21% of the server's datagrams on a clean
// 40 ms path [S5 §5]. The effective floor is 150 ms.
func (r *rtt) rto() time.Duration {
	if !r.sampled {
		return initialRTO
	}
	return max(rtoFloor, r.srtt+max(granularity, 4*r.rttvar)) + ackDelay
}

// frameInterval is SRTT/2 clamped to 20-250 ms: about one instruction in
// flight [P §2.3]. On a local connection the floor is 4 ms (§6.2.1).
func (r *rtt) frameInterval() time.Duration {
	floor := minFrame
	if r.local {
		floor = localFrame
	}
	if !r.sampled {
		return floor
	}
	return min(max(r.srtt/2, floor), maxFrame)
}

// retransmitAt is when unacknowledged state is next due to go again, with
// the last data sent at lastData, nothing heard from the peer since heard,
// and backoff timeouts since the peer's ack last advanced (§6.2).
//
// Below 300 ms of silence the interval is the RTO, doubled per timeout
// (RFC 6298 §5.5) and capped at 1 s. From 300 ms of silence, outage probes
// go every clamp(silence/8, frame interval, 1 s) instead. Because the
// silence grows while the sender waits, that interval is a function of the
// very time being sought; it is solved for here, so a timer set to the
// answer fires exactly when the rule says, not in ever smaller steps.
func (r *rtt) retransmitAt(lastData, heard time.Time, backoff int) time.Time {
	interval := r.rto()
	for range min(backoff, 8) {
		interval *= 2
	}
	normal := lastData.Add(min(interval, maxRetransmit))
	silent := heard.Add(silentAfter)
	if normal.Before(silent) {
		return normal
	}
	frame := r.frameInterval()
	var probe time.Time
	switch {
	case lastData.Add(frame).Sub(heard)/probeDivisor <= frame:
		probe = lastData.Add(frame)
	case lastData.Add(maxRetransmit).Sub(heard)/probeDivisor >= maxRetransmit:
		probe = lastData.Add(maxRetransmit)
	default:
		// t = lastData + (t - heard)/8, so t = lastData + (lastData - heard)/7.
		probe = lastData.Add(lastData.Sub(heard) / (probeDivisor - 1))
	}
	if probe.Before(silent) {
		return silent
	}
	return probe
}
