package sim

import (
	"time"

	"mosey.spike/s5-netsim-ssp/ssp"
)

// Variants returns the configurations compared in FINDINGS.
func Variants() []Variant {
	base := func() (ssp.Config, ssp.Config) {
		c, s := ssp.DefaultConfig(false), ssp.DefaultConfig(true)
		// Client: first keystroke immediately, later ones frame-limited
		// (observed, FINDINGS §4); no collection interval.
		c.FrameLimit = true
		return c, s
	}
	var out []Variant

	// 1. A literal reading of D11 / the paper: RTO-driven retransmission
	// with RFC 6298 doubling, capped at 1 s.
	c, s := base()
	out = append(out, Variant{Name: "rfc6298", Client: c, Server: s,
		Note: "RTO retransmit, doubling backoff, 1 s cap [P §2.2 + RFC 6298 §5.5; cap D]"})

	// 1b. Isolating experiments for O7 (review): rfc6298 with only the
	// ack-delay term added (backoff kept), and with only resend-on-receive
	// added (backoff kept, no ack delay).
	c, s = base()
	c.AckDelayInRTO, s.AckDelayInRTO = true, true
	out = append(out, Variant{Name: "rfc6298-ackdelay", Client: c, Server: s,
		Note: "rfc6298 + peer ack delay in RTO (RFC 9002 §6.2.1); backoff kept"})
	c, s = base()
	c.ResendOnRecv, s.ResendOnRecv = true, true
	out = append(out, Variant{Name: "rfc6298-resendonrecv", Client: c, Server: s,
		Note: "rfc6298 + resend on a peer datagram showing it is behind; backoff kept"})

	// 2. An approximation of what mosh 1.4.0 was observed to do as a black
	// box (FINDINGS §4), fitted to the per-second datagram histograms of
	// both directions (sim/calibrate_test.go asserts the fit). Both sides:
	// resend unacknowledged state every frame interval, no backoff; after
	// 10 s without news from the peer, every 3 s. The server waits one RTO
	// (including the peer's ack delay) before its first resend of a
	// version and folds a due ack into a resend. The client counts any
	// datagram as news; the server counts only datagrams that advance
	// something (in the s2c blackhole the client keeps resending input the
	// server already has, and the server still drops to 3 s at ~10 s).
	// This is a fit of timing, not a confirmed mechanism.
	obs := func() (ssp.Config, ssp.Config) {
		c, s := base()
		for _, x := range []*ssp.Config{&c, &s} {
			x.Backoff = false
			x.RetransmitAtFrame = true
			x.SilentAfter = 10 * time.Second
			x.SilentInterval = 3 * time.Second
		}
		s.SilentFromProgress = true
		s.FirstRetransmitRTO = true
		s.AckDelayInRTO = true
		s.PiggybackResend = true
		return c, s
	}
	c, s = obs()
	out = append(out, Variant{Name: "mosh-observed", Client: c, Server: s,
		Note: "timing fit to black-box mosh 1.4.0 [M], both directions"})

	// 3. O7 "resend": never back off. Resend current state every RTO
	// (RTO includes the peer's ack delay, RFC 9002 style) and at once when
	// a peer datagram shows the peer is behind (e.g. the first datagram
	// after an outage). After 2 s of silence from the peer, resend every
	// 1 s rather than every RTO to bound the cost of long outages.
	rec := func() (ssp.Config, ssp.Config) {
		c, s := base()
		for _, x := range []*ssp.Config{&c, &s} {
			x.Backoff = false
			x.AckDelayInRTO = true
			x.ResendOnRecv = true
			x.SilentAfter = 2 * time.Second
			x.SilentInterval = time.Second
		}
		return c, s
	}
	c, s = rec()
	out = append(out, Variant{Name: "o7-resend", Client: c, Server: s,
		Note: "no backoff; RTO+ackdelay; resend on peer datagram showing it is behind; 1 s after 2 s silence"})

	// 4. Same, but RTO without the ack-delay term (isolates its effect).
	c, s = rec()
	c.AckDelayInRTO, s.AckDelayInRTO = false, false
	out = append(out, Variant{Name: "o7-resend-noackdelay", Client: c, Server: s,
		Note: "o7-resend without the ack delay in the RTO"})

	// 5. Same, with silent-mode resend every 3 s (heartbeat cadence).
	c, s = rec()
	c.SilentInterval, s.SilentInterval = 3*time.Second, 3*time.Second
	out = append(out, Variant{Name: "o7-resend-3s", Client: c, Server: s,
		Note: "o7-resend with 3 s silent-mode cadence"})

	// 5b. Same, with probes proportional to the silence: from 300 ms of
	// silence, resend every silence/8 (at least a frame interval, at most
	// 1 s). Cheap for long outages, quick for short ones.
	c, s = rec()
	for _, x := range []*ssp.Config{&c, &s} {
		x.SilentAfter = 300 * time.Millisecond
		x.SilentDivisor = 8
	}
	out = append(out, Variant{Name: "o7-resend-prop", Client: c, Server: s,
		Note: "o7-resend with silent-mode resend every clamp(silence/8, frame, 1 s) after 300 ms"})

	// 6. O7 parity: client sends incremental keystroke diffs plus XOR
	// parity every 4 data datagrams (instead of cumulative diffs).
	c, s = rec()
	c.Optimistic, c.Parity = true, 4
	out = append(out, Variant{Name: "o7-parity", Client: c, Server: s,
		Note: "o7-resend; client incremental keystroke diffs + XOR parity per 4"})

	// 7. Incremental keystrokes without parity (control for 6).
	c, s = rec()
	c.Optimistic = true
	out = append(out, Variant{Name: "o7-incremental", Client: c, Server: s,
		Note: "o7-resend; client incremental keystroke diffs, no parity"})

	// 8. O9: optimistic screen diffs from the last sent state.
	c, s = rec()
	s.Optimistic = true
	out = append(out, Variant{Name: "o9-optimistic", Client: c, Server: s,
		Note: "o7-resend; server diffs from last sent state while young"})

	// 9. O9: the client sends every keystroke at once instead of holding
	// it for the frame interval (keystroke datagrams are tiny, so the
	// pacing argument [P §2.3] is about screen frames, not input).
	c, s = rec()
	c.FrameLimit = false
	out = append(out, Variant{Name: "o9-client-immediate", Client: c, Server: s,
		Note: "o7-resend; client does not frame-limit keystrokes"})
	return out
}

// VariantByName finds a variant.
func VariantByName(name string) (Variant, bool) {
	for _, v := range Variants() {
		if v.Name == name {
			return v, true
		}
	}
	return Variant{}, false
}
