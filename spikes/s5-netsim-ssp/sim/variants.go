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

	// 2. An approximation of what mosh 1.4.0 was observed to do as a black
	// box (FINDINGS §4). Client: resend unacked input every frame interval,
	// no backoff, slowing to every 3 s after 8 s without hearing from the
	// server. Server: no resend before a delayed ack could arrive; answers
	// a client datagram that shows the client is behind; slows to 3 s
	// after ~2 s of silence. The server half is our best fit, not a
	// confirmed mechanism.
	obs := func() (ssp.Config, ssp.Config) {
		c, s := base()
		for _, x := range []*ssp.Config{&c, &s} {
			x.Backoff = false
			x.SilentInterval = 3 * time.Second
		}
		c.RetransmitAtFrame = true
		c.SilentAfter = 10 * time.Second // ~10 s after last hearing the server
		s.AckDelayInRTO = true
		s.ResendOnRecv = true
		s.SilentAfter = 10 * time.Second // ~10 s after last news from the client
		s.SilentFromProgress = true
		return c, s
	}
	c, s = obs()
	out = append(out, Variant{Name: "mosh-observed", Client: c, Server: s,
		Note: "approximation of black-box mosh 1.4.0 [M]; server half is a fit"})

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
