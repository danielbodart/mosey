package ssp

import (
	"encoding/binary"
	"slices"
	"time"
)

// Config holds the timing constants (ssp-spec.md §7) and the experimental
// variant switches.
type Config struct {
	MinFrame, MaxFrame time.Duration // frame interval clamp: 20 ms, 250 ms
	Collection         time.Duration // wait after first change: 8 ms server
	// FrameLimit applies the frame interval to new state. True for the
	// server. For the client see ssp-spec.md §3 and FINDINGS §4.
	FrameLimit bool
	AckDelay   time.Duration // 100 ms
	Heartbeat  time.Duration // 3 s
	RTOMin     time.Duration // 50 ms
	RTOMax     time.Duration // backoff ceiling
	InitialRTO time.Duration // before any RTT sample
	MTU        int           // max UDP payload, 1280

	// Backoff doubles the RTO on each expiry without a new ack (RFC 6298
	// §5.5; the "rfc6298" variant).
	Backoff bool
	// RetransmitAtFrame resends unacknowledged state every frame interval
	// instead of every RTO (what mosh 1.4.0 is observed to do, FINDINGS §4).
	RetransmitAtFrame bool
	// FirstRetransmitRTO (with RetransmitAtFrame): the first retransmit of
	// a version waits one RTO, later ones the frame interval.
	FirstRetransmitRTO bool
	// PiggybackResend: when an ack is due and our state is unacknowledged,
	// resend the state (which carries the ack) instead of an empty ack.
	PiggybackResend bool
	// SilentAfter: once nothing has been heard from the peer for this long,
	// unacknowledged state is resent only every SilentInterval (mosh 1.4.0
	// observed, FINDINGS §4: ~10 s on both sides, then 3 s).
	SilentAfter, SilentInterval time.Duration
	// SilentFromProgress measures SilentAfter from the last datagram that
	// told us something new (advanced our ack or the peer's state) rather
	// than from the last datagram of any kind.
	SilentFromProgress bool
	// SilentDivisor > 0 makes the silent-mode resend interval
	// clamp(silence/SilentDivisor, frame interval, SilentInterval).
	SilentDivisor int
	// AckDelayInRTO adds the peer's maximum ack delay (assumed equal to our
	// AckDelay) to the RTO, as QUIC's PTO does (RFC 9002 §6.2.1). Without
	// it, because SSP's RTT samples exclude the hold time [P §2.2], the
	// RTO fires before a delayed ack can arrive.
	AckDelayInRTO bool
	// ResendOnRecv (O7): when a datagram from the peer shows it still lacks
	// our latest state although it has had time to receive it, resend
	// current state (from acked) at once instead of waiting for the RTO.
	ResendOnRecv bool
	// Optimistic (O9): diff from the last sent version (not the acked one)
	// while the oldest unacknowledged send is younger than one RTO.
	Optimistic bool
	// Parity (O7): after every Parity single-fragment data datagrams, send
	// one XOR parity datagram over them. Only meaningful with Optimistic.
	Parity int
	// Compress, if set, transforms each diff before framing (O8 hook).
	Compress func([]byte) []byte

	// Server selects the direction bit and keys.
	Server bool
	// Secret is the session secret (a fixed test secret in the spike).
	Secret []byte
}

// DefaultConfig returns the D11 baseline for one side.
func DefaultConfig(server bool) Config {
	c := Config{
		MinFrame: 20 * time.Millisecond, MaxFrame: 250 * time.Millisecond,
		AckDelay: 100 * time.Millisecond, Heartbeat: 3 * time.Second,
		RTOMin: 50 * time.Millisecond, RTOMax: time.Second,
		InitialRTO: time.Second, MTU: 1280, Backoff: true,
		Server: server, Secret: TestSecret,
	}
	if server {
		c.Collection = 8 * time.Millisecond
		c.FrameLimit = true
	}
	return c
}

// Stats counts what a transport sent.
type Stats struct {
	Datagrams, Bytes    int
	DataDatagrams       int
	Retransmits         int
	AckOnly, Heartbeats int
	ParityDatagrams     int
	ResendOnRecv        int
	Recovered           int // instructions rebuilt from parity
	Unappliable         int // instructions dropped for want of a source
	Fragments           int
	// Receive-side security counters.
	AuthFailures, Replays int
	PathChallenges        int
}

type sentRec struct {
	ver uint64
	at  time.Time
}

// Transport is one endpoint's SSP state for both directions: it sends its
// Source and receives into its Sink.
type Transport struct {
	cfg  Config
	src  Source
	sink Sink
	out  func([]byte)

	epoch  time.Time
	seq    uint64
	sealer sealer
	replay replayWindow

	// RTT
	srtt, rttvar time.Duration
	haveRTT      bool
	remoteTS     uint32
	remoteTSAt   time.Time
	haveRemoteTS bool

	// sender
	acked        uint64
	lastSentVer  uint64
	sentAny      bool
	lastDataSend time.Time
	lastAnySend  time.Time
	changeAt     time.Time // first unsent change, zero if none
	backoff      uint
	rexmits      int       // retransmits since acked last advanced
	inflight     []sentRec // sent versions > acked, oldest first
	instrID      uint32
	parityBuf    [][]byte
	parityIDs    []uint32
	lastResend   time.Time

	// receiver
	ackDue       time.Time
	frags        reassembly
	pending      map[uint64]instruction // incremental instructions awaiting their source, by from
	recent       map[uint32][]byte      // recent instruction bodies by id (parity recovery)
	recentQ      []uint32
	maxSeq       uint64
	gotAny       bool
	LastRecv     time.Time
	lastProgress time.Time

	Stats Stats
}

// NewTransport creates a transport. out sends one datagram to the peer.
func NewTransport(cfg Config, src Source, sink Sink, out func([]byte)) *Transport {
	now := time.Now()
	tr := &Transport{cfg: cfg, src: src, sink: sink, out: out, epoch: now,
		lastAnySend: now, pending: map[uint64]instruction{}, recent: map[uint32][]byte{},
		sealer: newSealer(cfg.Secret, cfg.Server)}
	if cfg.Server {
		tr.seq = dirBit
	}
	return tr
}

func (t *Transport) us32(now time.Time) uint32 {
	return uint32(now.Sub(t.epoch).Microseconds())
}

// SRTT returns the smoothed RTT (0 if unknown).
func (t *Transport) SRTT() time.Duration { return t.srtt }

// RTO returns the current retransmission timeout before backoff.
func (t *Transport) RTO() time.Duration {
	if !t.haveRTT {
		return t.cfg.InitialRTO
	}
	rto := t.srtt + max(time.Millisecond, 4*t.rttvar)
	rto = max(rto, t.cfg.RTOMin)
	if t.cfg.AckDelayInRTO {
		rto += t.cfg.AckDelay
	}
	return rto
}

func (t *Transport) effectiveRTO() time.Duration {
	rto := t.RTO()
	if t.cfg.Backoff {
		ceiling := max(t.cfg.RTOMax, rto)
		for i := uint(0); i < t.backoff && rto < ceiling; i++ {
			rto *= 2
		}
		rto = min(rto, ceiling)
	}
	return rto
}

func (t *Transport) retransmitInterval(now time.Time) time.Duration {
	if t.cfg.SilentAfter > 0 {
		heard := t.LastRecv
		if t.cfg.SilentFromProgress {
			heard = t.lastProgress
		}
		if heard.IsZero() {
			heard = t.epoch
		}
		if now.Sub(heard) >= t.cfg.SilentAfter {
			if d := t.cfg.SilentDivisor; d > 0 {
				// Probe in proportion to how long the silence has lasted:
				// often at first, at most every SilentInterval later.
				return min(max(now.Sub(heard)/time.Duration(d), t.frameInterval()), t.cfg.SilentInterval)
			}
			return t.cfg.SilentInterval
		}
	}
	if t.cfg.RetransmitAtFrame {
		if t.cfg.FirstRetransmitRTO && t.rexmits == 0 {
			return t.RTO()
		}
		return t.frameInterval()
	}
	return t.effectiveRTO()
}

func (t *Transport) frameInterval() time.Duration {
	if !t.haveRTT {
		return t.cfg.MinFrame
	}
	return min(max(t.srtt/2, t.cfg.MinFrame), t.cfg.MaxFrame)
}

// NextWake returns when Tick next needs to run.
func (t *Transport) NextWake() time.Time {
	now := time.Now()
	cur := t.src.Version()
	wake := t.lastAnySend.Add(t.cfg.Heartbeat)
	upd := func(x time.Time) {
		if x.Before(wake) {
			wake = x
		}
	}
	if cur != t.lastSentVer || !t.sentAny && cur != 0 {
		at := now
		if !t.changeAt.IsZero() {
			at = t.changeAt.Add(t.cfg.Collection)
		}
		if t.cfg.FrameLimit {
			if f := t.lastDataSend.Add(t.frameInterval()); f.After(at) {
				at = f
			}
		}
		upd(at)
	} else if t.sentAny && cur > t.acked {
		upd(t.lastDataSend.Add(t.retransmitInterval(now)))
	}
	if !t.ackDue.IsZero() {
		upd(t.ackDue)
	}
	return wake
}

// Tick performs whatever sends are due now.
func (t *Transport) Tick() {
	now := time.Now()
	cur := t.src.Version()
	newState := cur != t.lastSentVer
	if newState && t.changeAt.IsZero() {
		t.changeAt = now
	}
	sentData := false
	if newState {
		ok := !now.Before(t.changeAt.Add(t.cfg.Collection))
		if t.cfg.FrameLimit && now.Before(t.lastDataSend.Add(t.frameInterval())) {
			ok = false
		}
		if ok {
			t.sendData(now, false)
			sentData = true
		}
	} else if t.sentAny && cur > t.acked && !now.Before(t.lastDataSend.Add(t.retransmitInterval(now))) {
		t.sendData(now, true)
		t.Stats.Retransmits++
		t.rexmits++
		if t.cfg.Backoff {
			t.backoff++
		}
		sentData = true
	}
	if !sentData && !t.ackDue.IsZero() && !now.Before(t.ackDue) && t.cfg.PiggybackResend && t.sentAny && cur > t.acked {
		t.sendData(now, true)
		t.Stats.Retransmits++
		t.rexmits++
	} else if !sentData && !t.ackDue.IsZero() && !now.Before(t.ackDue) {
		t.sendEmpty(now)
		t.Stats.AckOnly++
	} else if !sentData && !now.Before(t.lastAnySend.Add(t.cfg.Heartbeat)) {
		t.sendEmpty(now)
		t.Stats.Heartbeats++
	}
}

func (t *Transport) base(now time.Time, retransmit bool) uint64 {
	if !t.cfg.Optimistic || retransmit || len(t.inflight) == 0 {
		return t.acked
	}
	if now.Sub(t.inflight[0].at) < t.RTO() {
		return t.lastSentVer
	}
	return t.acked
}

func (t *Transport) sendData(now time.Time, retransmit bool) {
	cur := t.src.Version()
	from := t.base(now, retransmit)
	diff := t.src.Diff(from)
	if t.cfg.Compress != nil {
		diff = t.cfg.Compress(diff)
	}
	in := instruction{from: from, to: cur, ack: t.sink.Latest(), floor: t.acked, diff: diff}
	t.src.Sent(cur)
	nfrag := t.sendInstruction(now, in.encode(), true)
	t.Stats.DataDatagrams += nfrag
	if cur != t.lastSentVer || len(t.inflight) == 0 {
		t.inflight = append(t.inflight, sentRec{cur, now})
	}
	t.lastSentVer = cur
	t.sentAny = true
	t.lastDataSend = now
	t.changeAt = time.Time{}
	t.ackDue = time.Time{}
}

func (t *Transport) sendEmpty(now time.Time) {
	v := t.lastSentVer
	in := instruction{from: v, to: v, ack: t.sink.Latest(), floor: t.acked}
	t.sendInstruction(now, in.encode(), false)
	t.ackDue = time.Time{}
}

func (t *Transport) header(now time.Time, kind byte) []byte {
	t.seq++
	h := header{seq: t.seq, kind: kind, ts: t.us32(now)}
	if t.haveRemoteTS {
		// The echo is the peer's timestamp advanced by how long we held
		// it, so our hold time (delayed ack, frame pacing) is not counted
		// as path delay [P §2.2]. Each timestamp is echoed once.
		h.hasEcho = true
		h.echo = t.remoteTS + uint32(now.Sub(t.remoteTSAt).Microseconds())
		t.haveRemoteTS = false
	}
	return putHeader(make([]byte, 0, t.cfg.MTU), h)
}

func (t *Transport) emit(now time.Time, b []byte) {
	b = t.sealer.seal(b)
	t.Stats.Datagrams++
	t.Stats.Bytes += len(b)
	t.lastAnySend = now
	t.out(b)
}

// sendInstruction fragments and sends an encoded instruction; returns the
// number of datagrams.
func (t *Transport) sendInstruction(now time.Time, body []byte, data bool) int {
	whole := body
	t.instrID++
	id := t.instrID
	maxPayload := t.cfg.MTU - Overhead
	count := max(1, (len(body)+maxPayload-1)/maxPayload)
	if count > MaxFragments {
		return 0 // the object must never produce this; the receiver would refuse it
	}
	for idx := 0; idx < count; idx++ {
		chunk := body[:min(len(body), maxPayload)]
		body = body[len(chunk):]
		b := t.header(now, kindFrag)
		b = binary.BigEndian.AppendUint32(b, id)
		b = binary.BigEndian.AppendUint16(b, uint16(idx))
		b = binary.BigEndian.AppendUint16(b, uint16(count))
		b = append(b, chunk...)
		t.emit(now, b)
	}
	t.Stats.Fragments += count
	if t.cfg.Parity > 0 && count == 1 && data {
		t.addParity(now, id, whole)
	}
	return count
}

// SealPathChallenge returns an authenticated path-challenge datagram
// carrying token. The caller sends it to the address being validated
// (not through out). It counts towards Stats.
func (t *Transport) SealPathChallenge(token [8]byte) []byte {
	now := time.Now()
	b := t.header(now, kindPathChl)
	b = append(b, token[:]...)
	b = t.sealer.seal(b)
	t.Stats.Datagrams++
	t.Stats.Bytes += len(b)
	t.Stats.PathChallenges++
	return b
}

// ---- receive ----

// RecvInfo says what Receive made of a datagram.
type RecvInfo struct {
	// Authentic: it authenticated and passed the replay window. Nothing
	// else in RecvInfo is meaningful otherwise, and no state was changed.
	Authentic bool
	// Newest: it has the highest sequence number accepted so far.
	Newest bool
	// PathResponse is set when it was a path response carrying Token.
	PathResponse bool
	Token        [8]byte
}

// Receive processes one datagram. Order matters: authenticate, then the
// replay window, and only then touch any state (sequence high-water mark,
// RTT, timestamps, acks, instructions).
func (t *Transport) Receive(d []byte) RecvInfo {
	now := time.Now()
	if len(d) >= seqLen && !t.replay.check(binary.BigEndian.Uint64(d)) {
		t.Stats.Replays++
		return RecvInfo{}
	}
	h, body, err := t.sealer.open(d)
	if err != nil {
		t.Stats.AuthFailures++
		return RecvInfo{}
	}
	t.replay.accept(h.seq)
	info := RecvInfo{Authentic: true}
	newest := !t.gotAny || h.seq > t.maxSeq
	if newest {
		t.maxSeq = h.seq
		t.gotAny = true
	}
	info.Newest = newest
	t.LastRecv = now
	if h.hasEcho {
		sample := time.Duration(t.us32(now)-h.echo) * time.Microsecond
		if sample < time.Minute { // a wrapped or bogus echo is ignored
			t.rttSample(sample)
		}
	}
	if newest {
		t.remoteTS, t.remoteTSAt, t.haveRemoteTS = h.ts, now, true
	}
	switch h.kind {
	case kindFrag:
		if len(body) < fragHdrLen {
			return info
		}
		id := binary.BigEndian.Uint32(body)
		idx := binary.BigEndian.Uint16(body[4:])
		count := binary.BigEndian.Uint16(body[6:])
		payload := body[fragHdrLen:]
		if count == 1 {
			t.remember(id, payload)
		}
		if full, ok := t.frags.add(id, idx, count, payload); ok {
			t.handleInstruction(now, full)
		}
	case kindParity:
		t.handleParity(now, body)
	case kindPathChl:
		if len(body) == 8 {
			// Answer at once, from wherever we are now.
			b := t.header(now, kindPathRsp)
			t.emit(now, append(b, body...))
		}
	case kindPathRsp:
		if len(body) == 8 {
			info.PathResponse = true
			copy(info.Token[:], body)
		}
	}
	return info
}

func (t *Transport) rttSample(r time.Duration) {
	if !t.haveRTT {
		t.srtt, t.rttvar, t.haveRTT = r, r/2, true
		return
	}
	d := t.srtt - r
	if d < 0 {
		d = -d
	}
	t.rttvar = (3*t.rttvar + d) / 4
	t.srtt = (7*t.srtt + r) / 8
}

func (t *Transport) handleInstruction(now time.Time, body []byte) {
	in, err := decodeInstruction(body)
	if err != nil {
		return
	}
	// The ack covers our source.
	if in.ack > t.acked && in.ack <= t.src.Version() {
		t.acked = in.ack
		t.lastProgress = now
		t.backoff = 0
		t.rexmits = 0
		t.src.Release(t.acked)
		k := 0
		for _, s := range t.inflight {
			if s.ver > t.acked {
				t.inflight[k] = s
				k++
			}
		}
		t.inflight = t.inflight[:k]
	}
	if in.from != in.to {
		t.applyIncoming(now, in)
	}
	// O7: the peer evidently lacks our latest state. At most once per
	// RTO, so a stream of small peer datagrams cannot make us send a
	// stream of large ones (the path layer separately limits what goes to
	// an address that has not been validated).
	if t.cfg.ResendOnRecv && t.sentAny && t.acked < t.lastSentVer && t.lastSentVer == t.src.Version() &&
		now.Sub(t.lastDataSend) >= t.srtt+t.rttvar && now.Sub(t.lastResend) >= t.RTO() {
		t.sendData(now, true)
		t.Stats.ResendOnRecv++
		t.lastResend = now
	}
}

func (t *Transport) scheduleAck(now time.Time) {
	if t.ackDue.IsZero() {
		t.ackDue = now.Add(t.cfg.AckDelay)
	}
}

func (t *Transport) applyIncoming(now time.Time, in instruction) {
	latest := t.sink.Latest()
	if in.to <= latest {
		t.scheduleAck(now) // duplicate: our ack was probably lost
		return
	}
	if !t.sink.Has(in.from) {
		t.Stats.Unappliable++
		if len(t.pending) < 64 {
			t.pending[in.from] = in
		}
		return
	}
	if err := t.sink.Apply(in.from, in.to, in.diff); err != nil {
		return
	}
	t.sink.Release(in.floor)
	t.lastProgress = now
	t.scheduleAck(now)
	// Drain instructions that were waiting for this state (in a fixed
	// order, for determinism).
	for {
		progressed := false
		keys := make([]uint64, 0, len(t.pending))
		for k := range t.pending {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, from := range keys {
			p := t.pending[from]
			if p.to <= t.sink.Latest() {
				delete(t.pending, from)
				continue
			}
			if t.sink.Has(from) {
				delete(t.pending, from)
				if t.sink.Apply(p.from, p.to, p.diff) == nil {
					progressed = true
				}
			}
		}
		if !progressed {
			break
		}
	}
}

// ---- parity (O7) ----

func (t *Transport) addParity(now time.Time, id uint32, body []byte) {
	t.parityBuf = append(t.parityBuf, append([]byte(nil), body...))
	t.parityIDs = append(t.parityIDs, id)
	if len(t.parityBuf) < t.cfg.Parity {
		return
	}
	maxLen := 0
	for _, b := range t.parityBuf {
		maxLen = max(maxLen, len(b))
	}
	p := t.header(now, kindParity)
	p = append(p, byte(len(t.parityBuf)))
	for i, b := range t.parityBuf {
		p = binary.BigEndian.AppendUint32(p, t.parityIDs[i])
		p = binary.BigEndian.AppendUint16(p, uint16(len(b)))
	}
	x := make([]byte, maxLen)
	for _, b := range t.parityBuf {
		for i, c := range b {
			x[i] ^= c
		}
	}
	p = append(p, x...)
	t.parityBuf, t.parityIDs = t.parityBuf[:0], t.parityIDs[:0]
	if len(p)+tagLen > t.cfg.MTU {
		t.seq-- // never sent; keep seq dense
		return
	}
	t.Stats.ParityDatagrams++
	t.emit(now, p)
}

func (t *Transport) remember(id uint32, body []byte) {
	if _, ok := t.recent[id]; ok {
		return
	}
	t.recent[id] = append([]byte(nil), body...)
	t.recentQ = append(t.recentQ, id)
	if len(t.recentQ) > 64 {
		delete(t.recent, t.recentQ[0])
		t.recentQ = t.recentQ[1:]
	}
}

func (t *Transport) handleParity(now time.Time, b []byte) {
	if len(b) < 1 {
		return
	}
	k := int(b[0])
	b = b[1:]
	if len(b) < 6*k {
		return
	}
	ids := make([]uint32, k)
	lens := make([]int, k)
	for i := 0; i < k; i++ {
		ids[i] = binary.BigEndian.Uint32(b[6*i:])
		lens[i] = int(binary.BigEndian.Uint16(b[6*i+4:]))
	}
	x := append([]byte(nil), b[6*k:]...)
	missing := -1
	for i, id := range ids {
		body, ok := t.recent[id]
		if !ok {
			if missing >= 0 {
				return // two or more missing: parity cannot help
			}
			missing = i
			continue
		}
		for j, c := range body {
			if j < len(x) {
				x[j] ^= c
			}
		}
	}
	if missing < 0 || lens[missing] > len(x) {
		return
	}
	rec := x[:lens[missing]]
	t.remember(ids[missing], rec)
	t.Stats.Recovered++
	t.handleInstruction(now, rec)
}
