package ssp

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Endpoint is one side's SSP: the sender of its local object L and the
// receiver of the peer's object R, which share datagrams because acks and
// timestamps ride on whatever goes next.
//
// Run does the work. Set, Remote, Acked, RemoteChanged and Stats may be
// called from any goroutine.
type Endpoint[L State[L], R State[R]] struct {
	d   Datagrams
	cfg Config
	lim limits
	// epoch is when the endpoint was made: the zero of its timestamps.
	epoch time.Time
	// collection is how long a change waits for more to join it (§6.2).
	collection time.Duration
	// wake tells Run that Set changed something.
	wake chan struct{}
	// changed is RemoteChanged's.
	changed chan struct{}

	mu sync.Mutex

	// The sender (§6.1).

	// pending is the newest local object from Set. It and every sent
	// version are the endpoint's own clones, never changed in place, so
	// they can be shared.
	pending L
	// sent holds the object at every version from acked to latest.
	sent          map[uint64]L
	latest, acked uint64
	// changeAt is when pending first differed from sent[latest]; zero when
	// it does not.
	changeAt time.Time
	// lastData is when the last fragment went, lastAny the last datagram
	// of any kind.
	lastData, lastAny time.Time
	// backoff is retransmission timeouts since acked last advanced.
	backoff int
	// instr is the newest instruction made, and tx its transmission if one
	// is being paced out.
	instr  *made
	nextID uint32
	tx     transmission

	// The receiver (§7.3).

	// held is the peer's object at versions this side has reached, newest
	// the largest of them, floor the largest from the peer has used.
	held          map[uint64]R
	newest, floor uint64
	re            reassembly

	// Both directions.

	rtt rtt
	// lastHeard is when the last datagram arrived, or the endpoint's
	// creation until one does: the start of the silence that outage probing
	// measures.
	lastHeard time.Time
	heard     bool
	// echo is the peer's last timestamp and when it arrived, to go back on
	// the next datagram, once (§7.1).
	echo    uint32
	echoAt  time.Time
	echoDue bool
	// ackDue is when an ack must have gone by; zero when none is owed.
	ackDue time.Time
	// queue is what this pass has made to send. Run sends it once the lock
	// is released, so a slow Send never holds up Set or Remote.
	queue []outgoing

	// ch is the chaff schedule (§9.1).
	ch chaffing
}

// outgoing is one datagram queued to send: an SSP payload, or, if payload
// is nil, a CHAFF frame of chaff bytes of sealed plaintext.
type outgoing struct {
	payload []byte
	chaff   int
}

// made is an instruction encoded and ready to fragment. A retransmission
// sends it again exactly, same id and bytes, so the receiver can fill the
// holes in a partial from a second transmission (§5).
type made struct {
	from, to uint64
	id       uint32
	bytes    []byte
	count    int
}

// transmission is the newest instruction being paced out, Burst fragments
// per frame interval (§5).
type transmission struct {
	active bool
	// next is the first fragment not yet sent, at when the next burst goes.
	next int
	at   time.Time
}

// NewEndpoint starts with local and remote as version 0, the empty object
// both sides know. It keeps clones of both.
func NewEndpoint[L State[L], R State[R]](d Datagrams, cfg Config, local L, remote R) *Endpoint[L, R] {
	if cfg.MaxPayload <= HeaderMax+padTrailer || cfg.MaxPayload > 1<<16-1 {
		// The top bound keeps every k a u16 (§3).
		panic(fmt.Sprintf("ssp: MaxPayload %d is not between %d and %d", cfg.MaxPayload, HeaderMax+padTrailer+1, 1<<16-1))
	}
	if cfg.FrameOverhead < 0 {
		panic(fmt.Sprintf("ssp: FrameOverhead %d is negative", cfg.FrameOverhead))
	}
	if cfg.MaxRemoteBytes <= 0 {
		panic(fmt.Sprintf("ssp: MaxRemoteBytes %d is not positive", cfg.MaxRemoteBytes))
	}
	now := time.Now()
	e := &Endpoint[L, R]{
		d:         d,
		cfg:       cfg,
		lim:       newLimits(cfg),
		epoch:     now,
		wake:      make(chan struct{}, 1),
		changed:   make(chan struct{}, 1),
		pending:   local.Clone(),
		sent:      map[uint64]L{},
		held:      map[uint64]R{0: remote.Clone()},
		lastAny:   now,
		lastHeard: now,
	}
	e.sent[0] = e.pending
	e.re.limits = e.lim
	if c, ok := d.(Chaffer); ok {
		e.ch = chaffing{c: c, tick: chaffTick, size: e.chaffSize()}
	}
	if cfg.Role == Server {
		e.collection = serverCollection
	}
	return e
}

// Run sends and receives until ctx is done, Datagrams fails, or the peer
// breaks the protocol, which ends it with an error wrapping ErrProtocol.
// It is called once.
func (e *Endpoint[L, R]) Run(ctx context.Context) error {
	parent := ctx
	ctx, cancel := context.WithCancel(ctx)
	received := make(chan []byte)
	failed := make(chan error, 1)
	var reader sync.WaitGroup
	reader.Go(func() {
		for {
			p, err := e.d.Recv(ctx)
			if err != nil {
				failed <- err
				return
			}
			select {
			case received <- p:
			case <-ctx.Done():
				return
			}
		}
	})
	defer reader.Wait()
	defer cancel()

	// Only the server chaffs because the peer does; the client chaffs
	// because the user types (§9.1.1).
	var chaffArrived <-chan struct{}
	if e.ch.c != nil && e.cfg.Role == Server {
		chaffArrived = e.ch.c.ChaffArrived()
	}

	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	var payload []byte
	for {
		next, err := e.pass(payload)
		if err != nil {
			return err
		}
		payload = nil
		timer.Reset(time.Until(next))
		select {
		case <-parent.Done():
			return parent.Err()
		case err := <-failed:
			if parent.Err() != nil {
				return parent.Err()
			}
			return fmt.Errorf("ssp: receiving: %w", err)
		case payload = <-received:
		case <-chaffArrived:
			e.mu.Lock()
			e.ch.extend(time.Now(), serverLinger)
			e.mu.Unlock()
		case <-e.wake:
		case <-timer.C:
		}
	}
}

// pass handles one received payload, if there is one, sends whatever is
// due, and says when the next thing will be.
func (e *Endpoint[L, R]) pass(payload []byte) (time.Time, error) {
	e.mu.Lock()
	now := time.Now()
	var err error
	if payload != nil {
		err = e.receive(payload, now)
	}
	if err == nil {
		switch {
		case !e.ch.active(now):
			err = e.send(now)
		case e.ch.due(now):
			err = e.tick(now)
		}
		// Chaffing, between ticks: nothing goes until the next (§9.1.1).
	}
	next := e.nextWake(now)
	queue := e.queue
	e.queue = nil
	e.mu.Unlock()
	for _, o := range queue {
		// A failed send is a loss, and SSP recovers from losses (§6.3).
		if o.payload != nil {
			_ = e.d.Send(o.payload)
		} else {
			_ = e.ch.c.SendChaff(o.chaff)
		}
	}
	return next, err
}

// tick is one tick of the grid while chaffing (§9.1.1): whatever §6.3 has
// due, else an owed ack, early, since a datagram goes this tick anyway,
// else one CHAFF frame of this side's chaff size, which every datagram is
// padded to while chaffing, so that it looks like a keystroke or an echo.
func (e *Endpoint[L, R]) tick(now time.Time) error {
	before := len(e.queue)
	if err := e.send(now); err != nil {
		return err
	}
	if len(e.queue) == before && !e.ackDue.IsZero() {
		e.emit(now, nil)
	}
	if len(e.queue) == before {
		e.queue = append(e.queue, outgoing{chaff: e.ch.size})
	}
	e.ch.advance(now)
	return nil
}

// Set makes local the newest version of the local object. The endpoint
// keeps its own clone.
func (e *Endpoint[L, R]) Set(local L) {
	e.mu.Lock()
	if local.Equal(e.pending) {
		e.mu.Unlock()
		return
	}
	e.pending = local.Clone()
	if e.cfg.Role == Client {
		// Every input starts or extends the chaff (§9.1.1).
		e.ch.extend(time.Now(), clientLinger())
	}
	if e.pending.Equal(e.sent[e.latest]) {
		// Changed back to what was last sent: nothing to send after all.
		e.changeAt = time.Time{}
	} else if e.changeAt.IsZero() {
		e.changeAt = time.Now()
	}
	e.mu.Unlock()
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

// Remote is a clone of the newest version of the peer's object, and its
// version number.
func (e *Endpoint[L, R]) Remote() (R, uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.held[e.newest].Clone(), e.newest
}

// Acked is a clone of the newest local version the peer has acknowledged,
// and its number. The client throttles its input on it (§10.1): the next
// diff SSP sends starts there.
func (e *Endpoint[L, R]) Acked() (L, uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.sent[e.acked].Clone(), e.acked
}

// RemoteChanged is signalled, without blocking, whenever a newer remote
// version arrives. One signal may stand for several versions.
func (e *Endpoint[L, R]) RemoteChanged() <-chan struct{} {
	return e.changed
}

// Stats is what the endpoint knows about the path, for the client's
// "last contact" warning and for tests.
func (e *Endpoint[L, R]) Stats() Stats {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := Stats{SRTT: e.rtt.srtt, RTTVar: e.rtt.rttvar, RTO: e.rtt.rto(), LocalAcked: e.acked}
	if e.heard {
		s.LastHeard = e.lastHeard
	}
	return s
}

// Stats is a snapshot of an endpoint's view of the path.
type Stats struct {
	SRTT, RTTVar, RTO time.Duration
	// LastHeard is when the last authentic payload arrived; zero if none
	// has.
	LastHeard time.Time
	// LocalAcked is the newest local version the peer has acknowledged.
	LocalAcked uint64
}

// receive handles one payload from the peer (§7.2). Everything that can be
// refused about the datagram itself is checked before anything changes.
func (e *Endpoint[L, R]) receive(p []byte, now time.Time) error {
	d, err := parseDatagram(p, e.lim.chunk, e.lim.maxFragments)
	if err != nil {
		return err
	}
	if d.ack > e.latest {
		return protocolError("peer acknowledges version %d, but the newest sent is %d", d.ack, e.latest)
	}
	e.lastHeard, e.heard = now, true
	e.echo, e.echoAt, e.echoDue = d.ts, now, true
	if d.hasEcho {
		// The echo is our own timestamp plus the peer's hold time, so the
		// sample is the path's round trip alone; every datagram has a new
		// timestamp, so no sample is ambiguous and Karn's rule is not needed
		// [P §2.2].
		if r := time.Duration(e.clock(now)-d.echo) * time.Microsecond; r < bogusRTT {
			e.rtt.sample(r)
		}
	}
	if d.ack > e.acked {
		for v := range e.sent {
			if v < d.ack {
				delete(e.sent, v)
			}
		}
		e.acked, e.backoff = d.ack, 0
		if e.tx.active && e.instr.to <= e.acked {
			// The peer has it already; the rest of the transmission would
			// only be thrown away.
			e.tx.active = false
			e.lastData = now
		}
	}
	if d.frag == nil {
		return nil
	}
	instr, stale, err := e.re.add(d.frag)
	switch {
	case err != nil:
		return err
	case stale:
		// The peer sent again what this side has handled: it missed our
		// ack (§5 step 1).
		e.oweAck(now)
		return nil
	case instr == nil:
		return nil
	}
	return e.handle(instr, now)
}

// handle applies one complete instruction (§7.3), validating all of it
// before anything changes, so a refused instruction leaves held, newest
// and RemoteChanged exactly as they were.
func (e *Endpoint[L, R]) handle(b []byte, now time.Time) error {
	in, err := parseInstruction(b)
	if err != nil {
		return err
	}
	floor := max(e.floor, in.from)
	src, ok := e.held[in.from]
	if in.to <= e.newest || !ok {
		// Old, a duplicate, or (from an honest peer) reordered from below
		// the floor. Either way the peer is behind on our ack, which will
		// tell it newest.
		e.raiseFloor(floor)
		e.oweAck(now)
		return nil
	}
	diff, err := decodeBody(in.encoding, in.body, e.cfg.MaxRemoteBytes)
	if err != nil {
		return fmt.Errorf("version %d: %w", in.to, err)
	}
	next := src.Clone()
	if err := next.Apply(diff); err != nil {
		return fmt.Errorf("%w: version %d does not apply: %v", ErrProtocol, in.to, err)
	}
	e.held[in.to], e.newest = next, in.to
	e.raiseFloor(floor)
	e.oweAck(now)
	select {
	case e.changed <- struct{}{}:
	default:
	}
	return nil
}

// raiseFloor forgets every version the peer will never diff from again:
// those below the oldest from it has used, but for the newest. The peer
// diffs only from versions this side acked, so nothing at or above the
// floor is ever forgotten, and every honest instruction applies (§7.3).
func (e *Endpoint[L, R]) raiseFloor(floor uint64) {
	e.floor = floor
	for v := range e.held {
		if v < floor && v != e.newest {
			delete(e.held, v)
		}
	}
}

// oweAck makes sure an ack goes within the delayed-ack time, unless one is
// already due sooner.
func (e *Endpoint[L, R]) oweAck(now time.Time) {
	if due := now.Add(ackDelay); e.ackDue.IsZero() || due.Before(e.ackDue) {
		e.ackDue = due
	}
}

// send sends whatever is due now (§6.3).
func (e *Endpoint[L, R]) send(now time.Time) error {
	if e.tx.active {
		// Nothing else carries data until the transmission is out; acks
		// ride on its fragments, and one owed between bursts goes alone.
		if !now.Before(e.tx.at) {
			e.burst(now)
		}
		if e.ackOwed(now) {
			e.emit(now, nil)
		}
		return nil
	}
	changed := !e.changeAt.IsZero()
	mayMint := e.mayMint()
	newDue := changed && mayMint &&
		!now.Before(e.lastData.Add(e.rtt.frameInterval())) &&
		!now.Before(e.changeAt.Add(e.collection))
	rexDue := e.latest > e.acked && !now.Before(e.retransmitAt())
	switch {
	case newDue || rexDue && changed && mayMint:
		// A retransmission that finds a newer pending sends that instead;
		// the retransmit interval is never shorter than the frame interval,
		// so the frame limit has passed already.
		e.latest++
		e.sent[e.latest] = e.pending
		e.changeAt = time.Time{}
		if err := e.make(); err != nil {
			return err
		}
		e.transmit(now)
	case rexDue:
		if e.instr == nil || e.instr.from != e.acked || e.instr.to != e.latest {
			if err := e.make(); err != nil {
				return err
			}
		}
		e.transmit(now)
	case e.ackOwed(now) || !now.Before(e.lastAny.Add(heartbeat)):
		e.emit(now, nil)
	}
	if rexDue {
		e.backoff++
	}
	return nil
}

// mayMint says whether a new version may be numbered: not with Window
// versions outstanding, and not while the newest instruction has more
// than one fragment and is unacknowledged. That one is retransmitted under
// its own id until it completes; superseding it would strand the holes in
// the receiver's partial, and under continuous output and loss a large
// redraw might never complete (§6.3).
func (e *Endpoint[L, R]) mayMint() bool {
	if e.latest-e.acked >= Window {
		return false
	}
	return !(e.latest > e.acked && e.instr != nil && e.instr.to == e.latest && e.instr.count > 1)
}

func (e *Endpoint[L, R]) ackOwed(now time.Time) bool {
	return !e.ackDue.IsZero() && !now.Before(e.ackDue)
}

func (e *Endpoint[L, R]) retransmitAt() time.Time {
	return e.rtt.retransmitAt(e.lastData, e.lastHeard, e.backoff)
}

// make encodes the instruction from acked to latest, under a new id.
func (e *Endpoint[L, R]) make() error {
	from, to := e.acked, e.latest
	diff := e.sent[to].Diff(e.sent[from])
	encoding, body := encodeBody(diff)
	b := appendInstruction(make([]byte, 0, InstructionHeaderMax+len(body)), instruction{from: from, to: to, encoding: encoding, body: body})
	count := (len(b) + e.lim.chunk - 1) / e.lim.chunk
	if count > 1<<16-1 {
		return fmt.Errorf("ssp: the diff to version %d is %d bytes, too big to send", to, len(diff))
	}
	e.instr = &made{from: from, to: to, id: e.nextID, bytes: b, count: count}
	e.nextID++
	return nil
}

// transmit starts sending the newest instruction, from its first fragment.
func (e *Endpoint[L, R]) transmit(now time.Time) {
	e.tx = transmission{active: true}
	e.burst(now)
}

// burst sends the transmission's next Burst fragments.
func (e *Endpoint[L, R]) burst(now time.Time) {
	in := e.instr
	end := min(e.tx.next+Burst, in.count)
	for i := e.tx.next; i < end; i++ {
		chunk := in.bytes[i*e.lim.chunk : min((i+1)*e.lim.chunk, len(in.bytes))]
		e.emit(now, &fragment{id: in.id, index: uint16(i), count: uint16(in.count), chunk: chunk})
	}
	e.tx.next = end
	if end == in.count {
		e.tx.active = false
		e.lastData = now
		return
	}
	e.tx.at = now.Add(e.rtt.frameInterval())
}

// emit queues one datagram carrying frag, or an ack if frag is nil. Every
// datagram carries the ack and, once, the echo.
func (e *Endpoint[L, R]) emit(now time.Time, frag *fragment) {
	d := datagram{ts: e.clock(now), ack: e.newest, frag: frag}
	if e.echoDue {
		// Adding the hold keeps delayed acks and frame pacing out of the
		// peer's sample [P §2.2].
		d.echo, d.hasEcho = e.echo+uint32(now.Sub(e.echoAt).Microseconds()), true
		e.echoDue = false
	}
	e.pad(&d, now)
	e.queue = append(e.queue, outgoing{payload: appendDatagram(make([]byte, 0, e.cfg.MaxPayload), d)})
	e.ackDue = time.Time{}
	e.lastAny = now
}

// pad sets d's padding so that the sealed plaintext, the frame overhead
// below SSP plus the whole datagram, is as long as §9.2 says: this side's
// floor, Padmé above it, capped at the most the layer below carries. Acks
// and heartbeats are padded like data, so size does not tell them apart.
func (e *Endpoint[L, R]) pad(d *datagram, now time.Time) {
	floor := e.padFloor()
	if e.ch.active(now) {
		// While chaffing, every datagram is at least the chaff's size.
		floor = max(floor, e.ch.size)
	}
	d.padded, d.pad = true, 0
	u := e.cfg.FrameOverhead + datagramLen(*d)
	d.pad = paddedLen(u, floor, e.cfg.FrameOverhead+e.cfg.MaxPayload) - u
}

// padFloor is this side's F (§9.2) when it is not chaffing.
func (e *Endpoint[L, R]) padFloor() int {
	if e.cfg.Role == Server {
		return serverPadFloor
	}
	return clientPadFloor
}

// chaffSize is the size of this side's chaff, and its floor while it
// chaffs (§9.1.1).
func (e *Endpoint[L, R]) chaffSize() int {
	if e.cfg.Role == Server {
		return serverChaffSize
	}
	return clientChaffSize
}

// nextWake is when send next has something to do, short of a payload
// arriving or Set. While chaffing that is the next tick, which comes far
// more often than anything else falls due (§9.1.1).
func (e *Endpoint[L, R]) nextWake(now time.Time) time.Time {
	if e.ch.active(now) {
		return e.ch.next
	}
	next := e.lastAny.Add(heartbeat)
	at := func(t time.Time) {
		if t.Before(next) {
			next = t
		}
	}
	if !e.ackDue.IsZero() {
		at(e.ackDue)
	}
	if e.tx.active {
		at(e.tx.at)
		return next
	}
	if !e.changeAt.IsZero() && e.mayMint() {
		t := e.changeAt.Add(e.collection)
		if f := e.lastData.Add(e.rtt.frameInterval()); f.After(t) {
			t = f
		}
		at(t)
	}
	if e.latest > e.acked {
		at(e.retransmitAt())
	}
	return next
}

// clock is the endpoint's timestamp: microseconds since it was made, mod
// 2^32. That wraps after 71 minutes, far beyond any round trip or hold, and
// all arithmetic on it is mod 2^32 (§3).
func (e *Endpoint[L, R]) clock(now time.Time) uint32 {
	return uint32(now.Sub(e.epoch).Microseconds())
}
