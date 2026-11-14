package transport

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"net/netip"
	"time"

	"github.com/danielbodart/mosey/internal/handshake"
)

// Conn is one end of an established, authenticated connection.
//
// Send and Recv may be called from different goroutines; each must be
// called from only one at a time.
type Conn struct {
	e      *engine
	server bool

	hash  [32]byte
	epoch uint64
	sid   [16]byte

	// The key sets of transport.md §6.1, and the current epoch's root.
	cur, next, prev *keyset
	prevUntil       time.Time
	root            [32]byte

	// A rekey this side started: the KEM key, the INIT bodies it resends,
	// and when it last sent them.
	rekey      *handshake.RekeyInitiator
	rekeyParts [2][]byte
	rekeySent  time.Time
	// The answer this side gave to the peer's INIT, until promotion.
	answer *rekeyAnswer
	// awaiting is an initiator's wait for a packet under its new keys,
	// which it asks for with KEEPALIVE(answer requested) every RekeyRetry.
	awaiting  bool
	awaitSent time.Time
	slot      initSlot
	overdue   bool

	// The client sends to one address and never changes it (§7.1).
	serverAddr netip.AddrPort
	// The client's handshake, until confirmed.
	hs *clientHandshake

	// The server's paths (§7.3): the validated peer, if any, and at most
	// one candidate being challenged.
	peer netip.AddrPort
	cand *candidate

	listener *Listener

	recvq  chan []byte
	events chan Event
	wake   chan struct{}
	done   chan struct{}
	closed bool
	err    error
	stats  Stats
}

type rekeyAnswer struct {
	init [32]byte // HASH(idx_I' || pk_I) of the INIT answered
	resp []byte
	root [32]byte
}

// candidate is an address the server has seen an authentic, newest packet
// from and is challenging (D21).
type candidate struct {
	addr       netip.AddrPort
	token      [8]byte
	recv, sent int
	born, next time.Time
	interval   time.Duration
}

// allow accounts for sending n bytes to the candidate, within 3x what came
// from it (RFC 9000 §8.1).
func (c *candidate) allow(n int) bool {
	if c.sent+n > AmplificationFactor*c.recv {
		return false
	}
	c.sent += n
	return true
}

var (
	keepaliveAnswer = []byte{0x01}
	keepaliveNone   = []byte{0x00}
)

func newConn(e *engine, server bool, cur *keyset, root, hash *[32]byte) *Conn {
	c := &Conn{
		e: e, server: server, cur: cur, root: *root, hash: *hash,
		recvq:  make(chan []byte, recvQueue),
		events: make(chan Event, eventQueue),
		wake:   make(chan struct{}, 1),
		done:   make(chan struct{}),
	}
	clear(root[:])
	return c
}

// receive handles a data packet routed to this connection by its index.
// The caller holds the lock. Nothing changes until the packet has
// authenticated (transport.md §5).
func (c *Conn) receive(pkt []byte, from netip.AddrPort, idx uint32) {
	if c.closed {
		c.e.drop(UnknownIndex, from, "closed connection")
		return
	}
	ks := c.lookup(idx)
	if ks == nil {
		c.e.drop(UnknownIndex, from, "no live keys for the index")
		return
	}
	plain, counter, why, ok := ks.open(pkt)
	if !ok {
		c.e.drop(why, from, "data packet")
		if ks.failures >= MaxFailedOpens {
			c.shutdown(errForgeries)
		}
		return
	}

	// Authentic: only now does anything move.
	top, seen := ks.window.Top()
	newest := !seen || counter > top
	ks.window.Commit(counter)
	if ks == c.next {
		c.promote()
	}
	if ks == c.cur && c.awaiting {
		c.awaiting = false
		c.emit(Rekeyed{Epoch: c.epoch})
	}
	if ks == c.cur && c.hs != nil && c.hs.established {
		c.hs.confirm(c)
	}
	if c.server && ks == c.cur && newest {
		c.onAuthentic(from, len(pkt))
	}
	c.act(ks, plain, from)
}

// lookup finds the key set an index names. prev counts only until it
// expires, even if the timer that wipes it has not yet run.
func (c *Conn) lookup(idx uint32) *keyset {
	switch {
	case c.cur != nil && c.cur.local == idx:
		return c.cur
	case c.next != nil && c.next.local == idx:
		return c.next
	case c.prev != nil && c.prev.local == idx && time.Now().Before(c.prevUntil):
		return c.prev
	}
	return nil
}

// act does what an authentic frame asks (transport.md §4.2). A body of the
// wrong length, and an unknown kind, are ignored: only the peer could have
// sealed them, and ignoring is what lets a later slice add kinds.
func (c *Conn) act(ks *keyset, plain []byte, from netip.AddrPort) {
	kind, body := Kind(plain[0]), plain[1:]
	switch kind {
	case KindTerminal:
		select {
		case c.recvq <- body:
		default:
			c.stats.QueueFull++
		}
	case KindRekeyInit1, KindRekeyInit2:
		// Rekey frames count only under the current epoch: a delayed INIT
		// from the last one would derive from the wrong root and wedge the
		// next rekey [S1 §1.3].
		if ks == c.cur && len(body) == handshake.RekeyPartSize {
			if parts, ok := c.slot.add(int(kind-KindRekeyInit1), body); ok {
				c.onRekeyInit(parts)
			}
		}
	case KindRekeyResp:
		if ks == c.cur && len(body) == handshake.RekeyRespSize {
			c.onRekeyResp(body)
		}
	case KindKeepalive:
		// One 31-byte answer per 31-byte request: it amplifies nothing.
		if len(body) == 1 && body[0] == keepaliveAnswer[0] {
			c.sendFrame(KindKeepalive, keepaliveNone)
		}
	case KindPathChallenge:
		if len(body) == 8 {
			c.sendFrame(KindPathResponse, body)
		}
	case KindPathResponse:
		if c.server && len(body) == 8 {
			c.onPathResponse(body, from)
		}
	case KindRevoked:
		if !c.server {
			c.onRevoked(body)
		}
	case KindEnd:
		if len(body) == 1 {
			c.e.log.Info("the peer ended the session", "reason", EndReason(body[0]))
			c.emit(Ended{Reason: EndReason(body[0])})
			c.shutdown(ErrEnded)
		}
	}
}

// sendFrame seals a control frame under the current keys and routes it. A
// control frame the limits hold back is simply not sent: each is resent on
// its own timer or not needed.
func (c *Conn) sendFrame(kind Kind, body []byte) {
	if c.cur == nil {
		return
	}
	pkt, err := c.cur.seal(kind, body)
	if err != nil {
		c.shutdown(err)
		return
	}
	if !c.route(pkt) {
		c.stats.Blocked++
	}
}

// route sends a sealed packet where this side sends (transport.md §7.1,
// §7.3): the client to the server's one address; the server to its
// validated peer, and a copy to a candidate within its budget, so a client
// that really has moved is not kept waiting a round trip. It reports
// whether the packet went anywhere.
func (c *Conn) route(pkt []byte) bool {
	if !c.server {
		c.e.send(pkt, c.serverAddr)
		return true
	}
	sent := false
	if c.peer.IsValid() {
		c.e.send(pkt, c.peer)
		sent = true
	}
	if c.cand != nil && c.cand.allow(len(pkt)) {
		c.e.send(pkt, c.cand.addr)
		sent = true
	}
	return sent
}

// emit reports an event; if the reader is behind, the oldest is dropped to
// make room.
func (c *Conn) emit(ev Event) {
	for {
		select {
		case c.events <- ev:
			return
		default:
		}
		select {
		case <-c.events:
		default:
		}
	}
}

func (c *Conn) poke() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// --- Rekey (transport.md §6) ---

// maybeRekey starts a rekey once the current keys are old enough or have
// sealed enough, checked whenever this side sends: never on idleness (D20).
func (c *Conn) maybeRekey(now time.Time) {
	if c.rekey != nil || c.next != nil || c.awaiting {
		return // at most one rekey in flight, in either role [S1 §1.3]
	}
	after := RekeyAfter
	if c.server {
		after = serverRekeyAfter
	}
	if now.Sub(c.cur.installed) < after && c.cur.sendCounter < RekeyAfterMessages {
		return
	}
	idx := c.e.table.reserve()
	ri, parts, err := handshake.StartRekey(c.root, idx)
	if err != nil {
		c.e.table.free(idx)
		c.e.log.Error("starting a rekey", "err", err)
		return
	}
	c.rekey, c.rekeyParts, c.rekeySent = ri, parts, now
	c.sendFrame(KindRekeyInit1, parts[0])
	c.sendFrame(KindRekeyInit2, parts[1])
	c.poke()
}

func (c *Conn) onRekeyInit(parts [2][]byte) {
	now := time.Now()
	if now.Sub(c.cur.installed) < RekeyMinEpochAge {
		return // the floor: a genuine initiator resends in a second
	}
	if c.awaiting {
		return // finish confirming our own rotation first
	}
	idxI, pk, err := handshake.JoinRekeyInit(parts)
	if err != nil {
		return
	}
	init := initHash(idxI, pk)
	if c.answer != nil && c.answer.init == init {
		c.sendFrame(KindRekeyResp, c.answer.resp) // a resend: answer again, derive nothing
		return
	}
	if c.next != nil {
		return // a different INIT while our answer is unconfirmed
	}
	if c.rekey != nil {
		if !c.server {
			return // both started: the client's rekey wins
		}
		c.abandonRekey()
	}
	idxR := c.e.table.reserve()
	resp, keys, err := handshake.RespondRekey(c.root, parts, idxR)
	if err != nil {
		c.e.table.free(idxR)
		return
	}
	c.next = newKeyset(&keys, now)
	c.e.table.set(idxR, c)
	c.answer = &rekeyAnswer{init: init, resp: resp, root: keys.Root}
	keys.Wipe()
	c.sendFrame(KindRekeyResp, resp)
}

func initHash(idxI uint32, pk []byte) [32]byte {
	d := sha256.New()
	d.Write(binary.LittleEndian.AppendUint32(nil, idxI))
	d.Write(pk)
	var h [32]byte
	d.Sum(h[:0])
	return h
}

func (c *Conn) onRekeyResp(body []byte) {
	if c.rekey == nil {
		return
	}
	keys, err := c.rekey.Finish(body)
	if err != nil {
		return
	}
	now := time.Now()
	nk := newKeyset(&keys, now)
	c.e.table.set(nk.local, c)
	c.rekey, c.rekeyParts = nil, [2][]byte{}
	c.rotate(nk, &keys.Root, now)
	// Ask for confirmation, and keep asking: without it an idle responder
	// whose first keepalive was lost would never promote [S1 §1.3].
	c.awaiting, c.awaitSent = true, now
	c.sendFrame(KindKeepalive, keepaliveAnswer)
}

// promote makes the responder's next keys current, on the first packet
// that opens under them.
func (c *Conn) promote() {
	root := c.answer.root
	c.rotate(c.next, &root, time.Now())
	clear(c.answer.root[:])
	c.next, c.answer = nil, nil
	c.emit(Rekeyed{Epoch: c.epoch})
}

// rotate installs nk as the current keys: the old current become prev,
// receive-only for KeepPrevFor, and the old prev and root are erased.
func (c *Conn) rotate(nk *keyset, root *[32]byte, now time.Time) {
	c.dropPrev()
	c.prev, c.prevUntil = c.cur, now.Add(KeepPrevFor)
	c.cur = nk
	c.root = *root
	clear(root[:])
	c.slot.clear()
	c.epoch++
	c.overdue = false
	c.poke()
}

func (c *Conn) dropPrev() {
	if c.prev != nil {
		c.e.table.free(c.prev.local)
		c.prev.wipe()
		c.prev = nil
	}
}

func (c *Conn) abandonRekey() {
	c.e.table.free(c.rekey.Index())
	c.rekey.Wipe()
	c.rekey, c.rekeyParts = nil, [2][]byte{}
}

// initSlot is the responder's one reassembly slot for the two halves of a
// REKEY_INIT (transport.md §6.4): at most 2 × 612 bytes, whatever the peer
// sends.
type initSlot struct {
	idx  uint32
	half [2][]byte
}

// add files one half. A half naming another INIT replaces the slot's
// contents. When both halves of one INIT are in, it hands them over and
// empties the slot.
func (s *initSlot) add(which int, body []byte) ([2][]byte, bool) {
	idx := binary.LittleEndian.Uint32(body)
	if idx != s.idx {
		s.clear()
		s.idx = idx
	}
	s.half[which] = append(s.half[which][:0], body...)
	if s.half[0] == nil || s.half[1] == nil {
		return [2][]byte{}, false
	}
	parts := s.half
	s.half = [2][]byte{}
	s.idx = 0
	return parts, true
}

func (s *initSlot) clear() { *s = initSlot{} }

// --- Paths (transport.md §7.3, D21) ---

// onAuthentic is the server's bookkeeping for an authentic packet under the
// current keys that raised the window's top: a packet from somewhere new
// makes that address the candidate, which is challenged at once.
func (c *Conn) onAuthentic(from netip.AddrPort, size int) {
	switch {
	case from == c.peer:
	case c.cand != nil && from == c.cand.addr:
		c.cand.recv += size
	default:
		c.newCandidate(from, size, 0)
	}
}

func (c *Conn) newCandidate(addr netip.AddrPort, recv, sent int) {
	now := time.Now()
	c.cand = &candidate{addr: addr, recv: recv, sent: sent, born: now, interval: challengeFirst}
	if _, err := rand.Read(c.cand.token[:]); err != nil {
		panic(err) // crypto/rand does not fail (Go 1.24+)
	}
	c.challenge(now)
}

// challenge sends the candidate its PATH_CHALLENGE, within its budget, and
// schedules the next resend.
func (c *Conn) challenge(now time.Time) {
	cand := c.cand
	cand.next = now.Add(cand.interval)
	cand.interval = min(2*cand.interval, challengeCap)
	pkt, err := c.cur.seal(KindPathChallenge, cand.token[:])
	if err != nil {
		c.shutdown(err)
		return
	}
	if cand.allow(len(pkt)) {
		c.e.send(pkt, cand.addr)
	} else {
		c.stats.Blocked++
	}
	c.poke()
}

// onPathResponse validates the candidate if the response carries its token
// and came from its address. Stricter than QUIC: from anywhere else, a
// relayed challenge would validate a victim (transport.md §7.3).
func (c *Conn) onPathResponse(token []byte, from netip.AddrPort) {
	cand := c.cand
	if cand == nil || from != cand.addr || subtle.ConstantTimeCompare(token, cand.token[:]) != 1 {
		return
	}
	old := c.peer
	c.peer = cand.addr
	c.cand = nil
	c.e.log.Info("the client moved", "from", old, "to", c.peer)
	c.emit(PeerChanged{From: old, To: c.peer})
}

// --- Revocation (D26), the client's side ---

// onRevoked reads a REVOKED body (transport.md §8.3) and ends the
// connection, saying who took it over and when. A malformed body is
// ignored like any other.
func (c *Conn) onRevoked(body []byte) {
	by, at, ok := parseRevoked(body)
	if !ok {
		return
	}
	c.emit(Revoked{By: by, At: at})
	c.shutdown(ErrRevoked)
}

func revokedBody(at time.Time, by netip.AddrPort) []byte {
	b := binary.LittleEndian.AppendUint64(nil, uint64(at.UnixMilli()))
	a := by.Addr().Unmap()
	if a.Is4() {
		b = append(b, 4)
	} else {
		b = append(b, 6)
	}
	b = append(b, a.AsSlice()...)
	return binary.LittleEndian.AppendUint16(b, by.Port())
}

func parseRevoked(b []byte) (netip.AddrPort, time.Time, bool) {
	if len(b) < 9 {
		return netip.AddrPort{}, time.Time{}, false
	}
	at := time.UnixMilli(int64(binary.LittleEndian.Uint64(b)))
	var size int
	switch b[8] {
	case 4:
		size = 4
	case 6:
		size = 16
	default:
		return netip.AddrPort{}, time.Time{}, false
	}
	if len(b) != 9+size+2 {
		return netip.AddrPort{}, time.Time{}, false
	}
	addr, _ := netip.AddrFromSlice(b[9 : 9+size])
	if addr.Is4In6() {
		// An IPv4 address has its own family; the sender never maps one.
		return netip.AddrPort{}, time.Time{}, false
	}
	return netip.AddrPortFrom(addr, binary.LittleEndian.Uint16(b[9+size:])), at, true
}

// --- Timers ---

// run drives the connection's timers until it closes: resends of the
// handshake, the rekey and its confirmation, and path challenges, and the
// end of prev's grace. Every timer is the time package's, so under
// testing/synctest it is virtual.
func (c *Conn) run() {
	t := time.NewTimer(time.Hour)
	defer t.Stop()
	for {
		c.e.lock()
		if c.closed {
			c.e.unlock()
			return
		}
		now := time.Now()
		c.tick(now)
		next, ok := c.nextDeadline()
		c.e.unlock()
		if ok {
			t.Reset(max(next.Sub(now), 0))
		} else {
			t.Stop()
		}
		select {
		case <-t.C:
		case <-c.wake:
		case <-c.done:
			return
		}
	}
}

// tick does whatever is due. The caller holds the lock.
func (c *Conn) tick(now time.Time) {
	if c.hs != nil {
		c.hs.tick(c, now)
		if c.closed {
			return
		}
	}
	if c.prev != nil && !now.Before(c.prevUntil) {
		c.dropPrev()
	}
	if c.rekey != nil && now.Sub(c.rekeySent) >= RekeyRetry {
		c.rekeySent = now
		c.sendFrame(KindRekeyInit1, c.rekeyParts[0])
		c.sendFrame(KindRekeyInit2, c.rekeyParts[1])
	}
	if c.awaiting && now.Sub(c.awaitSent) >= RekeyRetry {
		c.awaitSent = now
		c.sendFrame(KindKeepalive, keepaliveAnswer)
	}
	if c.cand != nil {
		if now.Sub(c.cand.born) >= candidateLife {
			c.cand = nil
		} else if !now.Before(c.cand.next) {
			c.challenge(now)
		}
	}
}

func (c *Conn) nextDeadline() (time.Time, bool) {
	var next time.Time
	consider := func(t time.Time) {
		if next.IsZero() || t.Before(next) {
			next = t
		}
	}
	if c.hs != nil {
		consider(c.hs.next)
		consider(c.hs.deadline)
	}
	if c.prev != nil {
		consider(c.prevUntil)
	}
	if c.rekey != nil {
		consider(c.rekeySent.Add(RekeyRetry))
	}
	if c.awaiting {
		consider(c.awaitSent.Add(RekeyRetry))
	}
	if c.cand != nil {
		consider(c.cand.next)
		consider(c.cand.born.Add(candidateLife))
	}
	return next, !next.IsZero()
}

// shutdown ends the connection: every key and the root are erased, Recv
// and Send fail with err from now on, and its indices are freed (a
// revocation keeps them, pointing at its tombstone). The caller holds the
// lock.
func (c *Conn) shutdown(err error) {
	if c.closed {
		return
	}
	c.closed, c.err = true, err
	for _, ks := range []*keyset{c.cur, c.next, c.prev} {
		if ks != nil {
			if c.e.table.get(ks.local) == c {
				c.e.table.free(ks.local)
			}
			ks.wipe()
		}
	}
	c.cur, c.next, c.prev = nil, nil, nil
	if c.rekey != nil {
		c.abandonRekey()
	}
	if c.answer != nil {
		clear(c.answer.root[:])
		c.answer = nil
	}
	clear(c.root[:])
	c.slot.clear()
	c.cand = nil
	if c.hs != nil {
		c.hs.fail(err)
	}
	close(c.done)
	if c.listener != nil {
		delete(c.listener.conns, c)
	} else {
		c.e.sock.close()
	}
}
