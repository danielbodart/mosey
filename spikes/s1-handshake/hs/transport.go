package hs

import (
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/netip"
	"time"
)

// Transport packet:
//
//	0      1          5                13
//	+------+----------+----------------+---------------------------+
//	| 0x04 | rcv idx  | counter (u64)  | AEAD(frame) + 16-byte tag |
//	+------+----------+----------------+---------------------------+
//
// The 13-byte header is the AEAD associated data; the nonce is the explicit
// counter. Each direction has its own key, so (key, nonce) never repeats as
// long as the sender's counter never repeats -- and counters live only in
// memory (D8): a process that loses its state also loses its keys.
//
// The receiver index is chosen by the receiver (as in WireGuard): it lets one
// UDP socket serve many sessions, lets a packet be routed before the source
// address is trusted (roaming, NAT rebinding, O6), and changes on every
// rekey so a passive observer cannot link epochs by index.
const (
	dataHeaderSize = 13
	DataOverhead   = dataHeaderSize + tagSize // 29 bytes

	frameApp           byte = 0
	frameRekeyInit     byte = 1
	frameRekeyResp     byte = 2
	frameKeepalive     byte = 3 // empty; confirms new keys after a rekey
	framePathChallenge byte = 4 // 8 random bytes (RFC 9000 §8.2 style)
	framePathResponse  byte = 5 // echo of a challenge

	// antiAmplification: before an address is validated, send at most this
	// many times the bytes received from it (RFC 9000 §8.1 uses 3).
	antiAmplification = 3
)

var (
	ErrReplay  = errors.New("hs: replayed or too-old counter")
	ErrNoKey   = errors.New("hs: unknown receiver index")
	ErrExpired = errors.New("hs: keys exhausted; rekey required")
)

// Config holds rekey policy. Values are spike defaults (see FINDINGS).
type Config struct {
	RekeyAfterTime      time.Duration
	RekeyAfterMessages  uint64
	RejectAfterMessages uint64
	RekeyRetry          time.Duration
	KeepPrevFor         time.Duration
	Now                 func() time.Time
}

func DefaultConfig() Config {
	return Config{
		RekeyAfterTime:      2 * time.Minute, // WireGuard's REKEY_AFTER_TIME
		RekeyAfterMessages:  1 << 48,
		RejectAfterMessages: 1<<64 - 1<<13 - 1,
		RekeyRetry:          1 * time.Second,
		KeepPrevFor:         10 * time.Second,
		Now:                 time.Now,
	}
}

type keyset struct {
	localIdx, remoteIdx uint32
	sendKey, recvKey    [32]byte
	sendCtr             uint64
	win                 replayWindow
	born                time.Time
}

type rekeyPending struct {
	sk       hpke.PrivateKey
	pk       []byte
	localIdx uint32
	frame    []byte
	sent     time.Time
}

type rekeyResp struct {
	pkHash   [32]byte
	frame    []byte
	nextRoot [32]byte
}

// Stats counts events, for tests and the FINDINGS measurements.
type Stats struct {
	Sent, Received, DroppedAuth, DroppedReplay, DroppedIdx uint64
	Rekeys, Roams                                          uint64
}

// Session is the post-handshake transport state of one peer.
type Session struct {
	cfg       Config
	initiator bool // handshake role (true = client)

	cur, prev, next *keyset
	prevExpires     time.Time
	root            [32]byte

	// Handshake is the final transcript hash h: mosey's channel binding
	// (the analogue of SSH's exchange hash), for S3's provenance envelope.
	Handshake [32]byte

	// Peer is where we send. It follows the newest authenticated packet;
	// until the address is validated, sends to it are capped (AllowSend).
	Peer             netip.AddrPort
	validated        bool
	lastValidated    netip.AddrPort
	amplifyBudget    int
	challenge        [8]byte
	challengeOut     bool
	challengeSent    time.Time
	keysProveReceipt bool // B2/B3: first packet proves msg2 was received

	confirmed bool           // first packet from the peer authenticated
	onConfirm func(*Session) // B3: consume the credential
	idxHook   func(uint32)   // dispatcher: register a new local index
	revoked   bool

	pend         *rekeyPending
	resp         *rekeyResp
	awaitConfirm bool // rekey initiator rotated; peer has not yet used new keys
	lastKA       time.Time
	out          [][]byte
	Stats        Stats
}

// newSession copies the keys and erases the caller's copies.
func newSession(cfg Config, initiator bool, localIdx, remoteIdx uint32, i2r, r2i, root *[32]byte) *Session {
	if cfg.Now == nil {
		cfg = DefaultConfig()
	}
	ks := &keyset{localIdx: localIdx, remoteIdx: remoteIdx, born: cfg.Now()}
	if initiator {
		ks.sendKey, ks.recvKey = *i2r, *r2i
	} else {
		ks.sendKey, ks.recvKey = *r2i, *i2r
	}
	s := &Session{cfg: cfg, initiator: initiator, cur: ks, root: *root, confirmed: initiator}
	clear(i2r[:])
	clear(r2i[:])
	clear(root[:])
	return s
}

// SetPeer sets a peer address we already trust (the client's configured
// server address; tests).
func (s *Session) SetPeer(a netip.AddrPort) {
	s.Peer, s.validated, s.lastValidated = a, true, a
}

// setUnvalidatedPeer is used by the server for the msg1 source address.
func (s *Session) setUnvalidatedPeer(a netip.AddrPort) {
	s.Peer, s.validated = a, false
}

// Validated reports whether Peer has proven it receives our packets.
func (s *Session) Validated() bool { return s.validated }

// AllowSend accounts for sending n bytes to Peer. Before the address is
// validated it enforces the anti-amplification budget; a false return
// means "don't send now" (SSP will retransmit state later).
func (s *Session) AllowSend(n int) bool {
	if s.validated {
		return true
	}
	if s.amplifyBudget >= n {
		s.amplifyBudget -= n
		return true
	}
	return false
}

func (s *Session) markValidated() {
	s.validated = true
	s.lastValidated = s.Peer
	s.challengeOut = false
}

func (s *Session) sendChallenge() {
	rand.Read(s.challenge[:])
	s.challengeOut = true
	s.challengeSent = s.cfg.Now()
	if pkt, err := s.sealFrame(framePathChallenge, s.challenge[:]); err == nil {
		s.out = append(s.out, pkt)
	}
}

// Revoke wipes every key and makes the session dead: later packets get
// ErrNoKey and Seal fails. Used for exclusive attach and losing B3 races.
func (s *Session) Revoke() {
	for _, k := range []*keyset{s.cur, s.prev, s.next} {
		if k != nil {
			s.wipeKeyset(k)
		}
	}
	s.cur, s.prev, s.next = nil, nil, nil
	clear(s.root[:])
	if s.resp != nil {
		clear(s.resp.nextRoot[:])
	}
	s.pend, s.resp = nil, nil
	s.revoked = true
}

func (s *Session) Revoked() bool { return s.revoked }

// LocalIndex is the receiver index the peer currently uses for us.
func (s *Session) LocalIndex() uint32 {
	if s.cur == nil {
		return 0
	}
	return s.cur.localIdx
}

// Outbox returns and clears control packets (rekey) that must be sent.
func (s *Session) Outbox() [][]byte {
	o := s.out
	s.out = nil
	return o
}

func randIndex() uint32 {
	var b [4]byte
	for {
		rand.Read(b[:])
		if v := binary.LittleEndian.Uint32(b[:]); v != 0 {
			return v
		}
	}
}

func (s *Session) sealFrame(kind byte, body []byte) ([]byte, error) {
	ks := s.cur
	if ks == nil {
		return nil, ErrNoKey
	}
	if ks.sendCtr >= s.cfg.RejectAfterMessages {
		return nil, ErrExpired
	}
	pkt := make([]byte, dataHeaderSize, dataHeaderSize+1+len(body)+tagSize)
	pkt[0] = TypeData
	binary.LittleEndian.PutUint32(pkt[1:], ks.remoteIdx)
	binary.LittleEndian.PutUint64(pkt[5:], ks.sendCtr)
	pt := make([]byte, 0, 1+len(body))
	pt = append(pt, kind)
	pt = append(pt, body...)
	pkt = newAEAD(ks.sendKey[:]).Seal(pkt, nonce(ks.sendCtr), pt, pkt[:dataHeaderSize])
	ks.sendCtr++
	s.Stats.Sent++
	return pkt, nil
}

// Seal encrypts an application frame. It may queue a rekey packet in the
// outbox if policy says so.
func (s *Session) Seal(app []byte) ([]byte, error) {
	s.maybeRekey()
	return s.sealFrame(frameApp, app)
}

// Tick drives timers (rekey and keepalive retransmission, path challenge
// retransmission, previous-key expiry).
func (s *Session) Tick() {
	if s.cur == nil {
		return
	}
	now := s.cfg.Now()
	if s.prev != nil && now.After(s.prevExpires) {
		s.wipeKeyset(s.prev)
		s.prev = nil
	}
	if s.challengeOut && now.Sub(s.challengeSent) >= s.cfg.RekeyRetry {
		s.sendChallenge()
	}
	s.maybeRekey()
}

func (s *Session) maybeRekey() {
	if s.cur == nil {
		return
	}
	now := s.cfg.Now()
	if s.awaitConfirm {
		// We rotated on REKEY_RESP; keep telling the responder to promote
		// until a packet under the new keys comes back.
		if now.Sub(s.lastKA) >= s.cfg.RekeyRetry {
			s.sendKeepalive()
		}
		return
	}
	if s.next != nil {
		return // responder: our previous answer is not yet confirmed
	}
	if s.pend != nil {
		if now.Sub(s.pend.sent) >= s.cfg.RekeyRetry {
			s.pend.sent = now
			if pkt, err := s.sealFrame(frameRekeyInit, s.pend.frame); err == nil {
				s.out = append(s.out, pkt)
			}
		}
		return
	}
	if now.Sub(s.cur.born) < s.cfg.RekeyAfterTime && s.cur.sendCtr < s.cfg.RekeyAfterMessages {
		return
	}
	s.StartRekey()
}

func (s *Session) sendKeepalive() {
	s.lastKA = s.cfg.Now()
	if pkt, err := s.sealFrame(frameKeepalive, []byte{1}); err == nil {
		s.out = append(s.out, pkt)
	}
}

// StartRekey begins an in-band hybrid rekey (exported for tests). It is a
// no-op while another rekey is in progress in either role.
func (s *Session) StartRekey() {
	if s.cur == nil || s.pend != nil || s.next != nil || s.awaitConfirm {
		return
	}
	sk, pk, err := kemGenerate()
	if err != nil {
		return
	}
	p := &rekeyPending{sk: sk, pk: pk, localIdx: randIndex(), sent: s.cfg.Now()}
	p.frame = binary.LittleEndian.AppendUint32(nil, p.localIdx)
	p.frame = append(p.frame, pk...)
	s.pend = p
	if s.idxHook != nil {
		s.idxHook(p.localIdx)
	}
	if pkt, err := s.sealFrame(frameRekeyInit, p.frame); err == nil {
		s.out = append(s.out, pkt)
	}
}

func (s *Session) lookup(idx uint32) *keyset {
	switch {
	case s.cur != nil && s.cur.localIdx == idx:
		return s.cur
	case s.next != nil && s.next.localIdx == idx:
		return s.next
	case s.prev != nil && s.prev.localIdx == idx && !s.cfg.Now().After(s.prevExpires):
		return s.prev
	}
	return nil
}

// Open authenticates and decrypts one datagram received from `from`.
// It returns the application payload (nil for control frames). On any
// error the session state is unchanged except for drop counters.
func (s *Session) Open(pkt []byte, from netip.AddrPort) ([]byte, error) {
	if len(pkt) < DataOverhead+1 || pkt[0] != TypeData {
		return nil, ErrMalformed
	}
	ks := s.lookup(binary.LittleEndian.Uint32(pkt[1:]))
	if ks == nil {
		s.Stats.DroppedIdx++
		return nil, ErrNoKey
	}
	ctr := binary.LittleEndian.Uint64(pkt[5:])
	if ctr >= s.cfg.RejectAfterMessages || !ks.win.check(ctr) {
		s.Stats.DroppedReplay++
		return nil, ErrReplay
	}
	pt, err := newAEAD(ks.recvKey[:]).Open(nil, nonce(ctr), pkt[dataHeaderSize:], pkt[:dataHeaderSize])
	if err != nil {
		s.Stats.DroppedAuth++
		return nil, ErrAuth
	}
	// ---- authenticated from here on: now, and only now, mutate ----
	ks.win.commit(ctr)
	s.Stats.Received++
	if ks == s.next {
		s.promoteNext()
	}
	if ks == s.cur && s.awaitConfirm {
		s.awaitConfirm = false // the responder is using the new keys
	}
	first := !s.confirmed
	s.confirmed = true
	if from.IsValid() {
		if first && from == s.Peer && s.keysProveReceipt {
			// B2/B3: these keys depend on msg2, which went only to Peer.
			s.markValidated()
		}
		// Roaming: follow the source address of the newest authenticated
		// packet of the current epoch (reordered old packets don't move
		// us). A new address must prove it receives before we send more
		// than antiAmplification x what it sent us.
		if ks == s.cur && ctr == ks.win.top && from != s.Peer {
			if s.Peer.IsValid() {
				s.Stats.Roams++
			}
			s.Peer = from
			if from == s.lastValidated {
				s.validated = true
			} else {
				s.validated = false
				s.amplifyBudget = antiAmplification * len(pkt)
				s.sendChallenge()
			}
		} else if from == s.Peer && !s.validated {
			s.amplifyBudget += antiAmplification * len(pkt)
			if first && !s.challengeOut {
				s.sendChallenge() // B1: keys alone don't prove receipt
			}
		}
	}
	if first && s.onConfirm != nil {
		cb := s.onConfirm
		s.onConfirm = nil
		cb(s)
	}
	switch pt[0] {
	case frameApp:
		return pt[1:], nil
	case frameRekeyInit, frameRekeyResp:
		// Rekey frames count only under the current epoch's keys. A
		// delayed or duplicated INIT/RESP from the previous epoch is stale:
		// acting on it would derive a `next` from the wrong root and wedge
		// the next rekey (found by TestRekeyInterleavingsProperty).
		if ks != s.cur {
			return nil, nil
		}
		if pt[0] == frameRekeyInit {
			s.onRekeyInit(pt[1:])
		} else {
			s.onRekeyResp(pt[1:])
		}
		return nil, nil
	case frameKeepalive:
		// body 1 = "I rotated, confirm": answer with a bare keepalive
		// (body 0) under the now-current keys, so an initiator whose peer
		// is idle still sees confirmation. A bare keepalive is not answered.
		if len(pt) == 2 && pt[1] == 1 && ks == s.cur {
			if r, err := s.sealFrame(frameKeepalive, []byte{0}); err == nil {
				s.out = append(s.out, r)
			}
		}
		return nil, nil
	case framePathChallenge:
		if len(pt) == 9 {
			if r, err := s.sealFrame(framePathResponse, pt[1:]); err == nil {
				s.out = append(s.out, r)
			}
		}
		return nil, nil
	case framePathResponse:
		if s.challengeOut && len(pt) == 9 && equal32x8(pt[1:], s.challenge[:]) && from == s.Peer {
			s.markValidated()
		}
		return nil, nil
	}
	return nil, nil // unknown frame kinds are ignored (forward compatible)
}

func rekeyInfo(root []byte, initIdx []byte, pk []byte) []byte {
	h := sha256.New()
	h.Write([]byte("mosey rekey v1"))
	h.Write(root)
	h.Write(initIdx)
	h.Write(pk)
	return h.Sum(nil)
}

func rekeyDerive(root, ss, info, enc, respIdx []byte) (i2r, r2i, next [32]byte) {
	ikmInfo := string(info) + string(enc) + string(respIdx)
	out, err := hkdf.Key(sha256.New, ss, root, "mosey rekey keys"+ikmInfo, 96)
	if err != nil {
		panic(err)
	}
	copy(i2r[:], out[:32])
	copy(r2i[:], out[32:64])
	copy(next[:], out[64:])
	clear(out)
	return
}

func (s *Session) onRekeyInit(body []byte) {
	if len(body) != 4+KEMPublicKeySize {
		return
	}
	if s.awaitConfirm {
		return // we just rotated as initiator; finish that first
	}
	h := sha256.Sum256(body)
	if s.resp != nil && s.resp.pkHash == h {
		// Retransmitted init: answer identically, derive nothing new.
		if pkt, err := s.sealFrame(frameRekeyResp, s.resp.frame); err == nil {
			s.out = append(s.out, pkt)
		}
		return
	}
	if s.next != nil {
		return // a different INIT while our answer is unconfirmed: ignore
	}
	if s.pend != nil {
		if s.initiator {
			return // collision: the client's rekey wins
		}
		s.pend = nil
	}
	info := rekeyInfo(s.root[:], body[:4], body[4:])
	enc, ss, err := kemEncap(body[4:], info)
	if err != nil {
		return
	}
	localIdx := randIndex()
	if s.idxHook != nil {
		s.idxHook(localIdx)
	}
	idxb := binary.LittleEndian.AppendUint32(nil, localIdx)
	i2r, r2i, nextRoot := rekeyDerive(s.root[:], ss, info, enc, idxb)
	clear(ss)
	s.next = &keyset{
		localIdx: localIdx, remoteIdx: binary.LittleEndian.Uint32(body),
		sendKey: r2i, recvKey: i2r, born: s.cfg.Now(),
	}
	frame := append(idxb, enc...)
	s.resp = &rekeyResp{pkHash: h, frame: frame, nextRoot: nextRoot}
	clear(i2r[:])
	clear(r2i[:])
	clear(nextRoot[:])
	if pkt, err := s.sealFrame(frameRekeyResp, frame); err == nil {
		s.out = append(s.out, pkt)
	}
}

func (s *Session) onRekeyResp(body []byte) {
	p := s.pend
	if p == nil || len(body) != 4+KEMCiphertextSize {
		return
	}
	initIdx := binary.LittleEndian.AppendUint32(nil, p.localIdx)
	info := rekeyInfo(s.root[:], initIdx, p.pk)
	ss, err := kemDecap(p.sk, body[4:], info)
	if err != nil {
		return
	}
	i2r, r2i, nextRoot := rekeyDerive(s.root[:], ss, info, body[4:], body[:4])
	clear(ss)
	nk := &keyset{
		localIdx: p.localIdx, remoteIdx: binary.LittleEndian.Uint32(body),
		sendKey: i2r, recvKey: r2i, born: s.cfg.Now(),
	}
	clear(i2r[:])
	clear(r2i[:])
	s.rotate(nk, &nextRoot)
	s.pend = nil // hpke key dropped, not erased (FINDINGS §3.2)
	// Key confirmation for the responder (WireGuard's keepalive): without
	// it an idle initiator would let its old keys expire while the
	// responder still sends under them. Retransmitted until confirmed.
	s.awaitConfirm = true
	s.sendKeepalive()
}

// promoteNext runs on the rekey responder when the first packet under the
// new keys authenticates (key confirmation, WireGuard-style).
func (s *Session) promoteNext() {
	s.rotate(s.next, &s.resp.nextRoot)
	s.next = nil
	s.resp = nil
}

// rotate installs nk and the next root, erasing the source copy.
func (s *Session) rotate(nk *keyset, nextRoot *[32]byte) {
	if s.prev != nil {
		s.wipeKeyset(s.prev)
	}
	s.prev = s.cur
	s.prevExpires = s.cfg.Now().Add(s.cfg.KeepPrevFor)
	s.cur = nk
	s.root = *nextRoot
	clear(nextRoot[:])
	s.Stats.Rekeys++
}

// Root exposes the current root key to tests (property test: both sides
// must agree after quiescence).
func (s *Session) rootForTest() [32]byte { return s.root }

func equal32x8(a, b []byte) bool { return len(a) == len(b) && equal32(a, b) }

func (s *Session) wipeKeyset(k *keyset) {
	clear(k.sendKey[:])
	clear(k.recvKey[:])
}
