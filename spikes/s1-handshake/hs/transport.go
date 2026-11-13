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

	frameApp       byte = 0
	frameRekeyInit byte = 1
	frameRekeyResp byte = 2
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

	Peer netip.AddrPort

	pend  *rekeyPending
	resp  *rekeyResp
	out   [][]byte
	Stats Stats
}

func newSession(cfg Config, initiator bool, localIdx, remoteIdx uint32, i2r, r2i, root [32]byte) *Session {
	if cfg.Now == nil {
		cfg = DefaultConfig()
	}
	ks := &keyset{localIdx: localIdx, remoteIdx: remoteIdx, born: cfg.Now()}
	if initiator {
		ks.sendKey, ks.recvKey = i2r, r2i
	} else {
		ks.sendKey, ks.recvKey = r2i, i2r
	}
	return &Session{cfg: cfg, initiator: initiator, cur: ks, root: root}
}

// LocalIndex is the receiver index the peer currently uses for us.
func (s *Session) LocalIndex() uint32 { return s.cur.localIdx }

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

// Tick drives timers (rekey retransmission, previous-key expiry).
func (s *Session) Tick() {
	now := s.cfg.Now()
	if s.prev != nil && now.After(s.prevExpires) {
		s.wipeKeyset(s.prev)
		s.prev = nil
	}
	s.maybeRekey()
}

func (s *Session) maybeRekey() {
	now := s.cfg.Now()
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

// StartRekey begins an in-band hybrid rekey (exported for tests).
func (s *Session) StartRekey() {
	sk, pk, err := kemGenerate()
	if err != nil {
		return
	}
	p := &rekeyPending{sk: sk, pk: pk, localIdx: randIndex(), sent: s.cfg.Now()}
	p.frame = binary.LittleEndian.AppendUint32(nil, p.localIdx)
	p.frame = append(p.frame, pk...)
	s.pend = p
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
	// Roaming: follow the source address of the newest authenticated
	// packet of the current epoch (reordered old packets don't move us).
	if ks == s.cur && ctr == ks.win.top && from.IsValid() && from != s.Peer {
		if s.Peer.IsValid() {
			s.Stats.Roams++
		}
		s.Peer = from
	}
	switch pt[0] {
	case frameApp:
		return pt[1:], nil
	case frameRekeyInit:
		s.onRekeyInit(pt[1:])
		return nil, nil
	case frameRekeyResp:
		s.onRekeyResp(pt[1:])
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
	if s.pend != nil {
		if s.initiator {
			return // collision: the client's rekey wins
		}
		s.pend = nil
	}
	h := sha256.Sum256(body)
	if s.resp != nil && s.resp.pkHash == h {
		// Retransmitted init: answer identically, derive nothing new.
		if pkt, err := s.sealFrame(frameRekeyResp, s.resp.frame); err == nil {
			s.out = append(s.out, pkt)
		}
		return
	}
	info := rekeyInfo(s.root[:], body[:4], body[4:])
	enc, ss, err := kemEncap(body[4:], info)
	if err != nil {
		return
	}
	localIdx := randIndex()
	idxb := binary.LittleEndian.AppendUint32(nil, localIdx)
	i2r, r2i, nextRoot := rekeyDerive(s.root[:], ss, info, enc, idxb)
	clear(ss)
	if s.next != nil {
		s.wipeKeyset(s.next)
	}
	s.next = &keyset{
		localIdx: localIdx, remoteIdx: binary.LittleEndian.Uint32(body),
		sendKey: r2i, recvKey: i2r, born: s.cfg.Now(),
	}
	frame := append(idxb, enc...)
	s.resp = &rekeyResp{pkHash: h, frame: frame, nextRoot: nextRoot}
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
	s.rotate(nk, nextRoot)
	s.pend = nil
}

// promoteNext runs on the rekey responder when the first packet under the
// new keys authenticates (key confirmation, WireGuard-style).
func (s *Session) promoteNext() {
	s.rotate(s.next, s.resp.nextRoot)
	s.next = nil
	s.resp = nil
}

func (s *Session) rotate(nk *keyset, nextRoot [32]byte) {
	if s.prev != nil {
		s.wipeKeyset(s.prev)
	}
	s.prev = s.cur
	s.prevExpires = s.cfg.Now().Add(s.cfg.KeepPrevFor)
	s.cur = nk
	s.root = nextRoot
	clear(nextRoot[:])
	s.Stats.Rekeys++
}

func (s *Session) wipeKeyset(k *keyset) {
	clear(k.sendKey[:])
	clear(k.recvKey[:])
}
