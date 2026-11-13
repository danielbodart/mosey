package hs

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"time"
)

// mac1 is a cheap pre-filter, as in WireGuard: an HMAC over the whole of
// msg1, keyed from the PSK only, checked BEFORE any KEM work. Without it a
// B1 server spends one X-Wing decapsulation on every garbage msg1 (~75 us,
// the measured decap cost; see FINDINGS §2.2); with it, ~1-3 us. It is not
// part of the transcript and adds no security beyond DoS resistance (the
// AEAD tag already authenticates).
const mac1Size = 16

func mac1Key(c *BCredentials) []byte {
	k, err := hkdf.Key(sha256.New, c.PSK[:], c.SessionID[:], "mosey mac1", 32)
	if err != nil {
		panic(err)
	}
	return k
}

func mac1(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)[:mac1Size]
}

// Variant B: "SSH vouches, ephemeral hybrid KEM gives forward secrecy".
// No long-term keys and no signatures.
//
// The SSH bootstrap (D6), or the authenticated local resume socket (D8),
// hands the client a BCredentials blob on SSH stdout: a cleartext
// credential id, a fresh session id, a fresh 32-byte PSK and -- in modes B1
// and B3 -- a fresh per-handshake X-Wing public key of the server. Every
// value in it is single-use, expires after CredentialTTL, and lives only in
// memory.
//
// Token sequences (pre-messages before "..."; "skem" = the sender
// encapsulates to the peer's SSH-delivered one-shot key; none of these is a
// pattern from the PQNoise catalogue -- see FINDINGS §4):
//
// B1 (server KEM key on SSH stdout; client is authenticated ONLY by the PSK,
// so B1 needs the SSH stream to stay CONFIDENTIAL):
//
//	<- s_S                        (stdout)
//	...
//	-> psk, skem_S, {hello_c}     msg1: 14 + 1120 + |hello|+16 + mac1(16)
//	<- {hello_s}                  msg2: 10 + |hello|+16
//
// B2 (nothing but the PSK pre-shared; KEM-only "pqNNpsk0", no DH tokens):
//
//	-> psk, e_kem, {hello_c}      msg1: 14 + 1216 + |hello|+16 + mac1(16)
//	<- ekem, {hello_s}            msg2: 10 + 1120 + |hello|+16
//
// B3 (recommended after review): both sides contribute a one-shot X-Wing
// key over SSH -- the client writes s_C to SSH STDIN, the server prints s_S
// on SSH stdout. Each side is authenticated by its ability to decapsulate,
// so B3 needs SSH only to be AUTHENTIC (integrity of s_C and s_S); a
// credential that leaks from stdout (session recorder, script(1), shell rc
// noise) is not enough to impersonate the client. The PSK stays as a
// defence in depth (and a hedge should X-Wing break entirely).
//
//	-> s_C                        (stdin)
//	<- s_S                        (stdout)
//	...
//	-> psk, skem_S, {hello_c}     msg1: 14 + 1120 + |hello|+16 + mac1(16)
//	<- skem_C, {hello_s}          msg2: 10 + 1120 + |hello|+16
//	-> first transport packet     (key confirmation = client authentication)
//
// In B3 the server only knows the client is genuine when the first
// transport packet authenticates (its keys depend on skem_C). It may send
// to the client at 0.5 RTT -- only the holder of sk_C can read it -- but it
// does not consume the credential, accept input, or validate the client's
// address until then. Up to maxPendingPerCred unconfirmed responders may
// exist per credential, so an attacker who replays or forges msg1 with a
// leaked PSK cannot lock the genuine client out.
//
// The "static" keys are generated per handshake and deleted after use, so
// they give forward secrecy like ephemerals; they are called s only because
// they are delivered in advance.
type BMode byte

const (
	B1ServerKEM BMode = 1
	B2ClientKEM BMode = 2
	B3BothKEM   BMode = 3

	// CredentialTTL bounds how long a minted, unused credential stays live
	// (our choice: covers the SSH-stdout -> UDP hop plus retransmissions).
	CredentialTTL = 30 * time.Second
	// maxPendingPerCred bounds unconfirmed B3 responders per credential.
	maxPendingPerCred = 4
	credIDSize        = 8
)

func (m BMode) protocolName() string {
	switch m {
	case B1ServerKEM:
		return "Mosey_B1_KEMpsk0_XWing_ChaChaPoly_HKDFSHA256"
	case B3BothKEM:
		return "Mosey_B3_KEMx2psk0_XWing_ChaChaPoly_HKDFSHA256"
	}
	return "Mosey_B2_pqNNpsk0_XWing_ChaChaPoly_HKDFSHA256"
}

func (m BMode) serverKEM() bool { return m == B1ServerKEM || m == B3BothKEM }

// BCredentials is what the SSH channel delivers to the client.
type BCredentials struct {
	Mode        BMode
	CredID      [credIDSize]byte // cleartext in msg1: O(1) dispatch; single use
	SessionID   [16]byte
	PSK         [32]byte
	ServerKEMPK []byte // B1, B3
}

// Wipe erases the secret part of the credentials.
func (c *BCredentials) Wipe() { clear(c.PSK[:]) }

// Marshal encodes the credentials for the SSH stdout line / resume socket.
// The caller must clear the returned buffer after writing it.
func (c BCredentials) Marshal() []byte {
	b := []byte{byte(c.Mode)}
	b = append(b, c.CredID[:]...)
	b = append(b, c.SessionID[:]...)
	b = append(b, c.PSK[:]...)
	b = append(b, c.ServerKEMPK...)
	return b
}

const credFixed = 1 + credIDSize + 16 + 32

func ParseBCredentials(b []byte) (BCredentials, error) {
	var c BCredentials
	if len(b) < credFixed {
		return c, ErrMalformed
	}
	c.Mode = BMode(b[0])
	copy(c.CredID[:], b[1:9])
	copy(c.SessionID[:], b[9:25])
	copy(c.PSK[:], b[25:57])
	rest := b[credFixed:]
	switch c.Mode {
	case B1ServerKEM, B3BothKEM:
		if len(rest) != KEMPublicKeySize {
			return BCredentials{}, ErrMalformed
		}
		c.ServerKEMPK = append([]byte(nil), rest...)
	case B2ClientKEM:
		if len(rest) != 0 {
			return BCredentials{}, ErrMalformed
		}
	default:
		return BCredentials{}, ErrMalformed
	}
	return c, nil
}

func bInitialState(c *BCredentials, clientPK []byte) symState {
	st := newSymState(c.Mode.protocolName())
	st.mixHash([]byte("mosey prologue v1"), c.SessionID[:])
	if c.Mode == B3BothKEM {
		st.mixHash(clientPK) // pre-message "-> s_C" (stdin)
	}
	if c.Mode.serverKEM() {
		st.mixHash(c.ServerKEMPK) // pre-message "<- s_S" (stdout)
	}
	st.mixKey(c.PSK[:]) // psk0
	return st
}

const (
	bInitHeader = 2 + credIDSize + 4 // type, version, cred id, sender index
	bRespHeader = 10                 // type, version, sender index, receiver index
)

// ---------------------------------------------------------------- server

type pendingResp struct {
	hash [32]byte
	resp []byte
	sess *Session
}

type BServer struct {
	cfg      Config
	cred     BCredentials
	clientPK []byte // B3: client's one-shot key, received on SSH stdin
	kemSK    hpke.PrivateKey
	local    Hello
	consumed bool
	expires  time.Time

	pending []pendingResp // B1/B2: at most one (consumed on msg1); B3: up to maxPendingPerCred

	// OnConsume is called once when the credential is consumed (B1/B2:
	// first valid msg1; B3: first authenticated transport packet).
	OnConsume func(winner *Session)
}

// NewBServer creates the single-use server half and the credentials that
// must be delivered to the client over SSH. For B3 pass the client's
// one-shot public key (read from SSH stdin); otherwise nil.
func NewBServer(mode BMode, local Hello, cfg Config, clientPK ...[]byte) (*BServer, BCredentials, error) {
	if cfg.Now == nil {
		cfg = DefaultConfig()
	}
	s := &BServer{cfg: cfg, local: local, expires: cfg.Now().Add(CredentialTTL)}
	s.cred.Mode = mode
	rand.Read(s.cred.CredID[:])
	rand.Read(s.cred.SessionID[:])
	rand.Read(s.cred.PSK[:])
	if mode == B3BothKEM {
		if len(clientPK) != 1 || len(clientPK[0]) != KEMPublicKeySize {
			return nil, BCredentials{}, ErrMalformed
		}
		s.clientPK = append([]byte(nil), clientPK[0]...)
	}
	if mode.serverKEM() {
		sk, pk, err := kemGenerate()
		if err != nil {
			return nil, BCredentials{}, err
		}
		s.kemSK, s.cred.ServerKEMPK = sk, pk
	}
	return s, s.cred, nil
}

func (s *BServer) CredID() [credIDSize]byte { return s.cred.CredID }

// Expired reports whether an unconsumed credential has outlived its TTL.
func (s *BServer) Expired() bool { return !s.consumed && s.cfg.Now().After(s.expires) }

// Wipe forgets every secret that could recompute keys and revokes any
// unconfirmed responder sessions except keep (nil = revoke all).
func (s *BServer) Wipe(keep *Session) {
	clear(s.cred.PSK[:])
	s.kemSK = nil // opaque hpke key: dropped, not erased (see FINDINGS §3.2)
	for _, p := range s.pending {
		if p.sess != keep && p.sess != nil {
			p.sess.Revoke()
		}
	}
}

func (s *BServer) consume(winner *Session) {
	if s.consumed {
		return
	}
	s.consumed = true
	s.Wipe(winner)
	kept := s.pending[:0]
	for _, p := range s.pending {
		if p.sess == winner {
			kept = append(kept, p)
		}
	}
	s.pending = kept
	if s.OnConsume != nil {
		s.OnConsume(winner)
	}
}

// HandleInit processes msg1. On success it returns msg2 and the new
// transport session. A byte-identical retransmission of an accepted msg1
// returns the cached msg2 and a nil session. Any failure leaves the server
// state untouched.
func (s *BServer) HandleInit(msg []byte) (resp []byte, sess *Session, peer Hello, err error) {
	h := sha256.Sum256(msg)
	for _, p := range s.pending {
		if p.hash == h {
			return p.resp, nil, Hello{}, nil
		}
	}
	if s.consumed || s.Expired() {
		return nil, nil, Hello{}, ErrState
	}
	kemLen := KEMCiphertextSize
	if s.cred.Mode == B2ClientKEM {
		kemLen = KEMPublicKeySize
	}
	if len(msg) < bInitHeader+kemLen+tagSize+mac1Size || msg[0] != TypeBInit || msg[1] != Version {
		return nil, nil, Hello{}, ErrMalformed
	}
	if !hmac.Equal(msg[2:2+credIDSize], s.cred.CredID[:]) {
		return nil, nil, Hello{}, ErrNoKey
	}
	body := msg[:len(msg)-mac1Size]
	if !hmac.Equal(mac1(mac1Key(&s.cred), body), msg[len(body):]) {
		return nil, nil, Hello{}, ErrAuth
	}
	st := bInitialState(&s.cred, s.clientPK) // working copy; committed only on success
	st.mixHash(msg[:bInitHeader])
	kemPart := msg[bInitHeader : bInitHeader+kemLen]
	if s.cred.Mode.serverKEM() {
		ss, err := kemDecap(s.kemSK, kemPart, st.h[:])
		if err != nil {
			return nil, nil, Hello{}, ErrAuth
		}
		st.mixHash(kemPart)
		st.mixKey(ss)
		clear(ss)
	} else {
		st.mixHash(kemPart)
	}
	pt, err := st.decryptAndHash(body[bInitHeader+kemLen:])
	if err != nil {
		return nil, nil, Hello{}, ErrAuth
	}
	peer, err = ParseHello(pt)
	if err != nil {
		return nil, nil, Hello{}, err
	}
	// ---- msg1 authenticated (by the PSK + skem_S): build msg2 ----
	peerIdx := binary.LittleEndian.Uint32(msg[2+credIDSize:])
	localIdx := randIndex()
	out := []byte{TypeBResp, Version}
	out = binary.LittleEndian.AppendUint32(out, localIdx)
	out = binary.LittleEndian.AppendUint32(out, peerIdx)
	st.mixHash(out)
	var encTo []byte
	switch s.cred.Mode {
	case B2ClientKEM:
		encTo = kemPart
	case B3BothKEM:
		encTo = s.clientPK
	}
	if encTo != nil {
		enc, ss, err := kemEncap(encTo, st.h[:])
		if err != nil {
			return nil, nil, Hello{}, ErrMalformed
		}
		out = append(out, enc...)
		st.mixHash(enc)
		st.mixKey(ss)
		clear(ss)
	}
	reply := Hello{Proto: s.local.Proto, Flags: s.local.Flags, Channels: Negotiate(peer.Channels, s.local.Channels)}
	hb, _ := MarshalHello(reply)
	out = append(out, st.encryptAndHash(hb)...)
	i2r, r2i, root := st.split()
	sess = newSession(s.cfg, false, localIdx, peerIdx, &i2r, &r2i, &root)
	sess.Handshake = st.h
	// Keys depend on msg2 in B2/B3, so the first authenticated packet also
	// proves the client received msg2 at the address it was sent to.
	sess.keysProveReceipt = encTo != nil
	sess.amplifyBudget = antiAmplification * len(msg)
	if len(s.pending) >= maxPendingPerCred {
		// B3 only (B1/B2 consume on the first msg1). Evict the oldest
		// unconfirmed responder rather than refusing the newcomer, so a
		// handful of msg1s forged with a leaked PSK cannot lock the
		// genuine client out; only a sustained flood can (DoS, not
		// impersonation).
		s.pending[0].sess.Revoke()
		s.pending = s.pending[1:]
	}
	s.pending = append(s.pending, pendingResp{hash: h, resp: out, sess: sess})
	if s.cred.Mode == B3BothKEM {
		sess.onConfirm = func(w *Session) { s.consume(w) }
	} else {
		s.consume(sess) // B1/B2: single use on the first valid msg1
	}
	return out, sess, peer, nil
}

// ---------------------------------------------------------------- client

type BClient struct {
	cfg      Config
	cred     BCredentials
	st       symState
	localIdx uint32
	kemSK    hpke.PrivateKey
	msg1     []byte
	done     bool
}

// ClientKEM is the client's one-shot B3 key pair. PublicKey goes to the
// server over SSH stdin before the credentials come back on stdout.
type ClientKEM struct {
	sk        hpke.PrivateKey
	PublicKey []byte
}

func NewClientKEM() (*ClientKEM, error) {
	sk, pk, err := kemGenerate()
	if err != nil {
		return nil, err
	}
	return &ClientKEM{sk: sk, PublicKey: pk}, nil
}

// NewBClient builds msg1. The client resends Msg1() unchanged until it gets
// msg2 (the server answers retransmissions from cache). In B3 pass the
// ClientKEM whose public key was written to SSH stdin.
func NewBClient(cred BCredentials, hello Hello, cfg Config, ck ...*ClientKEM) (*BClient, []byte, error) {
	c := &BClient{cfg: cfg, cred: cred, localIdx: randIndex()}
	var clientPK []byte
	if cred.Mode == B3BothKEM {
		if len(ck) != 1 || ck[0] == nil || ck[0].sk == nil {
			return nil, nil, ErrState
		}
		c.kemSK, clientPK = ck[0].sk, ck[0].PublicKey
		ck[0].sk = nil // one-shot
	}
	st := bInitialState(&c.cred, clientPK)
	out := []byte{TypeBInit, Version}
	out = append(out, cred.CredID[:]...)
	out = binary.LittleEndian.AppendUint32(out, c.localIdx)
	st.mixHash(out)
	if cred.Mode.serverKEM() {
		enc, ss, err := kemEncap(cred.ServerKEMPK, st.h[:])
		if err != nil {
			return nil, nil, err
		}
		out = append(out, enc...)
		st.mixHash(enc)
		st.mixKey(ss)
		clear(ss)
	} else {
		sk, pk, err := kemGenerate()
		if err != nil {
			return nil, nil, err
		}
		c.kemSK = sk
		out = append(out, pk...)
		st.mixHash(pk)
	}
	hb, err := MarshalHello(hello)
	if err != nil {
		return nil, nil, err
	}
	out = append(out, st.encryptAndHash(hb)...)
	out = append(out, mac1(mac1Key(&c.cred), out)...)
	c.st = st
	c.msg1 = out
	return c, out, nil
}

func (c *BClient) Msg1() []byte { return c.msg1 }

// HandleResp processes msg2. Failure leaves the client waiting for a valid
// msg2 (an attacker cannot make it give up by injecting garbage).
func (c *BClient) HandleResp(msg []byte) (*Session, Hello, error) {
	if c.done {
		return nil, Hello{}, ErrState
	}
	kemLen := 0
	if c.cred.Mode != B1ServerKEM {
		kemLen = KEMCiphertextSize
	}
	if len(msg) < bRespHeader+kemLen+tagSize || msg[0] != TypeBResp || msg[1] != Version {
		return nil, Hello{}, ErrMalformed
	}
	if binary.LittleEndian.Uint32(msg[6:]) != c.localIdx {
		return nil, Hello{}, ErrNoKey
	}
	st := c.st
	st.mixHash(msg[:bRespHeader])
	if kemLen > 0 {
		enc := msg[bRespHeader : bRespHeader+kemLen]
		ss, err := kemDecap(c.kemSK, enc, st.h[:])
		if err != nil {
			return nil, Hello{}, ErrAuth
		}
		st.mixHash(enc)
		st.mixKey(ss)
		clear(ss)
	}
	pt, err := st.decryptAndHash(msg[bRespHeader+kemLen:])
	if err != nil {
		return nil, Hello{}, ErrAuth
	}
	peer, err := ParseHello(pt)
	if err != nil {
		return nil, Hello{}, err
	}
	i2r, r2i, root := st.split()
	c.st.wipe()
	c.cred.Wipe()
	c.kemSK = nil
	c.done = true
	sess := newSession(c.cfg, true, c.localIdx, binary.LittleEndian.Uint32(msg[2:]), &i2r, &r2i, &root)
	sess.Handshake = st.h
	return sess, peer, nil
}
