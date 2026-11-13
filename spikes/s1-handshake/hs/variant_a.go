package hs

import (
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/binary"
)

// Variant A: SIGMA-I (Krawczyk, CRYPTO 2003, "SIGn-and-MAc", identity
// protection for the initiator) over a hybrid X-Wing KEM.
//
//	-> e                                    msg1: 6 + 1216
//	<- ekem, {ID_S, Sig_S(lbl_R, h), hello} msg2: 10 + 1120 + 32+64+|hello|+16
//	-> {ID_C, Sig_C(lbl_I, h), hello}       msg3: 6 + 32+64+|hello|+16
//
// h is the running transcript hash, so each signature covers both key
// shares, both indices, the role label, the signer's own identity and (for
// msg3) the peer's identity and signature. Encrypting under the KEM-derived
// key with h as associated data is SIGMA's "MAC over the identity", which is
// what prevents identity misbinding.
//
// Long-term keys: Ed25519. In the D6 world the server's public key is
// delivered over SSH and the client's public key goes the other way, so
// SSH remains the root of trust; the signatures re-prove what SSH already
// established.
const aProtocolName = "Mosey_A_SIGMA-I_XWing_Ed25519_ChaChaPoly_HKDFSHA256"

const (
	lblResponder = "mosey A responder signature v1"
	lblInitiator = "mosey A initiator signature v1"
	aInitHeader  = 6
	aRespHeader  = 10
	aFinHeader   = 6
)

type AIdentity struct {
	SessionID [16]byte
	Self      ed25519.PrivateKey
	Peer      ed25519.PublicKey // pinned, delivered over SSH
}

func aInitialState(id *AIdentity) symState {
	st := newSymState(aProtocolName)
	st.mixHash([]byte("mosey prologue v1"), id.SessionID[:])
	return st
}

func signed(label string, h []byte, pub []byte) []byte {
	m := make([]byte, 0, len(label)+64)
	m = append(m, label...)
	m = append(m, h...)
	m = append(m, pub...)
	return m
}

// ---------------------------------------------------------------- client

type AClient struct {
	cfg      Config
	id       AIdentity
	hello    Hello
	st       symState
	localIdx uint32
	kemSK    hpke.PrivateKey
	msg1     []byte
	done     bool
}

func NewAClient(id AIdentity, hello Hello, cfg Config) (*AClient, []byte, error) {
	c := &AClient{cfg: cfg, id: id, hello: hello, localIdx: randIndex()}
	sk, pk, err := kemGenerate()
	if err != nil {
		return nil, nil, err
	}
	c.kemSK = sk
	st := aInitialState(&c.id)
	out := []byte{TypeAInit, Version}
	out = binary.LittleEndian.AppendUint32(out, c.localIdx)
	out = append(out, pk...)
	st.mixHash(out)
	c.st, c.msg1 = st, out
	return c, out, nil
}

// HandleResp processes msg2 and returns msg3 plus the session. The client
// may send data immediately after msg3.
func (c *AClient) HandleResp(msg []byte) (msg3 []byte, sess *Session, peer Hello, err error) {
	if c.done {
		return nil, nil, Hello{}, ErrState
	}
	if len(msg) < aRespHeader+KEMCiphertextSize+tagSize+32+64 || msg[0] != TypeAResp || msg[1] != Version {
		return nil, nil, Hello{}, ErrMalformed
	}
	if binary.LittleEndian.Uint32(msg[6:]) != c.localIdx {
		return nil, nil, Hello{}, ErrNoKey
	}
	st := c.st
	st.mixHash(msg[:aRespHeader])
	enc := msg[aRespHeader : aRespHeader+KEMCiphertextSize]
	ss, err := kemDecap(c.kemSK, enc, st.h[:])
	if err != nil {
		return nil, nil, Hello{}, ErrAuth
	}
	st.mixHash(enc)
	st.mixKey(ss)
	clear(ss)
	hSig := st.h // what the responder signed
	pt, err := st.decryptAndHash(msg[aRespHeader+KEMCiphertextSize:])
	if err != nil || len(pt) < 96 {
		return nil, nil, Hello{}, ErrAuth
	}
	pub, sig := pt[:32], pt[32:96]
	if !equal32(pub, c.id.Peer) || !ed25519.Verify(c.id.Peer, signed(lblResponder, hSig[:], pub), sig) {
		return nil, nil, Hello{}, ErrAuth
	}
	peer, err = ParseHello(pt[96:])
	if err != nil {
		return nil, nil, Hello{}, err
	}
	// msg3
	serverIdx := binary.LittleEndian.Uint32(msg[2:])
	out := []byte{TypeAFin, Version}
	out = binary.LittleEndian.AppendUint32(out, serverIdx)
	st.mixHash(out)
	myPub := c.id.Self.Public().(ed25519.PublicKey)
	mySig := ed25519.Sign(c.id.Self, signed(lblInitiator, st.h[:], myPub))
	sel := Hello{Proto: c.hello.Proto, Flags: c.hello.Flags, Channels: Negotiate(c.hello.Channels, peer.Channels)}
	hb, _ := MarshalHello(sel)
	body := append(append(append([]byte{}, myPub...), mySig...), hb...)
	out = append(out, st.encryptAndHash(body)...)
	i2r, r2i, root := st.split()
	c.done = true
	c.kemSK = nil
	return out, newSession(c.cfg, true, c.localIdx, serverIdx, i2r, r2i, root), peer, nil
}

// ---------------------------------------------------------------- server

type AServer struct {
	cfg   Config
	id    AIdentity
	local Hello

	// one pending handshake (spike simplification)
	pending   bool
	st        symState
	localIdx  uint32
	peerIdx   uint32
	cacheHash [32]byte
	cacheResp []byte
}

func NewAServer(id AIdentity, local Hello, cfg Config) *AServer {
	return &AServer{cfg: cfg, id: id, local: local}
}

// HandleInit answers msg1. NOTE: msg1 is unauthenticated, so every spoofed
// msg1 costs the server an X-Wing encapsulation and an Ed25519 signature
// and creates state -- the DoS cost FINDINGS compares against variant B.
func (s *AServer) HandleInit(msg []byte) ([]byte, error) {
	if len(msg) != aInitHeader+KEMPublicKeySize || msg[0] != TypeAInit || msg[1] != Version {
		return nil, ErrMalformed
	}
	if s.pending && sha256.Sum256(msg) == s.cacheHash {
		return s.cacheResp, nil
	}
	st := aInitialState(&s.id)
	st.mixHash(msg)
	localIdx := randIndex()
	peerIdx := binary.LittleEndian.Uint32(msg[2:])
	out := []byte{TypeAResp, Version}
	out = binary.LittleEndian.AppendUint32(out, localIdx)
	out = binary.LittleEndian.AppendUint32(out, peerIdx)
	st.mixHash(out)
	enc, ss, err := kemEncap(msg[aInitHeader:], st.h[:])
	if err != nil {
		return nil, ErrMalformed
	}
	out = append(out, enc...)
	st.mixHash(enc)
	st.mixKey(ss)
	clear(ss)
	myPub := s.id.Self.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(s.id.Self, signed(lblResponder, st.h[:], myPub))
	hb, _ := MarshalHello(s.local)
	body := append(append(append([]byte{}, myPub...), sig...), hb...)
	out = append(out, st.encryptAndHash(body)...)
	s.pending, s.st, s.localIdx, s.peerIdx = true, st, localIdx, peerIdx
	s.cacheHash, s.cacheResp = sha256.Sum256(msg), out
	return out, nil
}

func (s *AServer) HandleFin(msg []byte) (*Session, Hello, error) {
	if !s.pending {
		return nil, Hello{}, ErrState
	}
	if len(msg) < aFinHeader+96+tagSize || msg[0] != TypeAFin || msg[1] != Version {
		return nil, Hello{}, ErrMalformed
	}
	if binary.LittleEndian.Uint32(msg[2:]) != s.localIdx {
		return nil, Hello{}, ErrNoKey
	}
	st := s.st
	st.mixHash(msg[:aFinHeader])
	hSig := st.h
	pt, err := st.decryptAndHash(msg[aFinHeader:])
	if err != nil || len(pt) < 96 {
		return nil, Hello{}, ErrAuth
	}
	pub, sig := pt[:32], pt[32:96]
	if !equal32(pub, s.id.Peer) || !ed25519.Verify(s.id.Peer, signed(lblInitiator, hSig[:], pub), sig) {
		return nil, Hello{}, ErrAuth
	}
	peer, err := ParseHello(pt[96:])
	if err != nil {
		return nil, Hello{}, err
	}
	i2r, r2i, root := st.split()
	s.pending = false
	s.st.wipe()
	return newSession(s.cfg, false, s.localIdx, s.peerIdx, i2r, r2i, root), peer, nil
}
