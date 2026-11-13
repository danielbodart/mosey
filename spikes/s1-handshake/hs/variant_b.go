package hs

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
)

// mac1 is a cheap pre-filter, as in WireGuard: an HMAC over the whole of
// msg1, keyed from the PSK only, checked BEFORE any KEM work. Without it a
// B1 server spends one X-Wing decapsulation (~80 us measured) on every
// garbage msg1; with it, ~1-3 us. It is not part of the transcript and adds
// no security beyond DoS resistance (the AEAD tag already authenticates).
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

// Variant B: "SSH vouches, PSK authenticates, ephemeral hybrid KEM gives
// forward secrecy". No long-term keys and no signatures.
//
// The SSH bootstrap (D6), or the authenticated local resume socket (D8),
// hands the client a BCredentials blob: a fresh session id, a fresh 32-byte
// PSK and -- in mode B1 -- a fresh per-handshake X-Wing public key of the
// server. Every value in it is single-use and lives only in memory.
//
// Mode B1 (recommended), Noise-style notation, "<- s" is the SSH-delivered
// ephemeral X-Wing key:
//
//	<- s
//	...
//	-> psk, skem, {hello_c}       msg1: 6 + 1120 + |hello|+16 + mac1(16)
//	<- {hello_s}                  msg2: 10 + |hello|+16
//
// Mode B2 (pure Noise NNpsk0 + HFS-style KEM, nothing but the PSK pre-shared):
//
//	-> psk, e1, {hello_c}         msg1: 6 + 1216 + |hello|+16 + mac1(16)
//	<- ekem1, {hello_s}           msg2: 10 + 1120 + |hello|+16
//
// The server's "static" key in B1 is generated per handshake and deleted
// after the first valid msg1, so it gives forward secrecy exactly like an
// ephemeral; it is called s only because it is delivered in advance.
type BMode byte

const (
	B1ServerKEM BMode = 1
	B2ClientKEM BMode = 2
)

func (m BMode) protocolName() string {
	if m == B1ServerKEM {
		return "Mosey_B1_pqNKpsk0_XWing_ChaChaPoly_HKDFSHA256"
	}
	return "Mosey_B2_pqNNpsk0_XWing_ChaChaPoly_HKDFSHA256"
}

// BCredentials is what the SSH channel delivers to the client.
type BCredentials struct {
	Mode        BMode
	SessionID   [16]byte
	PSK         [32]byte
	ServerKEMPK []byte // B1 only
}

// Marshal encodes the credentials for the SSH stdout line / resume socket.
func (c BCredentials) Marshal() []byte {
	b := []byte{byte(c.Mode)}
	b = append(b, c.SessionID[:]...)
	b = append(b, c.PSK[:]...)
	b = append(b, c.ServerKEMPK...)
	return b
}

func ParseBCredentials(b []byte) (BCredentials, error) {
	var c BCredentials
	if len(b) < 1+16+32 {
		return c, ErrMalformed
	}
	c.Mode = BMode(b[0])
	copy(c.SessionID[:], b[1:17])
	copy(c.PSK[:], b[17:49])
	rest := b[49:]
	switch c.Mode {
	case B1ServerKEM:
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

func bInitialState(c *BCredentials) symState {
	st := newSymState(c.Mode.protocolName())
	st.mixHash([]byte("mosey prologue v1"), c.SessionID[:])
	if c.Mode == B1ServerKEM {
		st.mixHash(c.ServerKEMPK) // pre-message "<- s"
	}
	st.mixKey(c.PSK[:]) // psk0
	return st
}

const (
	bInitHeader = 6  // type, version, sender index
	bRespHeader = 10 // type, version, sender index, receiver index
)

// ---------------------------------------------------------------- server

type BServer struct {
	cfg      Config
	cred     BCredentials
	kemSK    hpke.PrivateKey
	local    Hello
	consumed bool

	cacheHash [32]byte
	cacheResp []byte
}

// NewBServer creates the single-use server half and the credentials that
// must be delivered to the client over SSH.
func NewBServer(mode BMode, local Hello, cfg Config) (*BServer, BCredentials, error) {
	s := &BServer{cfg: cfg, local: local}
	s.cred.Mode = mode
	rand.Read(s.cred.SessionID[:])
	rand.Read(s.cred.PSK[:])
	if mode == B1ServerKEM {
		sk, pk, err := kemGenerate()
		if err != nil {
			return nil, BCredentials{}, err
		}
		s.kemSK, s.cred.ServerKEMPK = sk, pk
	}
	return s, s.cred, nil
}

// HandleInit processes msg1. On success it returns msg2 and the new
// transport session; the credentials are then consumed and wiped. A
// byte-identical retransmission of the accepted msg1 returns the cached
// msg2 and a nil session. Any failure leaves the server state untouched.
func (s *BServer) HandleInit(msg []byte) (resp []byte, sess *Session, peer Hello, err error) {
	if s.consumed {
		if sha256.Sum256(msg) == s.cacheHash {
			return s.cacheResp, nil, Hello{}, nil
		}
		return nil, nil, Hello{}, ErrState
	}
	kemLen := KEMCiphertextSize
	if s.cred.Mode == B2ClientKEM {
		kemLen = KEMPublicKeySize
	}
	if len(msg) < bInitHeader+kemLen+tagSize+mac1Size || msg[0] != TypeBInit || msg[1] != Version {
		return nil, nil, Hello{}, ErrMalformed
	}
	body := msg[:len(msg)-mac1Size]
	if !hmac.Equal(mac1(mac1Key(&s.cred), body), msg[len(body):]) {
		return nil, nil, Hello{}, ErrAuth
	}
	st := bInitialState(&s.cred) // working copy; committed only on success
	st.mixHash(msg[:bInitHeader])
	kemPart := msg[bInitHeader : bInitHeader+kemLen]
	if s.cred.Mode == B1ServerKEM {
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
	// ---- msg1 authenticated: build msg2 ----
	peerIdx := binary.LittleEndian.Uint32(msg[2:])
	localIdx := randIndex()
	out := []byte{TypeBResp, Version}
	out = binary.LittleEndian.AppendUint32(out, localIdx)
	out = binary.LittleEndian.AppendUint32(out, peerIdx)
	st.mixHash(out)
	if s.cred.Mode == B2ClientKEM {
		enc, ss, err := kemEncap(kemPart, st.h[:])
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
	sess = newSession(s.cfg, false, localIdx, peerIdx, i2r, r2i, root)

	// Commit: single use. Forget every secret that could recompute keys.
	s.consumed = true
	s.cacheHash = sha256.Sum256(msg)
	s.cacheResp = out
	clear(s.cred.PSK[:])
	s.kemSK = nil
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

// NewBClient builds msg1. The client resends Msg1() unchanged until it gets
// msg2 (the server answers retransmissions from cache).
func NewBClient(cred BCredentials, hello Hello, cfg Config) (*BClient, []byte, error) {
	c := &BClient{cfg: cfg, cred: cred, localIdx: randIndex()}
	st := bInitialState(&c.cred)
	out := []byte{TypeBInit, Version}
	out = binary.LittleEndian.AppendUint32(out, c.localIdx)
	st.mixHash(out)
	if cred.Mode == B1ServerKEM {
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
	if c.cred.Mode == B2ClientKEM {
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
	if c.cred.Mode == B2ClientKEM {
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
	clear(c.cred.PSK[:])
	c.kemSK = nil
	c.done = true
	sess := newSession(c.cfg, true, c.localIdx, binary.LittleEndian.Uint32(msg[2:]), i2r, r2i, root)
	return sess, peer, nil
}
