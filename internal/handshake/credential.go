package handshake

import (
	"crypto/hmac"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Credential is what the server hands the client over SSH stdout: enough
// to start one handshake. Its fields travel in a bootstrap.CredentialLine.
type Credential struct {
	// ID names the credential in msg1's clear header, so the server finds it
	// with one map lookup before any MAC or KEM work. Random and single-use,
	// so it links nothing beyond this one handshake. Public: it may be
	// logged.
	ID [8]byte
	// SessionID names the terminal session, for resume (D8) and logs.
	// Public.
	SessionID [16]byte
	// PSK is defence in depth and the key of msg1's mac1 DoS filter. It is
	// not what authenticates either side; the one-shot keys are.
	PSK [32]byte
	// ServerPublic is the server's one-shot X-Wing public key.
	ServerPublic []byte
}

// Wipe erases the PSK, the credential's one secret. Whoever marshals a
// credential into a line or a message erases that buffer too, once it is
// written (transport.md §9).
func (c *Credential) Wipe() { clear(c.PSK[:]) }

// NewSessionID draws a terminal session's id: once per session, shared by
// every credential minted for it (transport.md §3.4).
func NewSessionID() ([16]byte, error) {
	var sid [16]byte
	if _, err := rand.Read(sid[:]); err != nil {
		return sid, fmt.Errorf("drawing a session id: %w", err)
	}
	return sid, nil
}

// Credentials is the server's store of credentials it has minted and the
// client has not yet confirmed (D20): each lives CredentialTTL, at most
// MaxUnused may be outstanding per session, and the oldest is evicted, and
// logged, when a new one would exceed that.
//
// A credential is consumed only when the client confirms it with the first
// authentic transport packet, never on msg1, so msg1s forged with a leaked
// PSK cannot lock the genuine client out.
//
// It is safe for concurrent use: proto mints while the listener answers.
type Credentials struct {
	mu  sync.Mutex
	log *slog.Logger

	byID map[[8]byte]*credential
	// unused is each session's unconsumed credentials, oldest first.
	unused map[[16]byte][]*credential
	// nextExpiry is the earliest TTL in byID, so expiry is a comparison
	// until something is actually due.
	nextExpiry time.Time
	// erased are the pendings erased since the responder last collected
	// them, so the transport can free their indices.
	erased []*Pending
}

const (
	// CredentialTTL is how long a minted credential waits for its
	// handshake: SSH stdout to UDP plus retransmissions (S1, our choice).
	CredentialTTL = 30 * time.Second
	// MaxUnused is how many unconfirmed credentials a session may hold (S1).
	MaxUnused = 2
	// MaxPending is how many answered, unconfirmed msg1s a credential may
	// have (S1). A fifth evicts one of the four at random, so forged msg1s
	// cannot evict the genuine one with certainty (transport.md §3.8).
	MaxPending = 4
)

// credential is the server's side of a Credential.
type credential struct {
	id      [8]byte
	idHex   string
	sid     [16]byte
	sidHex  string
	psk     [32]byte
	mac1Key [32]byte
	sk      hpke.PrivateKey
	// clientPublic is s_C, which msg2 encapsulates to.
	clientPublic []byte
	// initial is the symmetric state after the prologue, both pre-messages
	// and the PSK: the same for every msg1 under this credential.
	initial  symmetric
	expires  time.Time
	consumed bool
	pendings []*Pending
}

// NewCredentials is an empty store that logs evictions to log.
func NewCredentials(log *slog.Logger) *Credentials {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Credentials{
		log:    log,
		byID:   map[[8]byte]*credential{},
		unused: map[[16]byte][]*credential{},
	}
}

// Mint makes a credential for the client whose one-shot public key arrived
// over SSH stdin, bound to session. The caller writes it to SSH stdout and
// then wipes both the Credential and the buffer it wrote.
func (c *Credentials) Mint(session [16]byte, clientPublic []byte) (Credential, error) {
	if len(clientPublic) != PublicKeySize {
		return Credential{}, fmt.Errorf("%w: a client key of %d bytes", ErrMalformed, len(clientPublic))
	}
	if _, err := xwing.NewPublicKey(clientPublic); err != nil {
		return Credential{}, fmt.Errorf("%w: the client's key: %v", ErrMalformed, err)
	}
	cred := &credential{sid: session, sidHex: hex.EncodeToString(session[:]), clientPublic: append([]byte(nil), clientPublic...)}
	var out Credential
	var err error
	secretDo(func() {
		var serverPublic []byte
		if cred.sk, serverPublic, err = generate(); err != nil {
			return
		}
		if _, err = rand.Read(cred.psk[:]); err != nil {
			err = fmt.Errorf("drawing a PSK: %w", err)
			return
		}
		cred.initial = initialState(session, clientPublic, serverPublic, &cred.psk)
		cred.mac1Key = mac1Key(session, &cred.psk)
		out = Credential{SessionID: session, PSK: cred.psk, ServerPublic: serverPublic}
	})
	if err != nil {
		cred.erase()
		return Credential{}, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	c.expireLocked(now)
	for {
		if _, err := rand.Read(out.ID[:]); err != nil {
			cred.erase()
			out.Wipe()
			return Credential{}, fmt.Errorf("drawing a credential id: %w", err)
		}
		// 64 bits make a collision theoretical, but re-drawing costs
		// nothing and keeps the map honest (S1).
		if c.byID[out.ID] == nil {
			break
		}
	}
	cred.id, cred.idHex = out.ID, hex.EncodeToString(out.ID[:])
	cred.expires = now.Add(CredentialTTL)
	for len(c.unused[session]) >= MaxUnused {
		oldest := c.unused[session][0]
		c.log.Info("evicting an unused credential: the session minted more than its cap",
			"credential", oldest.idHex, "session", oldest.sidHex, "cap", MaxUnused)
		c.dropLocked(oldest)
	}
	c.byID[out.ID] = cred
	c.unused[session] = append(c.unused[session], cred)
	if c.nextExpiry.IsZero() || cred.expires.Before(c.nextExpiry) {
		c.nextExpiry = cred.expires
	}
	return out, nil
}

// Live is how many credentials are minted and neither consumed nor expired,
// across every session.
func (c *Credentials) Live() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked(time.Now())
	n := 0
	for _, u := range c.unused {
		n += len(u)
	}
	return n
}

// expireLocked drops every credential past its TTL: an unconsumed one is
// erased with its pendings, and a consumed one, kept only so later msg1s
// naming it are dropped cheaply, is forgotten.
func (c *Credentials) expireLocked(now time.Time) {
	if c.nextExpiry.IsZero() || now.Before(c.nextExpiry) {
		return
	}
	c.nextExpiry = time.Time{}
	for _, cred := range c.byID {
		if !now.Before(cred.expires) {
			c.dropLocked(cred)
		} else if c.nextExpiry.IsZero() || cred.expires.Before(c.nextExpiry) {
			c.nextExpiry = cred.expires
		}
	}
}

// dropLocked removes cred from the store, erasing it and every pending it
// vouched for: a pending never outlives its credential (transport.md §3.8).
func (c *Credentials) dropLocked(cred *credential) {
	delete(c.byID, cred.id)
	c.unlistLocked(cred)
	c.erased = append(c.erased, cred.pendings...)
	cred.erase()
}

func (c *Credentials) unlistLocked(cred *credential) {
	list := c.unused[cred.sid]
	for i, u := range list {
		if u == cred {
			list = append(list[:i:i], list[i+1:]...)
			break
		}
	}
	if len(list) == 0 {
		delete(c.unused, cred.sid)
	} else {
		c.unused[cred.sid] = list
	}
}

// erase forgets every secret of the credential and of its pendings.
func (cred *credential) erase() {
	clear(cred.psk[:])
	clear(cred.mac1Key[:])
	cred.sk = nil // opaque: dropped, erased only under runtimesecret (S1 §3.2)
	cred.initial.wipe()
	for _, p := range cred.pendings {
		p.erase()
	}
	cred.pendings = nil
}

// initialState is the symmetric state both sides start msg1 from
// (transport.md §3.4): the protocol name, the prologue with the session id,
// both one-shot keys as pre-messages, then the PSK (psk0).
func initialState(sid [16]byte, clientPublic, serverPublic []byte, psk *[32]byte) symmetric {
	s := newSymmetric(Protocol)
	s.mixHash([]byte("mosey prologue v1"), sid[:])
	s.mixHash(clientPublic)
	s.mixHash(serverPublic)
	s.mixKey(psk[:])
	return s
}

// mac1Key is K_mac1 = HKDF(salt = sid, ikm = psk, "mosey mac1", 32).
func mac1Key(sid [16]byte, psk *[32]byte) [32]byte {
	var k [32]byte
	out := hkdfKey(psk[:], sid[:], "mosey mac1", 32)
	copy(k[:], out)
	clear(out)
	return k
}

// mac1 is the first 16 bytes of HMAC-SHA-256 under K_mac1: WireGuard's
// cheap filter, checked before any KEM work [WG §5.3, S1 §2.2].
func mac1(key *[32]byte, msg []byte) []byte {
	m := hmac.New(sha256.New, key[:])
	m.Write(msg)
	return m.Sum(nil)[:mac1Size]
}
