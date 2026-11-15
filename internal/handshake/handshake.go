package handshake

import (
	"crypto/hmac"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Wire layout (transport.md §3.5, §3.7). Every integer is little-endian.
const (
	// TypeMsg1 and TypeMsg2 are the first byte of the two handshake
	// datagrams; transport.TypeMsg1 and TypeMsg2 are the same numbers.
	TypeMsg1 = 0x01
	TypeMsg2 = 0x02
	// WireVersion is the second byte of msg1 and msg2. A peer is the same
	// build (D7), so another version is a bug or an attack, never answered.
	WireVersion = 0x01

	msg1Header = 1 + 1 + 8 + 4 // type, version, cred_id, idx_C
	msg2Header = 1 + 1 + 4 + 4 // type, version, idx_S, idx_C
	mac1Size   = 16
	tagSize    = chacha20poly1305.Overhead
)

// Msg1Size is the size of a msg1 whose hello offers channels channel types:
// 1169 + channels, so 1170 to 1185 bytes.
func Msg1Size(channels int) int {
	return msg1Header + EncapsulationSize + helloFixed + channels + tagSize + mac1Size
}

// Msg2Size is the size of a msg2 whose hello names channels channel types:
// 1149 + channels, so 1150 to 1165 bytes.
func Msg2Size(channels int) int {
	return msg2Header + EncapsulationSize + helloFixed + channels + tagSize
}

// Errors a handshake message is refused with. The transport counts drops by
// them, and answers none of them on the wire (transport.md §10.3).
var (
	// ErrMalformed is a message of the wrong size or shape.
	ErrMalformed = errors.New("handshake: malformed message")
	// ErrUnknownCredential is a msg1 naming no live credential: the cheapest
	// refusal, one map lookup.
	ErrUnknownCredential = errors.New("handshake: unknown credential")
	// ErrSpent is a msg1 for a credential already consumed or expired.
	ErrSpent = errors.New("handshake: credential consumed or expired")
	// ErrAuth is a message that failed mac1, the KEM or the AEAD.
	ErrAuth = errors.New("handshake: authentication failed")
	// ErrIncompatible is an authentic peer whose hello this build cannot
	// work with: a bug worth seeing, since only a key holder can send it.
	ErrIncompatible = errors.New("handshake: incompatible peer")
	// ErrState is a call this object's state does not allow, such as a
	// handshake with a key already used.
	ErrState = errors.New("handshake: wrong state")
)

// Keys are what a completed handshake or rekey gives the transport for one
// epoch.
type Keys struct {
	// Send and Recv are the ChaCha20-Poly1305 keys for each direction. Each
	// direction has its own key, so a counter is never used twice with one.
	Send, Recv [chacha20poly1305.KeySize]byte
	// LocalIndex is the index the peer puts on packets to us; RemoteIndex
	// is the one we put on packets to the peer. Each side picks its own, as
	// in WireGuard, and picks afresh at every rekey so epochs are unlinkable.
	LocalIndex, RemoteIndex uint32
	// Root is the chaining key the next rekey derives from.
	Root [32]byte
}

// Wipe erases the keys and the root.
func (k *Keys) Wipe() {
	clear(k.Send[:])
	clear(k.Recv[:])
	clear(k.Root[:])
}

// Wiped says whether the keys are all zero: wiped, or never set. No key
// set may ever be built from such keys, since anyone could seal under them.
func (k *Keys) Wiped() bool {
	return k.Send == [32]byte{} && k.Recv == [32]byte{} && k.Root == [32]byte{}
}

// Initiator is the client's side of one handshake.
//
// It keeps the private key and the symmetric state after c1 until Wipe, so
// that ReadMsg2 can accept a re-answered msg2 after the server lost the
// first pending to forged msg1s (transport.md §3.9).
type Initiator struct {
	sk      hpke.PrivateKey
	idxC    uint32
	msg1    []byte
	afterC1 symmetric
	offered Hello
}

// NewInitiator starts a handshake with the server that issued cred, using
// the client's own one-shot key from the bootstrap, which it takes: the key
// cannot start another handshake. idxC is the client's receiver index for
// epoch 0, drawn and reserved by the transport. NewInitiator erases its own
// copy of the PSK once msg1 is built; the caller erases cred's.
func NewInitiator(cred Credential, key *OneShotKey, hello Hello, idxC uint32) (*Initiator, error) {
	defer cred.Wipe() // cred is a copy; this erases ours
	if err := hello.check(); err != nil {
		return nil, err
	}
	if idxC == 0 {
		return nil, fmt.Errorf("%w: receiver index 0", ErrState)
	}
	if len(cred.ServerPublic) != PublicKeySize {
		return nil, fmt.Errorf("%w: a server key of %d bytes", ErrMalformed, len(cred.ServerPublic))
	}
	sk := key.take()
	if sk == nil {
		return nil, fmt.Errorf("%w: the one-shot key was already used or wiped", ErrState)
	}
	i := &Initiator{sk: sk, idxC: idxC, offered: hello}
	var err error
	secretDo(func() {
		i.msg1, i.afterC1, err = buildMsg1(&cred, key.public, hello, idxC)
	})
	if err != nil {
		i.Wipe()
		return nil, err
	}
	return i, nil
}

// buildMsg1 is msg1 for cred from the client whose one-shot public key is
// clientPublic, and the symmetric state after c1. It needs no private key:
// that is only needed to read msg2, which is the point of B3. It does not
// check idxC, so the tests can build the msg1 a buggy or hostile client
// would.
func buildMsg1(cred *Credential, clientPublic []byte, hello Hello, idxC uint32) ([]byte, symmetric, error) {
	st := initialState(cred.SessionID, clientPublic, cred.ServerPublic, &cred.PSK)
	macKey := mac1Key(cred.SessionID, &cred.PSK)
	defer clear(macKey[:])

	msg := make([]byte, 0, Msg1Size(len(hello.Channels)))
	msg = append(msg, TypeMsg1, WireVersion)
	msg = append(msg, cred.ID[:]...)
	msg = binary.LittleEndian.AppendUint32(msg, idxC)
	st.mixHash(msg)
	enc, ss, err := encapsulate(cred.ServerPublic, st.h[:])
	if err != nil {
		st.wipe()
		return nil, symmetric{}, err
	}
	msg = append(msg, enc...)
	st.mixHash(enc)
	st.mixKey(ss)
	clear(ss)
	msg = append(msg, st.encryptAndHash(MarshalHello(hello))...)
	msg = append(msg, mac1(&macKey, msg)...)
	return msg, st, nil
}

// ForgeMsg1 is what anyone holding a leaked credential line and the
// client's public key can make (threat-model.md T9, ProVerif
// b3_stdout_leak): a msg1 the server cannot tell from the client's, which
// it answers and which can never be confirmed, since reading the answer
// takes the client's private key. Nothing in mosey sends one; it exists so
// the transport's tests can play that attacker against the real listener.
func ForgeMsg1(cred Credential, clientPublic []byte, idxC uint32) ([]byte, error) {
	defer cred.Wipe()
	hello := Hello{Version: Revision, Channels: []ChannelType{ChannelTerminal}}
	msg, st, err := buildMsg1(&cred, clientPublic, hello, idxC)
	st.wipe()
	return msg, err
}

// Msg1 is the first handshake message, at most wire.MaxHandshake bytes. It
// is the same on every call, so a retransmission is a resend of it, which
// the server answers from its cache or, if it lost the pending, afresh.
func (i *Initiator) Msg1() []byte { return i.msg1 }

// ReadMsg2 finishes the handshake. It changes nothing, so a forged msg2
// cannot spoil the real one, and it may succeed more than once: each time
// it starts again from the state after c1, so a msg2 re-answered by a server
// that lost the first pending gives that pending's keys (transport.md
// §3.9). An authentic msg2 whose hello this build cannot work with is
// ErrIncompatible, which is final.
func (i *Initiator) ReadMsg2(msg2 []byte) (Keys, Hello, error) {
	if i.sk == nil {
		return Keys{}, Hello{}, fmt.Errorf("%w: the initiator was wiped", ErrState)
	}
	if len(msg2) < Msg2Size(1) || len(msg2) > Msg2Size(MaxChannels) ||
		msg2[0] != TypeMsg2 || msg2[1] != WireVersion {
		return Keys{}, Hello{}, ErrMalformed
	}
	idxS := binary.LittleEndian.Uint32(msg2[2:])
	if idxS == 0 || binary.LittleEndian.Uint32(msg2[6:]) != i.idxC {
		return Keys{}, Hello{}, ErrMalformed
	}
	var keys Keys
	var server Hello
	var err error
	secretDo(func() {
		st := i.afterC1
		defer st.wipe()
		st.mixHash(msg2[:msg2Header])
		enc := msg2[msg2Header : msg2Header+EncapsulationSize]
		ss, kerr := decapsulate(i.sk, enc, st.h[:])
		if kerr != nil {
			err = kerr
			return
		}
		st.mixHash(enc)
		st.mixKey(ss)
		clear(ss)
		plain, aerr := st.decryptAndHash(msg2[msg2Header+EncapsulationSize:])
		if aerr != nil {
			err = aerr
			return
		}
		if server, err = ParseHello(plain); err != nil {
			return
		}
		if err = server.agrees(i.offered); err != nil {
			return
		}
		i2r, r2i, root := st.split()
		keys.Send, keys.Recv, keys.Root = i2r, r2i, root
		clear(i2r[:])
		clear(r2i[:])
		clear(root[:])
		keys.LocalIndex, keys.RemoteIndex = i.idxC, idxS
	})
	if err != nil {
		return Keys{}, Hello{}, err
	}
	return keys, server, nil
}

// Wipe erases the private key and the state after c1. The client calls it
// once confirmed, or when Dial fails.
func (i *Initiator) Wipe() {
	i.sk = nil
	i.afterC1.wipe()
}

// Responder is the server's side: it answers msg1s for the credentials in
// its store.
//
// It never draws a receiver index itself: the transport owns the index
// table, so it hands in newIndex, which ReadMsg1 calls at most once, after
// every check has passed (transport.md §3.8 step 8). The transport reserves
// what it returns, and frees it if ReadMsg1 then fails anyway.
type Responder struct {
	creds    *Credentials
	hello    Hello
	newIndex func() uint32
}

// NewResponder answers handshakes for creds, offering hello. hello must be
// valid; a server that offers no terminal is a bug, so it panics.
func NewResponder(creds *Credentials, hello Hello, newIndex func() uint32) *Responder {
	if err := hello.check(); err != nil || !hello.Supports(ChannelTerminal) {
		panic(fmt.Sprintf("handshake: the server's own hello is invalid: %+v", hello))
	}
	return &Responder{creds: creds, hello: hello, newIndex: newIndex}
}

// Pending is a handshake the responder has answered and the client has not
// yet confirmed. Up to MaxPending may be pending per credential; the first
// to be confirmed consumes the credential and erases the rest.
type Pending struct {
	// Keys are epoch 0's, handed to the caller of the ReadMsg1 that made
	// the pending. They are the caller's from then on: the store never
	// reads or erases them again, so the transport can copy them into its
	// own key set and wipe these without racing an expiry that Mint, on
	// another goroutine, may trigger.
	Keys Keys
	// Hello is the client's.
	Hello Hello
	// SessionID and CredentialID are public, for revocation (D26) and logs.
	SessionID    [16]byte
	CredentialID [8]byte

	store    *Credentials
	cred     *credential
	msg1Hash [32]byte
	msg2     []byte
	erased   bool
}

// Erased says whether the pending has been erased: its credential expired,
// was evicted or was consumed by another pending, or it was evicted itself.
// The transport frees its index; a packet for it is an unknown index. It
// expires what is due first, so a pending past its credential's TTL reads
// as erased even if nothing else has looked since.
func (p *Pending) Erased() bool {
	p.store.mu.Lock()
	defer p.store.mu.Unlock()
	p.store.expireLocked(time.Now())
	return p.erased
}

// erase forgets the pending: its link to the credential and its cached
// answer. Its Keys are the transport's (see Keys). The caller holds the
// store's lock.
func (p *Pending) erase() {
	p.erased = true
	p.cred = nil
	p.msg2 = nil
}

// ReadMsg1 checks msg1, in order of cost (transport.md §3.8): its length
// and version, the credential id, the credential's state, a byte-identical
// resend, mac1, then the KEM and AEAD on a copy of the state, then the
// hello. It returns msg2 to send back and the pending it answered.
//
// A resend of a msg1 already answered returns the cached msg2 and the same
// *Pending, creating nothing. A msg1 that fails any check changes nothing.
func (r *Responder) ReadMsg1(msg1 []byte) (msg2 []byte, p *Pending, err error) {
	if len(msg1) < Msg1Size(1) || len(msg1) > Msg1Size(MaxChannels) ||
		msg1[0] != TypeMsg1 || msg1[1] != WireVersion {
		return nil, nil, ErrMalformed
	}
	// idx_C names the client's keys in every packet we send it; 0 is never
	// a valid index (transport.md §4.3), so refuse it with the header.
	if binary.LittleEndian.Uint32(msg1[10:]) == 0 {
		return nil, nil, ErrMalformed
	}
	var id [8]byte
	copy(id[:], msg1[2:10])

	c := r.creds
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	c.expireLocked(now)
	cred := c.byID[id]
	if cred == nil {
		return nil, nil, ErrUnknownCredential
	}
	if cred.consumed || !now.Before(cred.expires) {
		return nil, nil, ErrSpent
	}
	hash := sha256.Sum256(msg1)
	for _, p := range cred.pendings {
		if p.msg1Hash == hash {
			return p.msg2, p, nil
		}
	}
	body := msg1[:len(msg1)-mac1Size]
	if !hmac.Equal(mac1(&cred.mac1Key, body), msg1[len(body):]) {
		return nil, nil, ErrAuth
	}

	var keys Keys
	var client Hello
	secretDo(func() {
		st := cred.initial
		defer st.wipe()
		st.mixHash(msg1[:msg1Header])
		enc1 := msg1[msg1Header : msg1Header+EncapsulationSize]
		ss1, kerr := decapsulate(cred.sk, enc1, st.h[:])
		if kerr != nil {
			err = kerr
			return
		}
		st.mixHash(enc1)
		st.mixKey(ss1)
		clear(ss1)
		plain, aerr := st.decryptAndHash(body[msg1Header+EncapsulationSize:])
		if aerr != nil {
			err = aerr
			return
		}
		if client, err = ParseHello(plain); err != nil {
			return
		}
		if err = client.acceptable(); err != nil {
			return
		}

		// Every check has passed: only now draw idx_S, which msg2 and so
		// the transcript carry.
		idxS := r.newIndex()
		idxC := binary.LittleEndian.Uint32(msg1[10:])
		out := make([]byte, 0, Msg2Size(len(client.Channels)))
		out = append(out, TypeMsg2, WireVersion)
		out = binary.LittleEndian.AppendUint32(out, idxS)
		out = binary.LittleEndian.AppendUint32(out, idxC)
		st.mixHash(out)
		enc2, ss2, kerr := encapsulate(cred.clientPublic, st.h[:])
		if kerr != nil {
			err = kerr
			return
		}
		out = append(out, enc2...)
		st.mixHash(enc2)
		st.mixKey(ss2)
		clear(ss2)
		out = append(out, st.encryptAndHash(MarshalHello(r.hello.answer(client)))...)
		i2r, r2i, root := st.split()
		keys.Send, keys.Recv, keys.Root = r2i, i2r, root
		clear(i2r[:])
		clear(r2i[:])
		clear(root[:])
		keys.LocalIndex, keys.RemoteIndex = idxS, idxC
		msg2 = out
	})
	if err != nil {
		return nil, nil, err
	}

	p = &Pending{
		Keys: keys, Hello: client, SessionID: cred.sid, CredentialID: cred.id,
		store: c, cred: cred, msg1Hash: hash, msg2: msg2,
	}
	if len(cred.pendings) >= MaxPending {
		// Random, not oldest: a few forged msg1s then evict the genuine
		// pending with probability 1/4 each, not with certainty, and the
		// client's msg1 resend recovers it if they do (transport.md §3.8).
		victim := rand.IntN(len(cred.pendings))
		evicted := cred.pendings[victim]
		cred.pendings = append(cred.pendings[:victim:victim], cred.pendings[victim+1:]...)
		evicted.erase()
		c.erased = append(c.erased, evicted)
	}
	cred.pendings = append(cred.pendings, p)
	return msg2, p, nil
}

// Confirm consumes p's credential once the first transport packet under
// p's keys has authenticated: the credential's secrets are erased, every
// other pending for it is erased, and later msg1s naming it are refused.
//
// A pending never outlives its credential, so confirming one that is erased
// or whose credential is spent means the caller has a bug: it is refused
// with ErrSpent, and the transport drops the packet and logs it.
func (r *Responder) Confirm(p *Pending) error {
	c := r.creds
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked(time.Now())
	if p.erased || p.cred == nil || p.cred.consumed {
		return ErrSpent
	}
	cred := p.cred
	for _, other := range cred.pendings {
		if other != p {
			other.erase()
			c.erased = append(c.erased, other)
		}
	}
	cred.pendings = nil
	// Keep the id, marked consumed, until the TTL, so that later msg1s
	// naming it are dropped at the cheap step 3.
	clear(cred.psk[:])
	clear(cred.mac1Key[:])
	cred.sk = nil
	cred.initial.wipe()
	cred.consumed = true
	c.unlistLocked(cred)
	p.cred = nil
	return nil
}

// Evict erases p at the transport's request, when it gives the pending up
// itself (too many packets under its keys failed to open). p leaves its
// credential's list, so a resend of its msg1 is answered afresh with new
// keys, never from the cache with the keys the transport has wiped. An
// erased p is left as it is. The transport frees p's index itself, so
// Erased does not hand p over.
func (r *Responder) Evict(p *Pending) {
	c := r.creds
	c.mu.Lock()
	defer c.mu.Unlock()
	if p.erased {
		return
	}
	if cred := p.cred; cred != nil {
		cred.pendings = slices.DeleteFunc(cred.pendings, func(q *Pending) bool { return q == p })
	}
	p.erase()
}

// Erased hands over every pending erased since the last call, by expiry,
// eviction or another's confirmation, so the transport can free their
// receiver indices. It expires what is due first.
func (r *Responder) Erased() []*Pending {
	c := r.creds
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked(time.Now())
	out := c.erased
	c.erased = nil
	return out
}
