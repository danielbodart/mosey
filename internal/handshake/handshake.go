package handshake

import "golang.org/x/crypto/chacha20poly1305"

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
	// Hash is the handshake hash h, which quoin-attest signs (D28).
	Hash [32]byte
}

// Initiator is the client's side of one handshake.
type Initiator struct{}

// NewInitiator starts a handshake with the server that issued cred, using
// the client's own one-shot key from the bootstrap.
func NewInitiator(cred Credential, key *OneShotKey, hello Hello) (*Initiator, error) {
	panic("TODO slice 1")
}

// Msg1 is the first handshake message, at most wire.MaxHandshake bytes. It
// is the same on every call, so a retransmission is a resend of it.
//
// TODO slice 1: S1 measured msg1 at 1208 bytes, 8 over D5's 1200, with a
// 42-byte hello. The hello must shrink (or mac1 move) so msg1 fits; see
// docs/spec/architecture.md.
func (i *Initiator) Msg1() []byte {
	panic("TODO slice 1")
}

// ReadMsg2 finishes the handshake. It changes nothing unless msg2 is
// authentic, so a forged msg2 cannot spoil the real one.
func (i *Initiator) ReadMsg2(msg2 []byte) (Keys, Hello, error) {
	panic("TODO slice 1")
}

// Responder is the server's side: it answers msg1s for the credentials in
// its store.
type Responder struct{}

// NewResponder answers handshakes for creds.
func NewResponder(creds *Credentials, hello Hello) *Responder {
	panic("TODO slice 1")
}

// Pending is a handshake the responder has answered and the client has not
// yet confirmed. Several may be pending per credential (S1 caps them at 4,
// evicting the oldest); the first to be confirmed consumes the credential.
type Pending struct {
	Keys  Keys
	Hello Hello
}

// ReadMsg1 checks msg1 (credential id, mac1, then the KEM and AEAD, in that
// order of cost) and returns msg2 to send back and the pending session. A
// msg1 that fails any check changes nothing.
func (r *Responder) ReadMsg1(msg1 []byte) (msg2 []byte, p *Pending, err error) {
	panic("TODO slice 1")
}

// Confirm consumes p's credential once the first transport packet under
// p.Keys has authenticated, and drops every other pending handshake for it.
func (r *Responder) Confirm(p *Pending) {
	panic("TODO slice 1")
}
