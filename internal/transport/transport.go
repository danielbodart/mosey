package transport

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/danielbodart/mosey/internal/handshake"
)

const (
	// RekeyAfter is how long an epoch's keys are used before a rekey
	// (D20; WireGuard's REKEY_AFTER_TIME).
	RekeyAfter = 120 * time.Second
	// AmplificationFactor bounds what an unvalidated address may be sent:
	// this many times what came from it (RFC 9000 §8.1).
	AmplificationFactor = 3
)

// Conn is one end of an established, authenticated connection.
//
// Send and Recv may be called from different goroutines; each must be
// called from only one at a time.
type Conn struct{}

// Send seals payload as a terminal frame and sends it to the peer. A payload
// over MaxPayload is an error. A send the anti-amplification limit holds
// back is dropped and reported as ErrBlocked: SSP treats it as lost and
// sends again, which is what the limit wants.
func (c *Conn) Send(payload []byte) error {
	panic("TODO slice 1")
}

// Recv returns the next authentic terminal payload, handling every other
// kind of frame (rekeys, keepalives, path validation) itself. The returned
// slice is the caller's.
func (c *Conn) Recv(ctx context.Context) ([]byte, error) {
	panic("TODO slice 1")
}

// Events reports what happened to the connection that the layers above may
// want to show or act on. It is buffered, and a slow reader loses the oldest.
func (c *Conn) Events() <-chan Event {
	panic("TODO slice 1")
}

// HandshakeHash is h, the hash of the handshake that made this connection,
// which quoin-attest signs (D28).
func (c *Conn) HandshakeHash() [32]byte {
	panic("TODO slice 1")
}

// Peer is the validated address packets go to.
func (c *Conn) Peer() netip.AddrPort {
	panic("TODO slice 1")
}

// LocalAddressChanged tells the client's transport that its own address
// changed (netlink on Linux, D21), so it sends at once rather than waiting
// for SSP's next datagram, and the server starts validating the new path
// sooner.
func (c *Conn) LocalAddressChanged() {
	panic("TODO slice 1")
}

// Close wipes the connection's keys. Recv returns net.ErrClosed after it.
func (c *Conn) Close() error {
	panic("TODO slice 1")
}

// Dial runs the client's side of the handshake with the server at addr,
// over pc, which the connection then owns. It retransmits msg1 until msg2
// arrives or ctx is done.
func Dial(ctx context.Context, pc net.PacketConn, addr netip.AddrPort, cred handshake.Credential, key *handshake.OneShotKey, log *slog.Logger) (*Conn, error) {
	panic("TODO slice 1")
}

// Listener is the server's side: it reads every datagram on one socket and
// routes it by receiver index, before its source address is trusted, to the
// connection it belongs to, or to the handshake responder.
type Listener struct{}

// Listen serves handshakes for the credentials in creds on pc, which the
// listener then owns.
func Listen(pc net.PacketConn, creds *handshake.Credentials, log *slog.Logger) *Listener {
	panic("TODO slice 1")
}

// Accept returns the next confirmed connection. Under D26 a confirmed
// connection for a session revokes every other connection of that session:
// each is sent KindRevoked and its keys are wiped.
func (l *Listener) Accept(ctx context.Context) (*Conn, error) {
	panic("TODO slice 1")
}

// Close stops the listener and closes every connection it made.
func (l *Listener) Close() error {
	panic("TODO slice 1")
}

// Event is something that happened to a connection.
type Event interface{ event() }

// PeerChanged says the server now sends to a new, validated address.
type PeerChanged struct{ From, To netip.AddrPort }

// Rekeyed says a new epoch's keys are confirmed.
type Rekeyed struct{ Epoch uint64 }

// Revoked says another client took the session over (D26): the client says
// "session taken over from <By> at <At>" and exits.
type Revoked struct {
	By netip.AddrPort
	At time.Time
}

func (PeerChanged) event() {}
func (Rekeyed) event()     {}
func (Revoked) event()     {}

// ErrBlocked is Send's report that anti-amplification held a payload back.
var ErrBlocked = errors.New("transport: held back by the anti-amplification limit")
