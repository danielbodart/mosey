package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/danielbodart/mosey/internal/handshake"
	"github.com/danielbodart/mosey/internal/wire"
)

// Timers and limits, each from transport.md §12, which says where it comes
// from.
const (
	// RekeyAfter is how long an epoch's keys are used before the client
	// starts a rekey (D20; WireGuard's REKEY_AFTER_TIME).
	RekeyAfter = 120 * time.Second
	// serverRekeyAfter is the server's backstop, 10 s later so the two
	// rarely collide, for a client that never rekeys [D].
	serverRekeyAfter = RekeyAfter + 10*time.Second
	// RekeyAfterMessages is D20's "N packets" (WireGuard's
	// REKEY_AFTER_MESSAGES).
	RekeyAfterMessages = 1 << 60
	// RejectAfterMessages is the counter a sender never seals at and a
	// receiver drops at, leaving room above the replay window so a counter
	// never wraps (WireGuard's REJECT_AFTER_MESSAGES).
	RejectAfterMessages = 1<<64 - 1<<13 - 1
	// RejectAfterTime is the age past which a side seals no terminal frame
	// under its current keys, so blocking only the rekey frames stalls the
	// session rather than stretching one epoch, and what a memory compromise
	// exposes, without bound (WireGuard's REJECT_AFTER_TIME; transport.md
	// §6.2).
	RejectAfterTime = 180 * time.Second
	// RekeyRetry is how often REKEY_INIT and the rekey confirmation are
	// resent until answered (S1, untuned).
	RekeyRetry = time.Second
	// RekeyMinEpochAge is how young a current epoch may be for a responder
	// to ignore an INIT, so a hostile peer can force at most one KEM answer
	// a second (threat-model.md §4.3's floor).
	RekeyMinEpochAge = time.Second
	// KeepPrevFor is how long the previous epoch's keys still receive after
	// a rotation, for packets in flight (S1, untuned).
	KeepPrevFor = 10 * time.Second
	// MaxFailedOpens is how many forgeries one receive key survives:
	// ChaCha20-Poly1305's integrity limit (RFC 9001 §6.6). Unreachable in a
	// 120 s epoch, but counting is cheap and makes the bound hold whatever
	// the rekey does.
	MaxFailedOpens = 1 << 36

	// AmplificationFactor bounds what an unvalidated address may be sent:
	// this many times what came from it (RFC 9000 §8.1).
	AmplificationFactor = 3
	// challengeFirst, challengeCap and candidateLife time a path challenge:
	// resent after 250 ms, doubling to 1 s, abandoned after 10 s (ours; the
	// floor is above D11's effective RTO floor and the cap is its RTO cap).
	challengeFirst = 250 * time.Millisecond
	challengeCap   = time.Second
	candidateLife  = 10 * time.Second

	// handshakeFirst and handshakeCap time msg1 and confirmation resends:
	// RFC 6298 §2.1's initial RTO, doubling to 4 s [D].
	handshakeFirst = time.Second
	handshakeCap   = 4 * time.Second

	// revokedCopies is how many REVOKED frames a revocation seals, and
	// tombstoneLife how long the revoked indices answer with them [D].
	revokedCopies  = 4
	tombstoneLife  = 60 * time.Second
	tombstoneEvery = 250 * time.Millisecond

	// endCopies and endSpacing are how End repeats its END frame: three
	// copies 100 ms apart, so one loss, or a burst of loss shorter than
	// 100 ms, still gets one through, and a quitting client is held up
	// 200 ms at most [D]. The peer may be gone a moment later, so
	// nothing waits for an answer.
	endCopies  = 3
	endSpacing = 100 * time.Millisecond

	// recvQueue is how many terminal payloads wait for Recv before more are
	// dropped. SSP treats a drop as loss and sends its state again, so the
	// queue only has to ride out a scheduling hiccup: 256 payloads is a
	// full 16-fragment burst sixteen times over, about 300 KiB [D].
	recvQueue = 256
	// eventQueue is how many events wait for a reader before the oldest go.
	// Events are rare (a rekey every 120 s, a path change, the end) and
	// only logged or acted on once, so a short queue loses nothing a
	// reader that keeps up would see [D].
	eventQueue = 16

	maxDatagram = wire.MaxDatagram
)

// Overhead is what the transport adds to a payload: a 13-byte clear header
// (type, receiver index, counter), the 1-byte frame kind and the 16-byte
// Poly1305 tag.
const Overhead = headerSize + 1 + 16

// MaxPayload is the largest payload Send accepts: what is left of a
// datagram (D5) once the transport has framed and sealed it.
const MaxPayload = wire.MaxDatagram - Overhead

var (
	// ErrBlocked is Send's report that a payload was held back: by the
	// anti-amplification limit, or because the keys are past
	// RejectAfterTime and the rekey has not got through. SSP treats it as a
	// loss and sends again, which is what both limits want.
	ErrBlocked = errors.New("transport: payload held back")
	// ErrRevoked is what a connection fails with once another client has
	// taken the session over (D26). It is a net.ErrClosed.
	ErrRevoked = fmt.Errorf("transport: session taken over: %w", net.ErrClosed)
	// ErrEnded is what a connection fails with once the peer has said the
	// session is over with an END frame (transport.md §8.4). It is a
	// net.ErrClosed.
	ErrEnded = fmt.Errorf("transport: the peer ended the session: %w", net.ErrClosed)

	errOverdue   = fmt.Errorf("%w (the keys are past RejectAfterTime; waiting for the rekey)", ErrBlocked)
	errWiped     = errors.New("transport: keys wiped")
	errExhausted = fmt.Errorf("transport: a key reached RejectAfterMessages: %w", net.ErrClosed)
	errForgeries = fmt.Errorf("transport: a key reached its limit of failed opens: %w", net.ErrClosed)
)

// Event is something that happened to a connection.
type Event interface{ event() }

// PeerChanged says the server now sends to a new, validated address. From
// is invalid if there was no validated address before.
type PeerChanged struct{ From, To netip.AddrPort }

// Rekeyed says a new epoch's keys are confirmed. Epoch counts rotations
// from 0, the handshake's; it is local and never sent.
type Rekeyed struct{ Epoch uint64 }

// RekeyOverdue says the current keys reached RejectAfterTime without a
// rekey completing, so terminal frames are held back until one does
// (transport.md §6.2). It is reported once per epoch.
type RekeyOverdue struct{ Age time.Duration }

// Revoked says another client took the session over (D26): the client says
// "session taken over from <By> at <At>" and exits.
type Revoked struct {
	By netip.AddrPort
	At time.Time
}

// Ended says the peer ended the session with an END frame (transport.md
// §8.4), for Reason. The connection is closed with ErrEnded.
type Ended struct{ Reason EndReason }

// EndReason is why a session ended: the one byte of an END frame's body.
// A reason this build does not know still ends the session.
type EndReason uint8

const (
	// EndShellExited: the server's login shell exited.
	EndShellExited EndReason = 0x01
	// EndClientQuit: the client's user quit, or its terminal went away.
	EndClientQuit EndReason = 0x02
)

func (r EndReason) String() string {
	switch r {
	case EndShellExited:
		return "the shell exited"
	case EndClientQuit:
		return "the client quit"
	}
	return fmt.Sprintf("reason %#02x", uint8(r))
}

func (PeerChanged) event()  {}
func (Rekeyed) event()      {}
func (RekeyOverdue) event() {}
func (Revoked) event()      {}
func (Ended) event()        {}

// Stats is what a connection or listener has counted.
type Stats struct {
	// Dropped is datagrams dropped, by reason.
	Dropped Drops
	// Blocked is sends held back by the anti-amplification limit.
	Blocked uint64
	// QueueFull is terminal payloads dropped because Recv was not keeping up.
	QueueFull uint64
}

// clientHello and serverHello are what this build offers: the terminal
// channel, exclusive attach (D15, D26).
var (
	clientHello = handshake.Hello{Version: handshake.Revision, Channels: []handshake.ChannelType{handshake.ChannelTerminal}, Attach: handshake.Exclusive}
	serverHello = clientHello
)

// Recv returns the next authentic terminal payload, handling every other
// kind of frame (rekeys, keepalives, path validation) itself. The returned
// slice is the caller's.
func (c *Conn) Recv(ctx context.Context) ([]byte, error) {
	select {
	case p := <-c.recvq:
		return p, nil
	default:
	}
	select {
	case p := <-c.recvq:
		return p, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.done:
		return nil, c.err
	}
}

// Events reports what happened to the connection that the layers above may
// want to show or act on. It is buffered, and a slow reader loses the
// oldest.
func (c *Conn) Events() <-chan Event { return c.events }

// HandshakeHash is h, the hash of the handshake that made this connection,
// which quoin-attest signs (D28). A rekey does not change it.
func (c *Conn) HandshakeHash() [32]byte { return c.hash }

// Peer is the validated address packets go to: on the client, the
// server's; on the server, the client's, or the zero AddrPort while none is
// validated.
func (c *Conn) Peer() netip.AddrPort {
	c.e.lock()
	defer c.e.unlock()
	if c.server {
		return c.peer
	}
	return c.serverAddr
}

// Stats is what the connection has counted.
func (c *Conn) Stats() Stats {
	c.e.lock()
	defer c.e.unlock()
	s := c.stats
	s.Dropped = c.e.drops.count
	return s
}

// LocalAddressChanged tells the client's transport that its own address
// changed (netlink on Linux, D21), so it sends at once rather than waiting
// for SSP's next datagram, and the server starts validating the new path
// sooner (transport.md §7.4).
func (c *Conn) LocalAddressChanged() {
	c.e.lock()
	defer c.e.unlock()
	if !c.closed {
		c.sendFrame(KindKeepalive, keepaliveAnswer)
	}
}

// Close wipes the connection's keys. Recv returns net.ErrClosed after it.
// On the client it also closes the socket Dial was given.
func (c *Conn) Close() error {
	c.e.lock()
	defer c.e.unlock()
	c.shutdown(net.ErrClosed)
	return nil
}

// End tells the peer the session is over, for reason, and then closes the
// connection as Close does. It sends endCopies END frames endSpacing apart,
// so it blocks for up to 200 ms; there is no answer to wait for
// (transport.md §8.4). Once the connection is closed it does nothing more.
func (c *Conn) End(reason EndReason) error {
	for i := range endCopies {
		if i > 0 {
			time.Sleep(endSpacing)
		}
		c.e.lock()
		if c.closed {
			c.e.unlock()
			return nil
		}
		c.sendFrame(KindEnd, []byte{byte(reason)})
		c.e.unlock()
	}
	return c.Close()
}

// Send seals payload as a terminal frame and sends it to the peer. A payload
// over MaxPayload is an error. A send held back is dropped and reported as
// ErrBlocked: SSP treats it as lost and sends again.
func (c *Conn) Send(payload []byte) error {
	if len(payload) > MaxPayload {
		return fmt.Errorf("transport: a payload of %d bytes, over %d", len(payload), MaxPayload)
	}
	c.e.lock()
	defer c.e.unlock()
	if c.closed {
		return c.err
	}
	now := time.Now()
	c.maybeRekey(now)
	if age := now.Sub(c.cur.installed); age >= RejectAfterTime {
		if !c.overdue {
			c.overdue = true
			c.e.log.Warn("the session keys are past their limit and no rekey has got through; holding the terminal back",
				"age", age.Round(time.Second))
			c.emit(RekeyOverdue{Age: age})
		}
		return errOverdue
	}
	pkt, err := c.cur.seal(KindTerminal, payload)
	if err != nil {
		c.shutdown(err)
		return err
	}
	if !c.route(pkt) {
		c.stats.Blocked++
		return ErrBlocked
	}
	return nil
}
