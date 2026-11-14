package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/danielbodart/mosey/internal/handshake"
)

// clientHandshake is the client's side of transport.md §3.9's state
// machine, from Dial until CONFIRMED.
type clientHandshake struct {
	ini  *handshake.Initiator
	msg1 []byte
	// accepted is the msg2 the current epoch-0 keys came from. A
	// byte-identical one (the server's cached answer to a resend) is
	// ignored; a different authentic one replaces the keys.
	accepted    []byte
	established bool

	deadline time.Time
	next     time.Time
	interval time.Duration
	addr     netip.AddrPort

	done chan struct{}
	err  error
}

// Dial runs the client's side of the handshake with the server at addr,
// over pc, which the connection then owns: Close closes it, and so does a
// failed Dial.
//
// It returns only once the server has confirmed the connection, by sending
// anything under the new keys (transport.md §3.9): a client that returned
// earlier could send into an index the server never kept, for ever, with
// nothing to say so. It retransmits msg1, and once msg2 has arrived the
// confirmation with msg1 beside it, until then, ctx is done, or
// handshake.CredentialTTL has passed, which is when the server forgets the
// credential.
func Dial(ctx context.Context, pc net.PacketConn, addr netip.AddrPort, cred handshake.Credential, key *handshake.OneShotKey, log *slog.Logger) (*Conn, error) {
	return DialOffering(ctx, pc, addr, cred, key, nil, log)
}

// DialOffering is Dial with the channel types the client can serve
// besides the terminal (D15): the agent, when it has a pinned bind
// (bootstrap.md §7.3). The connection carries those the server supports
// too; Conn.Channels says which.
func DialOffering(ctx context.Context, pc net.PacketConn, addr netip.AddrPort, cred handshake.Credential, key *handshake.OneShotKey, offer []handshake.ChannelType, log *slog.Logger) (*Conn, error) {
	hello := clientHello
	hello.Channels = slices.Clone(hello.Channels)
	for _, ch := range offer {
		if !slices.Contains(hello.Channels, ch) {
			hello.Channels = append(hello.Channels, ch)
		}
	}
	slices.Sort(hello.Channels)
	e := newEngine(pc, log)
	c := newConn(e, false, nil, &[32]byte{}, &[32]byte{})
	c.serverAddr = unmap(addr)

	e.lock()
	idxC := e.table.reserve()
	ini, err := handshake.NewInitiator(cred, key, hello, idxC)
	if err != nil {
		e.table.free(idxC)
		c.shutdown(net.ErrClosed)
		e.unlock()
		return nil, fmt.Errorf("starting the handshake: %w", err)
	}
	e.table.set(idxC, c)
	now := time.Now()
	c.hs = &clientHandshake{
		ini: ini, msg1: ini.Msg1(), addr: c.serverAddr,
		deadline: now.Add(handshake.CredentialTTL),
		next:     now.Add(handshakeFirst), interval: handshakeFirst,
		done: make(chan struct{}),
	}
	hs := c.hs
	e.send(hs.msg1, c.serverAddr)
	e.unlock()

	go c.readLoop()
	go c.run()

	select {
	case <-hs.done:
	case <-ctx.Done():
		e.lock()
		if c.hs != nil { // not confirmed in the meantime
			c.shutdown(fmt.Errorf("handshaking with %v: %w", addr, ctx.Err()))
		}
		e.unlock()
		<-hs.done
	}
	if hs.err != nil {
		return nil, hs.err
	}
	return c, nil
}

// readLoop reads the client's socket until it closes.
func (c *Conn) readLoop() {
	buf := make([]byte, maxDatagram+1)
	for {
		n, from, err := c.e.sock.read(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				c.e.lock()
				c.shutdown(net.ErrClosed)
				c.e.unlock()
				return
			}
			c.e.lock()
			closed := c.closed
			c.e.unlock()
			if closed {
				return
			}
			continue // a transient error, such as ICMP unreachable on Linux
		}
		c.e.lock()
		c.handleClientDatagram(buf[:n], from)
		c.e.unlock()
	}
}

// handleClientDatagram routes one datagram on the client. It accepts msg2
// and data from any source: the authentication, not the address, says who
// sent it (transport.md §7.1).
func (c *Conn) handleClientDatagram(pkt []byte, from netip.AddrPort) {
	if c.closed {
		return
	}
	if len(pkt) == 0 || len(pkt) > maxDatagram {
		c.e.drop(Malformed, from, "size")
		return
	}
	switch pkt[0] {
	case TypeMsg2:
		if c.hs == nil {
			c.e.drop(State, from, "msg2 after confirmation")
			return
		}
		c.hs.onMsg2(c, pkt, from)
	case TypeData:
		if len(pkt) < Overhead {
			c.e.drop(Malformed, from, "short data packet")
			return
		}
		idx := binary.LittleEndian.Uint32(pkt[1:])
		if c.e.table.get(idx) != c {
			c.e.drop(UnknownIndex, from, "data packet")
			return
		}
		c.receive(pkt, from, idx)
	default:
		c.e.drop(Malformed, from, "type")
	}
}

func (hs *clientHandshake) onMsg2(c *Conn, pkt []byte, from netip.AddrPort) {
	if hs.accepted != nil && bytes.Equal(pkt, hs.accepted) {
		return // the cached answer to a resend: nothing new
	}
	keys, server, err := hs.ini.ReadMsg2(pkt)
	if err != nil {
		if errors.Is(err, handshake.ErrIncompatible) {
			// Authentic, so the server is genuine and incompatible:
			// waiting will not help.
			c.shutdown(fmt.Errorf("the server at %v cannot serve this client: %w", hs.addr, err))
			return
		}
		c.e.drop(reasonFor(err), from, "msg2")
		return
	}
	if c.cur != nil {
		// A re-answered msg2: the server lost our first pending (forged
		// msg1s evicted it), so its new answer's keys replace the old.
		c.cur.wipe()
	}
	c.cur = newKeyset(&keys, time.Now())
	c.root, c.hash = keys.Root, keys.Hash
	keys.Wipe()
	hs.accepted = bytes.Clone(pkt)
	c.channels = slices.Clone(server.Channels)
	hs.established = true
	c.sendFrame(KindKeepalive, keepaliveAnswer)
}

// tick resends msg1, and once established the confirmation beside it, on
// the 1 s doubling timer, and fails Dial at the deadline.
func (hs *clientHandshake) tick(c *Conn, now time.Time) {
	if !now.Before(hs.deadline) {
		if hs.established {
			c.shutdown(fmt.Errorf("the server at %v answered over UDP but never confirmed the connection", hs.addr))
		} else {
			c.shutdown(fmt.Errorf("no answer over UDP from %v within %v: is the port blocked?", hs.addr, handshake.CredentialTTL))
		}
		return
	}
	if now.Before(hs.next) {
		return
	}
	hs.interval = min(2*hs.interval, handshakeCap)
	hs.next = now.Add(hs.interval)
	c.e.send(hs.msg1, c.serverAddr)
	if hs.established {
		c.sendFrame(KindKeepalive, keepaliveAnswer)
	}
}

// confirm is CONFIRMED: Dial returns, and the private key and the state
// after c1 are erased.
func (hs *clientHandshake) confirm(c *Conn) {
	hs.ini.Wipe()
	c.hs = nil
	close(hs.done)
}

// fail ends Dial with err and erases what the handshake kept.
func (hs *clientHandshake) fail(err error) {
	hs.ini.Wipe()
	hs.err = err
	close(hs.done)
}

// reasonFor maps a handshake error to the drop it counts as.
func reasonFor(err error) Reason {
	switch {
	case errors.Is(err, handshake.ErrMalformed):
		return Malformed
	case errors.Is(err, handshake.ErrUnknownCredential):
		return UnknownCredential
	case errors.Is(err, handshake.ErrAuth):
		return Auth
	default:
		return State
	}
}
