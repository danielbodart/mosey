package netsim

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"
)

// DefaultReadBuffer is how many bytes of payload a socket holds unread
// before it drops what arrives, until SetReadBuffer changes it. It is a
// bound on the memory a flood can take in a test rather than a model of the
// kernel's buffer; a test that wants the kernel's behaviour sets that size.
const DefaultReadBuffer = 4 << 20

// Conn is a UDP-like socket on the simulated network.
//
// Oversized writes are not refused: as on a path that black-holes them,
// the link's MTU drops them silently.
type Conn struct {
	net  *Network
	host *Host
	id   uint64 // in Listen order, to order its deadline events

	// Guarded by net.mu.
	addr       netip.AddrPort
	queue      []packet
	queued     int // payload bytes in queue
	readBuffer int
	closed     bool
	deadline   time.Time
	dlGen      uint64 // bumped by every SetReadDeadline, to ignore stale events
	dlExpired  bool
	rxPackets  int
	rxBytes    int
	// changed is closed, and replaced, whenever a blocked reader may have
	// something to do: a packet, a deadline, Close. Closing a channel wakes
	// every reader, where a buffered signal would wake only one.
	changed chan struct{}
}

type packet struct {
	from netip.AddrPort
	data []byte
}

var _ net.PacketConn = (*Conn)(nil)

// ReadFrom reads one datagram, as a UDP socket does: a datagram longer than
// p is truncated to it.
//
// A packet that has arrived is returned even when the deadline has also
// passed, so that an instant with both goes the same way every run.
func (c *Conn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, from, err := c.ReadFromAddrPort(p)
	if err != nil {
		return 0, nil, err
	}
	return n, net.UDPAddrFromAddrPort(from), nil
}

// WriteTo sends p to addr, which must be a *net.UDPAddr or an address whose
// String is an ip:port.
func (c *Conn) WriteTo(p []byte, addr net.Addr) (int, error) {
	var to netip.AddrPort
	switch a := addr.(type) {
	case *net.UDPAddr:
		to = a.AddrPort()
	default:
		var err error
		if to, err = netip.ParseAddrPort(addr.String()); err != nil {
			return 0, fmt.Errorf("netsim: writing to %v: %w", addr, err)
		}
	}
	return c.WriteToAddrPort(p, to)
}

// ReadFromAddrPort is ReadFrom without the allocation of a net.Addr.
func (c *Conn) ReadFromAddrPort(p []byte) (int, netip.AddrPort, error) {
	n := c.net
	for {
		n.mu.Lock()
		if len(c.queue) > 0 {
			pk := c.queue[0]
			c.queue[0] = packet{}
			c.queue = c.queue[1:]
			c.queued -= len(pk.data)
			n.mu.Unlock()
			return copy(p, pk.data), pk.from, nil
		}
		if c.closed {
			n.mu.Unlock()
			return 0, netip.AddrPort{}, net.ErrClosed
		}
		// Only the scheduler expires a deadline, never a reader comparing
		// time.Now with it: a reader that got there first could time out
		// before the scheduler delivered a packet due at the same instant.
		if c.dlExpired {
			n.mu.Unlock()
			return 0, netip.AddrPort{}, errTimeout
		}
		changed := c.changed
		n.mu.Unlock()
		<-changed
	}
}

// WriteToAddrPort is WriteTo without the allocation of a net.Addr.
//
// It never blocks and never fails while the socket is open: what happens to
// the packet is the link's business, and the writer finds out, as a real
// one does, from what comes back.
func (c *Conn) WriteToAddrPort(p []byte, addr netip.AddrPort) (int, error) {
	n := c.net
	n.mu.Lock()
	defer n.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	now := time.Now()
	from, to := c.addr, unmap(addr)

	var l *Link
	if d, ok := n.conns[to]; ok {
		l = n.links[[2]*Host{c.host, d.host}]
	}
	if l == nil {
		u := n.unrouted
		u.seq++
		u.stats.Sent++
		u.stats.Bytes += len(p)
		u.stats.DroppedNoRoute++
		if n.Trace != nil {
			n.Trace(TraceEvent{At: now, Link: u.name, Seq: u.seq, Size: len(p), Verdict: DroppedNoRoute})
		}
		return len(p), nil
	}

	seq, delivery, verdict := l.admit(now, len(p))
	if n.Trace != nil {
		n.Trace(TraceEvent{At: now, Link: l.name, Seq: seq, Size: len(p), Verdict: verdict, Delivery: delivery})
	}
	data := append([]byte(nil), p...)
	deliver := verdict == Delivered
	if n.Tap != nil {
		tp := &TapPacket{Link: l.name, At: now, From: from, To: to, Data: data, Deliver: deliver, Delivery: delivery}
		if !deliver {
			tp.Delivery = now.Add(l.p.Delay)
		}
		for _, inj := range n.Tap(tp) {
			n.inject(inj)
		}
		if tp.Deliver != deliver {
			l.stats.Tampered++
		}
		deliver = tp.Deliver
		data, from, to, delivery = tp.Data, unmap(tp.From), unmap(tp.To), tp.Delivery
		if delivery.Before(now) {
			delivery = now
		}
	}
	if deliver {
		n.push(&event{
			at: delivery, class: classDeliver, a: l.id, b: seq,
			link: l, seq: seq, from: from, to: to, data: data,
		})
	}
	return len(p), nil
}

// Close closes the socket. Its address is free again at once, and packets
// in flight to it are lost.
func (c *Conn) Close() error {
	c.net.mu.Lock()
	defer c.net.mu.Unlock()
	c.closeLocked()
	return nil
}

func (c *Conn) closeLocked() {
	if c.closed {
		return
	}
	c.closed = true
	if c.net.conns[c.addr] == c {
		delete(c.net.conns, c.addr)
	}
	c.queue, c.queued = nil, 0
	c.signal()
}

// LocalAddr is the socket's address, a *net.UDPAddr, which changes on
// Rebind.
func (c *Conn) LocalAddr() net.Addr {
	c.net.mu.Lock()
	defer c.net.mu.Unlock()
	return net.UDPAddrFromAddrPort(c.addr)
}

// SetDeadline sets the read deadline; writes never block, so they have no
// deadline to set.
func (c *Conn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

// SetReadDeadline makes reads fail with an error satisfying
// errors.Is(err, os.ErrDeadlineExceeded) once t has passed and nothing is
// queued. The zero time clears it.
func (c *Conn) SetReadDeadline(t time.Time) error {
	n := c.net
	n.mu.Lock()
	defer n.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.dlGen++
	c.deadline = t
	c.dlExpired = false
	switch {
	case t.IsZero():
	case t.Before(time.Now()):
		// Everything due before now has been delivered (in a bubble, time
		// moves only once the scheduler is idle), so this cannot race one.
		c.dlExpired = true
	default:
		// Due now or later: the scheduler expires it in order with that
		// instant's deliveries, so a packet due then still wins.
		n.push(&event{at: t, class: classDeadline, a: c.id, b: c.dlGen, conn: c, gen: c.dlGen})
	}
	c.signal()
	return nil
}

// SetWriteDeadline does nothing: writes never block.
func (c *Conn) SetWriteDeadline(t time.Time) error { return nil }

// SetReadBuffer sets how many bytes of payload the socket holds unread
// before it drops what arrives, as a UDP socket's receive buffer does.
func (c *Conn) SetReadBuffer(bytes int) error {
	if bytes < 0 {
		return fmt.Errorf("netsim: a read buffer of %d bytes", bytes)
	}
	c.net.mu.Lock()
	defer c.net.mu.Unlock()
	c.readBuffer = bytes
	return nil
}

// Rebind moves the socket to a new address, as a NAT rebinding or a roam
// from wifi to cellular does. Packets in flight to the old address are
// lost, and the application is not told: it finds out, as a real one does,
// from what arrives.
//
// A test that wants the application told, as netlink tells it on Linux,
// sets Network.Rebound.
func (c *Conn) Rebind(addr netip.AddrPort) error {
	n := c.net
	n.mu.Lock()
	if c.closed {
		n.mu.Unlock()
		return net.ErrClosed
	}
	addr = unmap(addr)
	if !addr.Addr().IsValid() || addr.Addr().IsUnspecified() || addr.Port() == 0 {
		n.mu.Unlock()
		return fmt.Errorf("netsim: rebinding to %v: give the socket a specific address and port", addr)
	}
	if other, ok := n.conns[addr]; ok && other != c {
		n.mu.Unlock()
		return fmt.Errorf("netsim: rebinding to %v: address in use", addr)
	}
	from := c.addr
	delete(n.conns, from)
	c.addr = addr
	n.conns[addr] = c
	rebound := n.Rebound
	n.mu.Unlock()
	if rebound != nil && from != addr {
		rebound(c, from, addr)
	}
	return nil
}

// RxStats is how much the socket has received, so a test can measure what
// an attacker drew towards a victim.
func (c *Conn) RxStats() (packets, bytes int) {
	c.net.mu.Lock()
	defer c.net.mu.Unlock()
	return c.rxPackets, c.rxBytes
}

// receive queues a packet. Called by the scheduler with the lock held.
func (c *Conn) receive(from netip.AddrPort, data []byte) {
	c.rxPackets++
	c.rxBytes += len(data)
	c.queue = append(c.queue, packet{from: from, data: data})
	c.queued += len(data)
	c.signal()
}

// deadlineFired expires the read deadline, unless it has been set again
// since this event was scheduled. Called with the lock held.
func (c *Conn) deadlineFired(gen uint64) {
	if gen != c.dlGen || c.closed {
		return
	}
	c.dlExpired = true
	c.signal()
}

// signal wakes every blocked reader. Called with the lock held.
func (c *Conn) signal() {
	close(c.changed)
	c.changed = make(chan struct{})
}

// errTimeout is what a read past its deadline returns, as the net package's
// is: a net.Error whose Timeout is true, and os.ErrDeadlineExceeded to
// errors.Is.
var errTimeout error = timeoutError{}

type timeoutError struct{}

func (timeoutError) Error() string   { return "netsim: i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
func (timeoutError) Unwrap() error   { return os.ErrDeadlineExceeded }
