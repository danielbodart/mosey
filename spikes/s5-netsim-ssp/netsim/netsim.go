// Package netsim is a deterministic simulated datagram network for use under
// testing/synctest (virtual time). It provides net.PacketConn endpoints joined
// by per-direction links that model delay, jitter, reordering, MTU limits,
// continuous-time Gilbert-Elliott burst loss, outages, address changes
// (roaming / NAT rebinding) and Mahimahi-style capacity traces.
//
// Determinism. All delivery and read-deadline events go through one
// scheduler goroutine that owns a single timer and processes the events due
// at an instant in a fixed order (time, class, link, per-link sequence). Every
// random decision for a packet is drawn from a PRNG seeded by (network seed,
// link id, per-link packet sequence), and Gilbert-Elliott state is a function
// of time drawn from its own seeded stream. So, provided every endpoint is a
// single goroutine whose behaviour depends only on what it reads and on
// time.Now, a run is a pure function of the seed, whatever order the Go
// scheduler happens to run goroutines in within an instant.
//
// The package uses only time.Now / time.Timer, so outside a synctest bubble it
// also works in real time (useful for ad-hoc demos, never for assertions).
package netsim

import (
	"container/heap"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
)

// Network is a set of hosts, their conns and the links between hosts.
type Network struct {
	seed uint64

	mu      sync.Mutex
	conns   map[netip.AddrPort]*Conn
	links   map[[2]*Host]*Link
	events  eventHeap
	nextKey uint64
	closed  bool
	wake    chan struct{}
	done    chan struct{}
	stats   map[string]*LinkStats

	// Trace, if non-nil, is called (with the network lock held) for every
	// packet decision. Used by determinism tests and debugging.
	Trace func(ev TraceEvent)
}

// TraceEvent describes what happened to one packet.
type TraceEvent struct {
	At       time.Time
	Link     string
	Seq      uint64
	Size     int
	Verdict  string // "deliver", "drop-mtu", "drop-loss", "drop-outage", "drop-queue", "drop-noroute"
	Delivery time.Time
}

// New creates a network and starts its scheduler goroutine. Call Close when
// done so the goroutine exits (synctest requires this).
func New(seed uint64) *Network {
	n := &Network{
		seed:  seed,
		conns: map[netip.AddrPort]*Conn{},
		links: map[[2]*Host]*Link{},
		wake:  make(chan struct{}, 1),
		done:  make(chan struct{}),
		stats: map[string]*LinkStats{},
	}
	go n.run()
	return n
}

// Close stops the scheduler and closes every conn.
func (n *Network) Close() {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return
	}
	n.closed = true
	conns := make([]*Conn, 0, len(n.conns))
	for _, c := range n.conns {
		conns = append(conns, c)
	}
	n.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
	close(n.done)
}

// Host is a named machine. Links are between hosts; conns live on hosts.
type Host struct {
	Name string
	net  *Network
}

// NewHost creates a host.
func (n *Network) NewHost(name string) *Host { return &Host{Name: name, net: n} }

// Connect installs a link from a to b with the given parameters (one
// direction). Call it twice for a bidirectional path.
func (n *Network) Connect(a, b *Host, p LinkParams) *Link {
	n.mu.Lock()
	defer n.mu.Unlock()
	id := uint64(len(n.links) + 1)
	l := newLink(id, a.Name+"->"+b.Name, n.seed, p)
	n.links[[2]*Host{a, b}] = l
	n.stats[l.name] = &l.Stats
	return l
}

// Stats returns a copy of per-link statistics.
func (n *Network) Stats() map[string]LinkStats {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := map[string]LinkStats{}
	for k, v := range n.stats {
		out[k] = *v
	}
	return out
}

// Listen opens a conn on host h at addr.
func (h *Host) Listen(addr netip.AddrPort) (*Conn, error) {
	n := h.net
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.conns[addr]; ok {
		return nil, fmt.Errorf("netsim: %v in use", addr)
	}
	c := &Conn{net: n, host: h, addr: addr, notify: make(chan struct{}, 1)}
	n.conns[addr] = c
	return c, nil
}

// Rebind moves conn c to a new local address, as a NAT rebinding or a roam
// to a new network would. Packets in flight to the old address are lost
// (nothing listens there any more). The application is not told.
func (c *Conn) Rebind(addr netip.AddrPort) error {
	n := c.net
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.conns[addr]; ok {
		return fmt.Errorf("netsim: %v in use", addr)
	}
	delete(n.conns, c.addr)
	c.addr = addr
	n.conns[addr] = c
	return nil
}

// ---- scheduler ----

const (
	classDeliver  = 0 // deliveries before deadlines at the same instant
	classDeadline = 1
	classFunc     = 2
)

type event struct {
	at    time.Time
	class int
	a, b  uint64 // tie-breakers: (link id, link seq) or (conn id, gen)
	// delivery
	dst  netip.AddrPort
	src  netip.AddrPort
	data []byte
	link *Link
	seq  uint64
	// deadline
	conn *Conn
	gen  uint64
	// func
	fn func()
}

type eventHeap []*event

func (h eventHeap) Len() int { return len(h) }
func (h eventHeap) Less(i, j int) bool {
	x, y := h[i], h[j]
	if !x.at.Equal(y.at) {
		return x.at.Before(y.at)
	}
	if x.class != y.class {
		return x.class < y.class
	}
	if x.a != y.a {
		return x.a < y.a
	}
	return x.b < y.b
}
func (h eventHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *eventHeap) Push(x any)   { *h = append(*h, x.(*event)) }
func (h *eventHeap) Pop() any {
	old := *h
	e := old[len(old)-1]
	*h = old[:len(old)-1]
	return e
}

func (n *Network) push(e *event) {
	heap.Push(&n.events, e)
	select {
	case n.wake <- struct{}{}:
	default:
	}
}

// At runs fn on the scheduler goroutine at time t (ordered after deliveries
// and deadlines due at the same instant, then by registration order). fn
// runs with no lock held. Used for scripted events such as roaming.
func (n *Network) At(t time.Time, fn func()) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.nextKey++
	n.push(&event{at: t, class: classFunc, a: n.nextKey, fn: fn})
}

func (n *Network) run() {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		var fns []func()
		n.mu.Lock()
		now := time.Now()
		for len(n.events) > 0 && !n.events[0].at.After(now) {
			e := heap.Pop(&n.events).(*event)
			switch e.class {
			case classDeliver:
				n.deliver(e)
			case classDeadline:
				e.conn.deadlineFired(e.gen)
			case classFunc:
				fns = append(fns, e.fn)
			}
		}
		var wait time.Duration = time.Hour
		if len(n.events) > 0 {
			wait = n.events[0].at.Sub(now)
		}
		closed := n.closed
		n.mu.Unlock()
		for _, fn := range fns {
			fn()
		}
		if closed {
			return
		}
		if len(fns) > 0 {
			continue // fns may have scheduled events due now
		}
		timer.Reset(wait)
		select {
		case <-timer.C:
		case <-n.wake:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-n.done:
			return
		}
	}
}

func (n *Network) deliver(e *event) {
	c, ok := n.conns[e.dst]
	if !ok || c.closed {
		e.link.Stats.DroppedNoRoute++
		return
	}
	e.link.Stats.Delivered++
	c.queue = append(c.queue, packet{data: e.data, from: e.src})
	c.signal()
}

// ---- Conn ----

type packet struct {
	data []byte
	from netip.AddrPort
}

// Conn is a simulated UDP socket implementing net.PacketConn.
type Conn struct {
	net  *Network
	host *Host

	// guarded by net.mu
	addr       netip.AddrPort
	queue      []packet
	closed     bool
	deadline   time.Time
	dlGen      uint64
	dlExpired  bool
	notify     chan struct{}
	sendSeq    uint64
}

var errTimeout = &timeoutError{}

type timeoutError struct{}

func (*timeoutError) Error() string   { return "i/o timeout" }
func (*timeoutError) Timeout() bool   { return true }
func (*timeoutError) Temporary() bool { return true }
func (*timeoutError) Unwrap() error   { return os.ErrDeadlineExceeded }

func (c *Conn) signal() {
	select {
	case c.notify <- struct{}{}:
	default:
	}
}

func (c *Conn) deadlineFired(gen uint64) {
	if gen != c.dlGen {
		return
	}
	c.dlExpired = true
	c.signal()
}

// ReadFrom implements net.PacketConn. A queued packet always wins over an
// expired deadline, so an instant with both a delivery and a deadline is
// handled the same way every run.
func (c *Conn) ReadFrom(p []byte) (int, net.Addr, error) {
	ap, n, err := c.readFrom(p)
	if err != nil {
		return 0, nil, err
	}
	return n, net.UDPAddrFromAddrPort(ap), nil
}

// ReadFromAddrPort is ReadFrom returning a netip.AddrPort.
func (c *Conn) ReadFromAddrPort(p []byte) (int, netip.AddrPort, error) {
	ap, n, err := c.readFrom(p)
	return n, ap, err
}

func (c *Conn) readFrom(p []byte) (netip.AddrPort, int, error) {
	for {
		c.net.mu.Lock()
		if len(c.queue) > 0 {
			pk := c.queue[0]
			c.queue[0] = packet{}
			c.queue = c.queue[1:]
			c.net.mu.Unlock()
			n := copy(p, pk.data)
			return pk.from, n, nil
		}
		if c.closed {
			c.net.mu.Unlock()
			return netip.AddrPort{}, 0, net.ErrClosed
		}
		if c.dlExpired || (!c.deadline.IsZero() && !time.Now().Before(c.deadline)) {
			c.net.mu.Unlock()
			return netip.AddrPort{}, 0, errTimeout
		}
		c.net.mu.Unlock()
		<-c.notify
	}
}

// WriteTo implements net.PacketConn.
func (c *Conn) WriteTo(p []byte, addr net.Addr) (int, error) {
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("netsim: need *net.UDPAddr")
	}
	return c.WriteToAddrPort(p, ua.AddrPort())
}

// WriteToAddrPort sends p to dst.
func (c *Conn) WriteToAddrPort(p []byte, dst netip.AddrPort) (int, error) {
	n := c.net
	n.mu.Lock()
	defer n.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	dst = netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
	now := time.Now()
	d, ok := n.conns[dst]
	if !ok {
		// Nothing there now; still count it on no link.
		return len(p), nil
	}
	l := n.links[[2]*Host{c.host, d.host}]
	if l == nil {
		return len(p), nil
	}
	data := append([]byte(nil), p...)
	seq, at, verdict := l.admit(now, len(p))
	if n.Trace != nil {
		n.Trace(TraceEvent{At: now, Link: l.name, Seq: seq, Size: len(p), Verdict: verdict, Delivery: at})
	}
	if verdict != "deliver" {
		return len(p), nil
	}
	n.push(&event{at: at, class: classDeliver, a: l.id, b: seq, dst: dst, src: c.addr, data: data, link: l, seq: seq})
	return len(p), nil
}

// Close implements net.PacketConn.
func (c *Conn) Close() error {
	c.net.mu.Lock()
	defer c.net.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.net.conns[c.addr] == c {
		delete(c.net.conns, c.addr)
	}
	c.signal()
	return nil
}

// LocalAddr implements net.PacketConn.
func (c *Conn) LocalAddr() net.Addr {
	c.net.mu.Lock()
	defer c.net.mu.Unlock()
	return net.UDPAddrFromAddrPort(c.addr)
}

// SetDeadline implements net.PacketConn (write deadlines are ignored: writes
// never block).
func (c *Conn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

// SetWriteDeadline implements net.PacketConn.
func (c *Conn) SetWriteDeadline(time.Time) error { return nil }

// SetReadDeadline implements net.PacketConn.
func (c *Conn) SetReadDeadline(t time.Time) error {
	n := c.net
	n.mu.Lock()
	defer n.mu.Unlock()
	c.dlGen++
	c.deadline = t
	c.dlExpired = false
	if !t.IsZero() {
		if !t.After(time.Now()) {
			c.dlExpired = true
			c.signal()
		} else {
			n.push(&event{at: t, class: classDeadline, a: uint64(c.addr.Port()), b: c.dlGen, conn: c, gen: c.dlGen})
		}
	}
	return nil
}

var _ net.PacketConn = (*Conn)(nil)
