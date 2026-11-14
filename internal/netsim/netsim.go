package netsim

import (
	"container/heap"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// Network is one simulated network: its hosts, the links between them and
// the scheduler that delivers packets. It owns one goroutine, started by
// New and stopped by Close.
type Network struct {
	// Tap, if set, sees every packet written to a link after the link has
	// decided its fate, and may change that fate, its bytes, its source or
	// destination, or when it arrives, and may return packets to inject.
	// It is the on-path adversary of S5 §6. Set it before traffic flows.
	//
	// It is called with the network's lock held, so it must not call back
	// into the network: it returns what it wants injected instead. A tap
	// that makes random choices should draw them from its own seeded PRNG,
	// and the run stays a pure function of the seeds.
	Tap func(p *TapPacket) []Injection

	// Trace, if set, is told the fate of every packet, for tests that
	// assert on what the network did rather than on what arrived. It is
	// called with the network's lock held, like Tap. The verdict is the
	// link's, before the Tap sees the packet. A packet a link
	// delivers is traced when it is written; one that is then lost on
	// arrival (its address went away, or the socket's receive buffer was
	// full) is traced again when it arrives, with the same link and Seq.
	Trace func(ev TraceEvent)

	// Rebound, if set, is told when a socket has moved to a new address,
	// for a test that plays the part of the operating system telling the
	// application its address changed (netlink, D21). It runs with no lock
	// held on the goroutine that called Rebind, which for a profile's roam
	// is the scheduler's, so it must not block. Set it before traffic flows.
	Rebound func(c *Conn, from, to netip.AddrPort)

	seed  uint64
	start time.Time

	mu       sync.Mutex
	hosts    map[string]*Host
	conns    map[netip.AddrPort]*Conn
	links    map[[2]*Host]*Link
	order    []*Link // in Connect order, for Stats
	injected *Link   // the pseudo-link injected packets are counted on
	unrouted *Link   // the pseudo-link for writes to nowhere
	events   eventHeap
	nextKey  uint64
	nextConn uint64
	closed   bool
	wake     chan struct{}
	done     chan struct{}
}

// New is an empty network whose every random choice derives from seed.
func New(seed uint64) *Network {
	n := &Network{
		seed:  seed,
		start: time.Now(),
		hosts: map[string]*Host{},
		conns: map[netip.AddrPort]*Conn{},
		links: map[[2]*Host]*Link{},
		wake:  make(chan struct{}, 1),
		done:  make(chan struct{}),
	}
	// Their ids sort after every real link's, so at one instant injected
	// packets arrive after the links' packets, in the order they were made.
	n.injected = &Link{net: n, id: injectedLinkID, name: "injected"}
	n.unrouted = &Link{net: n, id: injectedLinkID - 1, name: "unrouted"}
	go n.run()
	return n
}

// Close stops the scheduler. Reads blocked on any of the network's sockets
// return net.ErrClosed. Packets still in flight are never delivered.
func (n *Network) Close() {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return
	}
	n.closed = true
	for _, c := range n.conns {
		c.closeLocked()
	}
	n.events = nil
	n.mu.Unlock()
	close(n.done)
}

// Start is the network's time zero, from which every Window and every
// trace is measured.
func (n *Network) Start() time.Time { return n.start }

// NewHost adds a host. A host owns addresses; sockets on it Listen on one.
// Host names name links, so they must be unique.
func (n *Network) NewHost(name string) *Host {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.hosts[name]; ok {
		panic(fmt.Sprintf("netsim: a host called %q already exists", name))
	}
	h := &Host{Name: name, net: n}
	n.hosts[name] = h
	return h
}

// Connect adds a one-way link from one host to another: packets from any of
// from's sockets to any of to's addresses take it. A path needs a link each
// way, which is what lets a test make the two directions differ, as
// cellular uplinks and downlinks do.
//
// A host may be connected to itself, for two sockets on one machine. Two
// links the same way between the same hosts are a mistake in the test, and
// panic.
func (n *Network) Connect(from, to *Host, p LinkParams) *Link {
	n.mu.Lock()
	defer n.mu.Unlock()
	key := [2]*Host{from, to}
	if _, ok := n.links[key]; ok {
		panic(fmt.Sprintf("netsim: %s->%s is already connected", from.Name, to.Name))
	}
	l := &Link{net: n, id: uint64(len(n.order) + 1), name: from.Name + "->" + to.Name}
	l.setParams(n.start, p)
	n.links[key] = l
	n.order = append(n.order, l)
	return l
}

// Link is the link from one host to another, or nil if they are not
// connected that way. With Link.Params and Link.SetParams it lets a test
// vary one parameter of a profile and keep the rest, as the chaff
// measurement does to separate the cost of a send rate from netsim's
// per-packet delay spikes (docs/spec/ssp.md §9.1.5).
func (n *Network) Link(from, to *Host) *Link {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.links[[2]*Host{from, to}]
}

// At runs fn at simulated time t, in order with packet deliveries, for
// scripted events such as a roam or the start of an outage. Events at the
// same instant run after that instant's deliveries and read deadlines, in
// the order they were scheduled. fn runs on the scheduler's goroutine with
// no lock held, so it may use the network; it must not block.
func (n *Network) At(t time.Time, fn func()) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return
	}
	n.nextKey++
	n.push(&event{at: t, class: classFunc, a: n.nextKey, fn: fn})
}

// Inject delivers a packet as if it came from inj.From, which may be any
// address: an off-path spoofer. It bypasses every link. Injections due at
// the same instant arrive in the order they were made, after that
// instant's link deliveries. An injection due in the past arrives now.
func (n *Network) Inject(inj Injection) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return
	}
	n.inject(inj)
}

func (n *Network) inject(inj Injection) {
	n.nextKey++
	l := n.injected
	l.stats.Sent++
	l.stats.Bytes += len(inj.Data)
	n.push(&event{
		at: inj.At, class: classDeliver, a: l.id, b: n.nextKey,
		link: l, seq: n.nextKey,
		from: unmap(inj.From), to: unmap(inj.To),
		data: append([]byte(nil), inj.Data...),
	})
}

// Stats is what every link did, by link name. It also has the pseudo-links
// "injected", for what Inject and the Tap injected, and "unrouted", for
// writes to an address no host holds or to a host with no link from the
// writer's.
func (n *Network) Stats() map[string]LinkStats {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make(map[string]LinkStats, len(n.order)+2)
	for _, l := range n.order {
		out[l.name] = l.stats
	}
	out[n.injected.name] = n.injected.stats
	out[n.unrouted.name] = n.unrouted.stats
	return out
}

// Host is a machine on the network.
type Host struct {
	Name string
	net  *Network
}

// firstEphemeralPort is where Listen starts looking when asked for port 0,
// the bottom of the IANA dynamic range (RFC 6335 §6).
const firstEphemeralPort = 49152

// Listen opens a socket at addr, which becomes one of the host's addresses.
// Port 0 picks a free port, as the kernel does. The unspecified address is
// refused: a simulated host has no interfaces for it to stand for, so a
// test gives each socket the address its peer should see.
func (h *Host) Listen(addr netip.AddrPort) (*Conn, error) {
	n := h.net
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil, fmt.Errorf("netsim: listening on %v: network closed", addr)
	}
	addr = unmap(addr)
	if !addr.Addr().IsValid() || addr.Addr().IsUnspecified() {
		return nil, fmt.Errorf("netsim: listening on %v: give the socket a specific address", addr)
	}
	if addr.Port() == 0 {
		free, ok := n.freePort(addr.Addr())
		if !ok {
			return nil, fmt.Errorf("netsim: listening on %v: no free port", addr.Addr())
		}
		addr = free
	}
	if _, ok := n.conns[addr]; ok {
		return nil, fmt.Errorf("netsim: listening on %v: address in use", addr)
	}
	n.nextConn++
	c := &Conn{
		net: n, host: h, id: n.nextConn, addr: addr,
		readBuffer: DefaultReadBuffer,
		changed:    make(chan struct{}),
	}
	n.conns[addr] = c
	return c, nil
}

func (n *Network) freePort(a netip.Addr) (netip.AddrPort, bool) {
	for p := firstEphemeralPort; p <= 65535; p++ {
		ap := netip.AddrPortFrom(a, uint16(p))
		if _, ok := n.conns[ap]; !ok {
			return ap, true
		}
	}
	return netip.AddrPort{}, false
}

// unmap makes an IPv4-mapped IPv6 address plain IPv4, so that a socket at
// 10.0.0.1 is reached whichever way a test spells its address, as a
// dual-stack socket would be.
func unmap(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// TapPacket is a packet as the Tap sees it. The tap may change any field.
type TapPacket struct {
	Link     string
	At       time.Time // when it was written
	From, To netip.AddrPort
	Data     []byte
	// Deliver is the link's verdict. The tap sees a packet the link
	// dropped too, as an adversary at the sender's end of the link would,
	// and may resurrect it; or it may drop one the link would deliver.
	Deliver bool
	// Delivery is when it will arrive, if delivered. For a packet the link
	// dropped it is when the link's fixed delay would have brought it. A
	// time before At is taken as At.
	Delivery time.Time
}

// Injection is a packet the network delivers from any address at any time.
type Injection struct {
	At       time.Time
	From, To netip.AddrPort
	Data     []byte
}

// TraceEvent is the fate of one packet.
type TraceEvent struct {
	At       time.Time // when it was written, or arrived for a loss on arrival
	Link     string
	Seq      uint64 // the packet's sequence on its link, from 1
	Size     int
	Verdict  Verdict
	Delivery time.Time // when it arrives, if Verdict is Delivered
}

// Verdict is what a link decided to do with a packet.
type Verdict uint8

const (
	Delivered Verdict = iota
	DroppedMTU
	DroppedLoss
	DroppedOutage
	DroppedQueue
	DroppedNoRoute
	// DroppedReadBuffer is a packet that arrived at a socket whose
	// receive buffer was full, as a kernel drops it.
	DroppedReadBuffer
)

func (v Verdict) String() string {
	switch v {
	case Delivered:
		return "delivered"
	case DroppedMTU:
		return "dropped-mtu"
	case DroppedLoss:
		return "dropped-loss"
	case DroppedOutage:
		return "dropped-outage"
	case DroppedQueue:
		return "dropped-queue"
	case DroppedNoRoute:
		return "dropped-no-route"
	case DroppedReadBuffer:
		return "dropped-read-buffer"
	}
	return fmt.Sprintf("verdict(%d)", uint8(v))
}

// The scheduler.
//
// One goroutine owns delivery. Everything due at an instant is handled in
// one pass, under the lock, in a fixed order: deliveries before read
// deadlines (so a packet and a deadline at the same instant always go the
// packet's way), then scripted events; within a class by link id and the
// packet's sequence on its link, or by the order things were scheduled.
// The order never depends on which goroutine the Go scheduler ran first.

// injectedLinkID sorts injected packets after every real link's packets at
// the same instant.
const injectedLinkID = ^uint64(0)

const (
	classDeliver = iota
	classDeadline
	classFunc
)

type event struct {
	at    time.Time
	class int
	a, b  uint64 // tie-breakers within a class

	// classDeliver
	link     *Link
	seq      uint64
	from, to netip.AddrPort
	data     []byte

	// classDeadline
	conn *Conn
	gen  uint64

	// classFunc
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
	old[len(old)-1] = nil
	*h = old[:len(old)-1]
	return e
}

// push schedules e and nudges the scheduler, which may be waiting for a
// later event or for none. Called with the lock held.
func (n *Network) push(e *event) {
	heap.Push(&n.events, e)
	select {
	case n.wake <- struct{}{}:
	default:
	}
}

func (n *Network) run() {
	timer := time.NewTimer(0)
	timer.Stop()
	defer timer.Stop()
	for {
		var fns []func()
		n.mu.Lock()
		if n.closed {
			n.mu.Unlock()
			return
		}
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
		var next time.Time
		if len(n.events) > 0 {
			next = n.events[0].at
		}
		n.mu.Unlock()

		for _, fn := range fns {
			fn()
		}
		if len(fns) > 0 {
			continue // they may have scheduled something due now
		}

		// With nothing in flight the scheduler waits on no timer at all,
		// so that a test blocked forever is a deadlock synctest reports,
		// not an endless march through virtual time.
		var tick <-chan time.Time
		if !next.IsZero() {
			timer.Reset(next.Sub(now))
			tick = timer.C
		}
		select {
		case <-tick:
		case <-n.wake:
			timer.Stop()
		case <-n.done:
			return
		}
	}
}

// deliver hands a packet to whichever socket holds its destination now,
// which after a Rebind may be none. Called with the lock held.
func (n *Network) deliver(e *event) {
	l := e.link
	c, ok := n.conns[e.to]
	verdict := Delivered
	switch {
	case !ok || c.closed:
		verdict = DroppedNoRoute
		l.stats.DroppedNoRoute++
	case c.queued+len(e.data) > c.readBuffer:
		verdict = DroppedReadBuffer
		l.stats.DroppedReadBuffer++
	default:
		l.stats.Delivered++
		c.receive(e.from, e.data)
	}
	if verdict != Delivered && n.Trace != nil {
		n.Trace(TraceEvent{At: e.at, Link: l.name, Seq: e.seq, Size: len(e.data), Verdict: verdict})
	}
}
