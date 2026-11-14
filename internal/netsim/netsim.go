package netsim

import (
	"net"
	"net/netip"
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
	Tap func(p *TapPacket) []Injection

	// Trace, if set, is told the fate of every packet, for tests that
	// assert on what the network did rather than on what arrived.
	Trace func(ev TraceEvent)
}

// New is an empty network whose every random choice derives from seed.
func New(seed uint64) *Network {
	panic("TODO slice 1")
}

// Close stops the scheduler. Reads blocked on any of the network's sockets
// return net.ErrClosed.
func (n *Network) Close() {
	panic("TODO slice 1")
}

// NewHost adds a host. A host owns addresses; sockets on it Listen on one.
func (n *Network) NewHost(name string) *Host {
	panic("TODO slice 1")
}

// Connect adds a one-way link from one host to another: packets from any of
// from's sockets to any of to's addresses take it. A path needs a link each
// way, which is what lets a test make the two directions differ, as
// cellular uplinks and downlinks do.
func (n *Network) Connect(from, to *Host, p LinkParams) *Link {
	panic("TODO slice 1")
}

// At runs fn at simulated time t, in order with packet deliveries, for
// scripted events such as a roam or the start of an outage.
func (n *Network) At(t time.Time, fn func()) {
	panic("TODO slice 1")
}

// Inject delivers a packet as if it came from inj.From, which may be any
// address: an off-path spoofer.
func (n *Network) Inject(inj Injection) {
	panic("TODO slice 1")
}

// Stats is what every link did, by link name.
func (n *Network) Stats() map[string]LinkStats {
	panic("TODO slice 1")
}

// Host is a machine on the network.
type Host struct {
	Name string
}

// Listen opens a socket at addr, which becomes one of the host's addresses.
func (h *Host) Listen(addr netip.AddrPort) (*Conn, error) {
	panic("TODO slice 1")
}

// Conn is a UDP-like socket on the simulated network.
//
// Oversized writes are not refused: as on a path that black-holes them,
// the link's MTU drops them silently.
type Conn struct{}

var _ net.PacketConn = (*Conn)(nil)

func (c *Conn) ReadFrom(p []byte) (int, net.Addr, error) { panic("TODO slice 1") }

func (c *Conn) WriteTo(p []byte, addr net.Addr) (int, error) { panic("TODO slice 1") }

// ReadFromAddrPort is ReadFrom without the allocation of a net.Addr.
func (c *Conn) ReadFromAddrPort(p []byte) (int, netip.AddrPort, error) { panic("TODO slice 1") }

// WriteToAddrPort is WriteTo without the allocation of a net.Addr.
func (c *Conn) WriteToAddrPort(p []byte, addr netip.AddrPort) (int, error) {
	panic("TODO slice 1")
}

func (c *Conn) Close() error                       { panic("TODO slice 1") }
func (c *Conn) LocalAddr() net.Addr                { panic("TODO slice 1") }
func (c *Conn) SetDeadline(t time.Time) error      { panic("TODO slice 1") }
func (c *Conn) SetReadDeadline(t time.Time) error  { panic("TODO slice 1") }
func (c *Conn) SetWriteDeadline(t time.Time) error { panic("TODO slice 1") }

// Rebind moves the socket to a new address, as a NAT rebinding or a roam
// from wifi to cellular does. Packets in flight to the old address are
// lost, and the application is not told: it finds out, as a real one does,
// from what arrives.
func (c *Conn) Rebind(addr netip.AddrPort) error {
	panic("TODO slice 1")
}

// RxStats is how much the socket has received, so a test can measure what
// an attacker drew towards a victim.
func (c *Conn) RxStats() (packets, bytes int) {
	panic("TODO slice 1")
}

// TapPacket is a packet as the Tap sees it. The tap may change any field.
type TapPacket struct {
	Link     string
	At       time.Time // when it was written
	From, To netip.AddrPort
	Data     []byte
	Deliver  bool      // the link's verdict; the tap may overturn it
	Delivery time.Time // when it will arrive, if delivered
}

// Injection is a packet the network delivers from any address at any time.
type Injection struct {
	At       time.Time
	From, To netip.AddrPort
	Data     []byte
}

// TraceEvent is the fate of one packet.
type TraceEvent struct {
	At       time.Time
	Link     string
	Seq      uint64
	Size     int
	Verdict  Verdict
	Delivery time.Time
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
)
