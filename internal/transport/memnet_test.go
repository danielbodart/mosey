package transport

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/danielbodart/mosey/internal/handshake"
)

// memNet is the smallest network the transport's tests need: sockets that
// deliver after a fixed delay, an adversary that sees and rewrites every
// packet, and roaming. It runs on the time package, so inside a synctest
// bubble it is virtual and deterministic. (internal/netsim is the full
// simulator, with loss models and traces, for SSP and the end-to-end
// tests; these tests want only an adversary they script themselves.)
type memNet struct {
	mu    sync.Mutex
	socks map[netip.AddrPort]*memSock
	delay time.Duration
	// tap, if set, sees every packet as it is sent and returns what to
	// deliver instead: nothing (a drop), it as it is, copies, or packets
	// with other sources, destinations or delays. It runs under the
	// network's lock.
	tap func(p memPacket) []memPacket
	// rx is the bytes delivered to each address, bound or not, so a test
	// can measure what an attacker drew towards a victim.
	rx map[netip.AddrPort]int
}

type memPacket struct {
	from, to netip.AddrPort
	data     []byte
	delay    time.Duration
}

func newMemNet(delay time.Duration) *memNet {
	return &memNet{socks: map[netip.AddrPort]*memSock{}, rx: map[netip.AddrPort]int{}, delay: delay}
}

func (n *memNet) listen(addr string) *memSock {
	n.mu.Lock()
	defer n.mu.Unlock()
	s := &memSock{n: n, addr: netip.MustParseAddrPort(addr), in: make(chan memPacket, 4096), closed: make(chan struct{})}
	n.socks[s.addr] = s
	return s
}

// send delivers p, through the tap, after its delay.
func (n *memNet) send(p memPacket) {
	n.mu.Lock()
	out := []memPacket{p}
	if n.tap != nil {
		out = n.tap(p)
	}
	n.mu.Unlock()
	for _, q := range out {
		time.AfterFunc(q.delay, func() { n.deliver(q) })
	}
}

func (n *memNet) deliver(p memPacket) {
	n.mu.Lock()
	n.rx[p.to] += len(p.data)
	s := n.socks[p.to]
	n.mu.Unlock()
	if s == nil {
		return
	}
	select {
	case s.in <- p:
	case <-s.closed:
	default: // a full socket buffer drops, as a kernel's does
	}
}

func (n *memNet) received(a netip.AddrPort) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.rx[a]
}

func (n *memNet) setTap(tap func(p memPacket) []memPacket) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.tap = tap
}

// locked runs f under the network's lock, which is the lock a tap runs
// under: a test reads or changes what its tap captured through this, so
// the two never race whichever goroutine sent the packet.
func (n *memNet) locked(f func()) {
	n.mu.Lock()
	defer n.mu.Unlock()
	f()
}

// read is locked for a test reading one value its tap keeps.
func read[T any](n *memNet, v *T) T {
	var out T
	n.locked(func() { out = *v })
	return out
}

// memSock is a net.PacketConn on a memNet.
type memSock struct {
	n      *memNet
	addr   netip.AddrPort
	in     chan memPacket
	closed chan struct{}
	once   sync.Once
}

var _ net.PacketConn = (*memSock)(nil)

func (s *memSock) ReadFromAddrPort(b []byte) (int, netip.AddrPort, error) {
	select {
	case p := <-s.in:
		return copy(b, p.data), p.from, nil
	case <-s.closed:
		return 0, netip.AddrPort{}, net.ErrClosed
	}
}

func (s *memSock) WriteToAddrPort(b []byte, to netip.AddrPort) (int, error) {
	select {
	case <-s.closed:
		return 0, net.ErrClosed
	default:
	}
	s.n.mu.Lock()
	from := s.addr
	delay := s.n.delay
	s.n.mu.Unlock()
	s.n.send(memPacket{from: from, to: to, data: bytes.Clone(b), delay: delay})
	return len(b), nil
}

func (s *memSock) ReadFrom(b []byte) (int, net.Addr, error) {
	n, from, err := s.ReadFromAddrPort(b)
	return n, net.UDPAddrFromAddrPort(from), err
}

func (s *memSock) WriteTo(b []byte, to net.Addr) (int, error) {
	return s.WriteToAddrPort(b, to.(*net.UDPAddr).AddrPort())
}

func (s *memSock) Close() error {
	s.once.Do(func() {
		close(s.closed)
		s.n.mu.Lock()
		if s.n.socks[s.addr] == s {
			delete(s.n.socks, s.addr)
		}
		s.n.mu.Unlock()
	})
	return nil
}

func (s *memSock) LocalAddr() net.Addr              { return net.UDPAddrFromAddrPort(s.local()) }
func (s *memSock) SetDeadline(time.Time) error      { return nil }
func (s *memSock) SetReadDeadline(time.Time) error  { return nil }
func (s *memSock) SetWriteDeadline(time.Time) error { return nil }

func (s *memSock) local() netip.AddrPort {
	s.n.mu.Lock()
	defer s.n.mu.Unlock()
	return s.addr
}

// rebind moves the socket to a new address: a roam, or a NAT rebinding.
func (s *memSock) rebind(addr string) {
	s.n.mu.Lock()
	defer s.n.mu.Unlock()
	delete(s.n.socks, s.addr)
	s.addr = netip.MustParseAddrPort(addr)
	s.n.socks[s.addr] = s
}

// --- A server and a client on a memNet ---

var (
	serverAddr = netip.MustParseAddrPort("192.0.2.1:60001")
	clientAddr = netip.MustParseAddrPort("198.51.100.7:40000")
	victimAddr = netip.MustParseAddrPort("203.0.113.66:9")
)

type setup struct {
	t       testing.TB
	net     *memNet
	creds   *handshake.Credentials
	l       *Listener
	ssock   *memSock
	session [16]byte
}

func newSetup(t testing.TB, delay time.Duration) *setup {
	n := newMemNet(delay)
	s := &setup{t: t, net: n, creds: handshake.NewCredentials(nil)}
	s.ssock = n.listen(serverAddr.String())
	s.l = Listen(s.ssock, s.creds, nil)
	s.session = must(handshake.NewSessionID())
	t.Cleanup(func() { s.l.Close() })
	return s
}

// mint is the bootstrap: a client key, and a credential for it.
func (s *setup) mint() (handshake.Credential, *handshake.OneShotKey) {
	key := must(handshake.NewOneShotKey())
	cred, err := s.creds.Mint(s.session, key.PublicKey())
	if err != nil {
		s.t.Fatal(err)
	}
	return cred, key
}

// connect dials from addr and accepts on the server, returning both ends.
func (s *setup) connect(addr string) (client, server *Conn, csock *memSock) {
	s.t.Helper()
	return s.connectOffering(addr, nil)
}

// connectOffering is connect with the client offering offer besides the
// terminal (DialOffering).
func (s *setup) connectOffering(addr string, offer []handshake.ChannelType) (client, server *Conn, csock *memSock) {
	s.t.Helper()
	cred, key := s.mint()
	csock = s.net.listen(addr)
	accepted := make(chan *Conn, 1)
	go func() {
		c, err := s.l.Accept(context.Background())
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- c
	}()
	client, err := DialOffering(context.Background(), csock, serverAddr, cred, key, offer, nil)
	if err != nil {
		s.t.Fatal(err)
	}
	server = <-accepted
	if server == nil {
		s.t.Fatal("no connection accepted")
	}
	s.t.Cleanup(func() { client.Close() })
	return client, server, csock
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// recv waits for a payload, failing after a long virtual while.
func recv(t *testing.T, c *Conn) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	p, err := c.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	return p
}

// exchange sends a payload each way and checks it arrives.
func exchange(t *testing.T, client, server *Conn, what string) {
	t.Helper()
	if err := client.Send([]byte("c:" + what)); err != nil {
		t.Fatalf("client Send: %v", err)
	}
	if got := string(recv(t, server)); got != "c:"+what {
		t.Fatalf("server got %q", got)
	}
	if err := server.Send([]byte("s:" + what)); err != nil {
		t.Fatalf("server Send: %v", err)
	}
	if got := string(recv(t, client)); got != "s:"+what {
		t.Fatalf("client got %q", got)
	}
}

// events drains what a connection has reported so far.
func events(c *Conn) []Event {
	var out []Event
	for {
		select {
		case ev := <-c.Events():
			out = append(out, ev)
		default:
			return out
		}
	}
}
