package client

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
)

// bootstrap.md §7.2 leaves a hostile server's directed broadcast to the
// kernel rather than listing the client's interfaces on every attach: a
// socket without SO_BROADCAST may not send to its own subnet's broadcast
// address. This pins that, from the very socket the client uses, so a
// platform where it does not hold fails here rather than spraying a LAN.
func TestTheKernelRefusesALocalDirectedBroadcast(t *testing.T) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("listing interfaces: %v", err)
	}
	var bcast netip.Addr
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(n.IP.To4())
		ones, _ := n.Mask.Size()
		if !ok || ip.IsLoopback() || n.IP.To4() == nil || ones == 0 || ones > 30 {
			continue
		}
		b := netip.PrefixFrom(ip, ones).Masked().Addr().As4()
		for i := range 4 {
			b[i] |= ^n.Mask[len(n.Mask)-4+i]
		}
		bcast = netip.AddrFrom4(b)
		break
	}
	if !bcast.IsValid() {
		t.Skip("no IPv4 interface with a subnet broadcast")
	}
	pc, err := listenFor(bcast)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	// Port 9 is discard, should the kernel ever let it through.
	_, err = pc.WriteToUDPAddrPort([]byte("x"), netip.AddrPortFrom(bcast, 9))
	if !errors.Is(err, syscall.EACCES) {
		t.Fatalf("sending to %s: %v, want EACCES", bcast, err)
	}
}
