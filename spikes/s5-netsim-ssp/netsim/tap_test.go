package netsim

import (
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// TestTap exercises every adversary operation: drop, duplicate, modify,
// re-source (with a delivery time that races the original), delay, and
// off-path injection. All of it is in virtual time and deterministic.
func TestTap(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n, a, b := pair(t, 1, LinkParams{Delay: 40 * time.Millisecond}, LinkParams{Delay: 40 * time.Millisecond})
		start := time.Now()
		evil := netip.MustParseAddrPort("192.0.2.66:6666")
		n.Tap = func(p *TapPacket) []Injection {
			switch string(p.Data) {
			case "drop":
				p.Deliver = false
			case "dup":
				return []Injection{{At: p.Delivery.Add(5 * time.Millisecond), Src: p.Src, Dst: p.Dst, Data: p.Data}}
			case "flip":
				p.Data = []byte("flap")
			case "race":
				// Re-send a copy from another address that arrives first;
				// hold the original back.
				inj := Injection{At: p.At.Add(10 * time.Millisecond), Src: evil, Dst: p.Dst, Data: p.Data}
				p.Delivery = p.Delivery.Add(100 * time.Millisecond)
				return []Injection{inj}
			}
			return nil
		}
		var got []rx
		var wg sync.WaitGroup
		wg.Add(1)
		go collect(b, start, &got, &wg)
		for _, m := range []string{"drop", "dup", "flip", "race"} {
			a.WriteToAddrPort([]byte(m), addrB)
			time.Sleep(time.Second)
		}
		n.Inject(Injection{At: time.Now().Add(time.Millisecond), Src: evil, Dst: addrB, Data: []byte("forged")})
		time.Sleep(time.Second)
		a.Close()
		b.Close()
		wg.Wait()
		n.Close()
		want := []rx{
			{1040 * time.Millisecond, "dup", addrA},
			{1045 * time.Millisecond, "dup", addrA},
			{2040 * time.Millisecond, "flap", addrA},
			{3010 * time.Millisecond, "race", evil},
			{3140 * time.Millisecond, "race", addrA},
			{4001 * time.Millisecond, "forged", evil},
		}
		if len(got) != len(want) {
			t.Fatalf("got %v", got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("packet %d: got %+v want %+v", i, got[i], want[i])
			}
		}
		if p, _ := b.RxStats(); p != len(want) {
			t.Fatalf("RxStats %d", p)
		}
	})
}
