package netsim

import (
	"net/netip"
	"testing"
	"testing/synctest"
	"time"
)

// The adversary of S5 §6, operation by operation: every one in virtual time
// and deterministic.
func TestTheTapCanDropDuplicateRewriteResourceAndDelay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n, a, b := pair(t, 1, LinkParams{Delay: 40 * time.Millisecond}, LinkParams{Delay: 40 * time.Millisecond})
		evil := netip.MustParseAddrPort("192.0.2.66:6666")
		var seen []string
		n.Tap = func(p *TapPacket) []Injection {
			seen = append(seen, p.Link+" "+string(p.Data))
			switch string(p.Data) {
			case "drop":
				p.Deliver = false
			case "dup":
				return []Injection{{At: p.Delivery.Add(5 * time.Millisecond), From: p.From, To: p.To, Data: p.Data}}
			case "flip":
				p.Data = []byte("flap")
			case "race":
				// A copy from another address that arrives first, and the
				// original held back: the roaming redirect of S5 §6.
				p.Delivery = p.Delivery.Add(100 * time.Millisecond)
				return []Injection{{At: p.At.Add(10 * time.Millisecond), From: evil, To: p.To, Data: p.Data}}
			}
			return nil
		}
		received := collect(b)
		for _, m := range []string{"drop", "dup", "flip", "race"} {
			a.WriteToAddrPort([]byte(m), addrB)
			time.Sleep(time.Second)
		}
		n.Inject(Injection{At: time.Now().Add(time.Millisecond), From: evil, To: addrB, Data: []byte("forged")})
		time.Sleep(time.Second)
		st := n.Stats()
		n.Close()

		want := []arrival{
			{1040 * time.Millisecond, "dup", addrA},
			{1045 * time.Millisecond, "dup", addrA},
			{2040 * time.Millisecond, "flap", addrA},
			{3010 * time.Millisecond, "race", evil},
			{3140 * time.Millisecond, "race", addrA},
			{4001 * time.Millisecond, "forged", evil},
		}
		got := received()
		if len(got) != len(want) {
			t.Fatalf("got %v", got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("packet %d: got %v, want %v", i, got[i], want[i])
			}
		}
		if p, _ := b.RxStats(); p != len(want) {
			t.Errorf("RxStats counted %d packets", p)
		}
		if len(seen) != 4 {
			t.Errorf("the tap saw %v", seen)
		}
		if st["a->b"].Tampered != 1 || st["injected"].Sent != 3 || st["injected"].Delivered != 3 {
			t.Errorf("stats %+v", st)
		}
	})
}

func TestTheTapSeesWhatTheLinkDroppedAndMayResurrectIt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n, a, b := pair(t, 1, LinkParams{Delay: 20 * time.Millisecond, Loss: 1}, LinkParams{})
		n.Tap = func(p *TapPacket) []Injection {
			if p.Deliver {
				t.Error("a link with total loss delivered")
			}
			if p.Delivery != p.At.Add(20*time.Millisecond) {
				t.Errorf("a dropped packet's delivery is %v after it was sent", p.Delivery.Sub(p.At))
			}
			p.Deliver = string(p.Data) == "resurrect"
			return nil
		}
		received := collect(b)
		a.WriteToAddrPort([]byte("lost"), addrB)
		a.WriteToAddrPort([]byte("resurrect"), addrB)
		time.Sleep(time.Second)
		st := n.Stats()["a->b"]
		n.Close()
		if got := received(); len(got) != 1 || got[0].data != "resurrect" || got[0].at != 20*time.Millisecond {
			t.Errorf("got %v", got)
		}
		if st.DroppedLoss != 2 || st.Tampered != 1 || st.Delivered != 1 {
			t.Errorf("stats %+v", st)
		}
	})
}

func TestTheTapMayRedirectAPacketToAVictim(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n, a, b := pair(t, 1, LinkParams{Delay: 10 * time.Millisecond}, LinkParams{Delay: 10 * time.Millisecond})
		victimAddr := netip.MustParseAddrPort("10.0.0.99:99")
		victim, err := n.NewHost("victim").Listen(victimAddr)
		if err != nil {
			t.Fatal(err)
		}
		n.Tap = func(p *TapPacket) []Injection {
			p.To = victimAddr
			return nil
		}
		b.WriteToAddrPort(make([]byte, 500), addrA)
		time.Sleep(time.Second)
		if p, bytes := victim.RxStats(); p != 1 || bytes != 500 {
			t.Errorf("the victim got %d packets, %d bytes", p, bytes)
		}
		if p, _ := a.RxStats(); p != 0 {
			t.Error("the packet reached its first destination too")
		}
	})
}

func TestAnInjectionDueInThePastArrivesNow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n, _, b := pair(t, 1, LinkParams{}, LinkParams{})
		time.Sleep(time.Second)
		start := time.Now()
		n.Inject(Injection{At: start.Add(-time.Hour), From: addrA, To: addrB, Data: []byte("late")})
		buf := make([]byte, 10)
		if k, _, err := b.ReadFrom(buf); err != nil || string(buf[:k]) != "late" {
			t.Fatalf("got %q, %v", buf[:k], err)
		}
		if time.Since(start) != 0 {
			t.Error("it waited")
		}
	})
}
