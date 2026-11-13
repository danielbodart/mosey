package sim

import (
	"math/rand/v2"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"mosey.spike/s5-netsim-ssp/netsim"
)

// Adversary tests (review finding: the D18 harness must be able to model an
// on-path attacker). All deterministic, virtual time.

var victim = netip.MustParseAddrPort("192.0.2.99:5353")

func runWith(t *testing.T, v Variant, setup func(n *netsim.Network, start time.Time)) *Result {
	t.Helper()
	var res *Result
	synctest.Test(t, func(t *testing.T) {
		p := Wired(2 * time.Minute)
		p.Setup = setup
		w := GenTyping(1, p.Duration)
		r, err := Run(p, v, w, 1)
		if err != nil {
			t.Fatal(err)
		}
		res = r
	})
	return res
}

// TestReplayedDatagramsRejected: the attacker re-delivers every datagram in
// both directions 300 ms later. The replay window drops every copy and the
// session is unaffected.
func TestReplayedDatagramsRejected(t *testing.T) {
	v, _ := VariantByName("o7-resend")
	copies := 0
	r := runWith(t, v, func(n *netsim.Network, start time.Time) {
		n.Tap = func(p *netsim.TapPacket) []netsim.Injection {
			if !p.Deliver {
				return nil
			}
			copies++
			return []netsim.Injection{{At: p.Delivery.Add(300 * time.Millisecond), Src: p.Src, Dst: p.Dst, Data: p.Data}}
		}
	})
	if got := r.Client.Replays + r.Server.Replays; got != copies || copies == 0 {
		t.Fatalf("%d replays rejected of %d injected", got, copies)
	}
	if r.Unechoed != 0 || pct(r.Latency, .5) > 70*time.Millisecond {
		t.Fatalf("session disturbed: unechoed %d p50 %v", r.Unechoed, pct(r.Latency, .5))
	}
}

// TestBitFlipsRejected: 5% of datagrams get one random bit flipped. Each
// fails authentication; the session carries on (they count as losses).
func TestBitFlipsRejected(t *testing.T) {
	v, _ := VariantByName("o7-resend")
	rng := rand.New(rand.NewPCG(7, 7))
	flipped := 0
	r := runWith(t, v, func(n *netsim.Network, start time.Time) {
		n.Tap = func(p *netsim.TapPacket) []netsim.Injection {
			if p.Deliver && rng.Float64() < 0.05 {
				d := append([]byte(nil), p.Data...)
				i := rng.IntN(len(d))
				d[i] ^= 1 << rng.IntN(8)
				p.Data = d
				flipped++
			}
			return nil
		}
	})
	if got := r.Client.AuthFailures + r.Server.AuthFailures + r.Client.Replays + r.Server.Replays; got != flipped || flipped == 0 {
		t.Fatalf("%d rejected of %d flipped", got, flipped)
	}
	if r.Unechoed != 0 {
		t.Fatalf("%d keys lost", r.Unechoed)
	}
}

// redirectAttack: from 30 s on, every client datagram is copied, the copy
// re-sourced from the victim's address and delivered first; the genuine one
// is held back 50 ms (so it then arrives as a replay). Returns the result
// and the bytes the victim received.
func redirectAttack(t *testing.T, naive bool) (*Result, int, int) {
	v, _ := VariantByName("o7-resend")
	v.NaiveRoaming = naive
	var vconn *netsim.Conn
	injected := 0
	r := runWith(t, v, func(n *netsim.Network, start time.Time) {
		hv := n.NewHost("victim")
		n.Connect(n.HostNamed("server"), hv, netsim.LinkParams{Delay: 20 * time.Millisecond})
		var err error
		if vconn, err = hv.Listen(victim); err != nil {
			t.Fatal(err)
		}
		n.Tap = func(p *netsim.TapPacket) []netsim.Injection {
			if p.Link != "client->server" || !p.Deliver || p.At.Sub(start) < 30*time.Second {
				return nil
			}
			injected += len(p.Data)
			inj := netsim.Injection{At: p.Delivery, Src: victim, Dst: p.Dst, Data: p.Data}
			p.Delivery = p.Delivery.Add(50 * time.Millisecond)
			return []netsim.Injection{inj}
		}
	})
	_, vb := vconn.RxStats()
	return r, vb, injected
}

// TestRoamingRedirect shows the attack works against the paper's roaming
// rule and fails against path validation with anti-amplification.
func TestRoamingRedirect(t *testing.T) {
	r, vb, inj := redirectAttack(t, true)
	t.Logf("naive: victim received %d B (attacker sent %d B); unechoed %d; p50 %v; server switches %d",
		vb, inj, r.Unechoed, pct(r.Latency, .5), r.Path.Switches)
	if vb < 100_000 || r.Unechoed < 100 {
		t.Fatalf("expected the naive rule to be hijacked")
	}
	r, vb, inj = redirectAttack(t, false)
	t.Logf("validated: victim received %d B (attacker sent %d B); unechoed %d; p50 %v; server switches %d, amp-limited %d",
		vb, inj, r.Unechoed, pct(r.Latency, .5), r.Path.Switches, r.Path.AmpLimited)
	if vb > 3*inj {
		t.Fatalf("victim got %d B > 3 x %d B", vb, inj)
	}
	if r.Unechoed != 0 || r.Path.Switches != 1 {
		t.Fatalf("session disturbed: unechoed %d switches %d", r.Unechoed, r.Path.Switches)
	}
}

// TestGenuineRoamValidates: a real address change still switches (one
// validation round trip), and only once per roam.
func TestGenuineRoamValidates(t *testing.T) {
	v, _ := VariantByName("o7-resend")
	synctest.Test(t, func(t *testing.T) {
		p := Wired(3 * time.Minute)
		p.Roams = []time.Duration{40 * time.Second, 80 * time.Second, 120 * time.Second}
		r, err := Run(p, v, GenTyping(2, p.Duration), 2)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("repair %v, switches %d, roam-key latency p50 %v max %v", r.RoamRepair, r.Path.Switches, pct(r.RoamKeyLatency, .5), pct(r.RoamKeyLatency, 1))
		if len(r.RoamRepair) != 3 || r.Path.Switches != 4 {
			t.Fatalf("repairs %v switches %d", r.RoamRepair, r.Path.Switches)
		}
		for _, d := range r.RoamRepair {
			if d > 4*time.Second { // at most one heartbeat (3 s) + 1 RTT + validation RTT
				t.Fatalf("repair took %v", d)
			}
		}
	})
}
