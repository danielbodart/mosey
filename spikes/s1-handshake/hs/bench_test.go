package hs

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"
)

func BenchmarkHandshakeB1(b *testing.B) {
	for b.Loop() {
		handshakeB(b, B1ServerKEM, DefaultConfig())
	}
}

func BenchmarkHandshakeB2(b *testing.B) {
	for b.Loop() {
		handshakeB(b, B2ClientKEM, DefaultConfig())
	}
}

func BenchmarkHandshakeA(b *testing.B) {
	for b.Loop() {
		handshakeA(b, DefaultConfig())
	}
}

func BenchmarkTransportSealOpen1K(b *testing.B) {
	cli, srv, _, _ := handshakeB(b, B1ServerKEM, DefaultConfig())
	cfg := DefaultConfig()
	cfg.RekeyAfterTime = time.Hour
	cli.cfg, srv.cfg = cfg, cfg
	msg := make([]byte, 1024)
	b.SetBytes(1024)
	for b.Loop() {
		p, _ := cli.Seal(msg)
		if _, err := srv.Open(p, addrA); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRekeyRoundTrip(b *testing.B) {
	cli, srv, _, _ := handshakeB(b, B1ServerKEM, DefaultConfig())
	for b.Loop() {
		cli.StartRekey()
		srv.Open(cli.Outbox()[0], addrA)
		cli.Open(srv.Outbox()[0], addrS)
		p, _ := cli.Seal([]byte("x"))
		srv.Open(p, addrA)
	}
}

// TestCostBreakdown prints the median wall time of each handshake step on
// one core. Run with MOSEY_COST=1 go test -run CostBreakdown -v.
func TestCostBreakdown(t *testing.T) {
	if os.Getenv("MOSEY_COST") == "" {
		t.Skip("set MOSEY_COST=1")
	}
	const n = 400
	med := func(f func() time.Duration) time.Duration {
		d := make([]time.Duration, n)
		for i := range d {
			d[i] = f()
		}
		slices.Sort(d)
		return d[n/2]
	}
	timeit := func(f func()) time.Duration { s := time.Now(); f(); return time.Since(s) }
	row := func(name string, d time.Duration) { fmt.Printf("%-48s %8.1f us\n", name, float64(d.Nanoseconds())/1000) }
	cfg := DefaultConfig()

	for _, mode := range []BMode{B1ServerKEM, B2ClientKEM} {
		p := fmt.Sprintf("B%d ", mode)
		row(p+"server: mint credentials (NewBServer)", med(func() time.Duration {
			return timeit(func() { NewBServer(mode, serverHello, cfg) })
		}))
		row(p+"client: build msg1", med(func() time.Duration {
			_, cred, _ := NewBServer(mode, serverHello, cfg)
			return timeit(func() { NewBClient(cred, clientHello, cfg) })
		}))
		row(p+"server: process msg1, build msg2", med(func() time.Duration {
			s, cred, _ := NewBServer(mode, serverHello, cfg)
			_, m1, _ := NewBClient(cred, clientHello, cfg)
			return timeit(func() { s.HandleInit(m1) })
		}))
		row(p+"client: process msg2", med(func() time.Duration {
			s, cred, _ := NewBServer(mode, serverHello, cfg)
			c, m1, _ := NewBClient(cred, clientHello, cfg)
			m2, _, _, _ := s.HandleInit(m1)
			return timeit(func() { c.HandleResp(m2) })
		}))
		row(p+"server: REJECT garbage msg1 (wrong PSK)", med(func() time.Duration {
			s, cred, _ := NewBServer(mode, serverHello, cfg)
			bad := cred
			bad.PSK[0] ^= 1
			_, m1, _ := NewBClient(bad, clientHello, cfg)
			return timeit(func() { s.HandleInit(m1) })
		}))
	}
	_, ssk, _ := ed25519.GenerateKey(rand.Reader)
	_, csk, _ := ed25519.GenerateKey(rand.Reader)
	var sid [16]byte
	sid0 := AIdentity{SessionID: sid, Self: ssk, Peer: csk.Public().(ed25519.PublicKey)}
	cid0 := AIdentity{SessionID: sid, Self: csk, Peer: ssk.Public().(ed25519.PublicKey)}
	row("A  client: build msg1", med(func() time.Duration {
		return timeit(func() { NewAClient(cid0, clientHello, cfg) })
	}))
	row("A  server: process msg1, build msg2 (also for spoofed msg1)", med(func() time.Duration {
		s := NewAServer(sid0, serverHello, cfg)
		_, m1, _ := NewAClient(cid0, clientHello, cfg)
		return timeit(func() { s.HandleInit(m1) })
	}))
	row("A  client: process msg2, build msg3", med(func() time.Duration {
		s := NewAServer(sid0, serverHello, cfg)
		c, m1, _ := NewAClient(cid0, clientHello, cfg)
		m2, _ := s.HandleInit(m1)
		return timeit(func() { c.HandleResp(m2) })
	}))
	row("A  server: process msg3", med(func() time.Duration {
		s := NewAServer(sid0, serverHello, cfg)
		c, m1, _ := NewAClient(cid0, clientHello, cfg)
		m2, _ := s.HandleInit(m1)
		m3, _, _, _ := c.HandleResp(m2)
		return timeit(func() { s.HandleFin(m3) })
	}))
}
