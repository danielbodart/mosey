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

func BenchmarkHandshakeB3(b *testing.B) {
	for b.Loop() {
		handshakeB(b, B3BothKEM, DefaultConfig())
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
	row := func(name string, d time.Duration) {
		fmt.Printf("%-48s %8.1f us\n", name, float64(d.Nanoseconds())/1000)
	}
	cfg := DefaultConfig()

	pk3, _ := NewClientKEM()
	row("B3 client: make one-shot KEM key (during SSH bootstrap)", med(func() time.Duration {
		return timeit(func() { NewClientKEM() })
	}))
	for _, mode := range allB {
		p := fmt.Sprintf("B%d ", mode)
		var pks [][]byte
		if mode == B3BothKEM {
			pks = [][]byte{pk3.PublicKey}
		}
		row(p+"server: mint credentials (NewBServer)", med(func() time.Duration {
			return timeit(func() { NewBServer(mode, serverHello, cfg, pks...) })
		}))
		row(p+"client: build msg1", med(func() time.Duration {
			_, cred, mk := mintB(t, mode, cfg)
			return timeit(func() { mk(cred) })
		}))
		row(p+"server: process msg1, build msg2", med(func() time.Duration {
			s, cred, mk := mintB(t, mode, cfg)
			_, m1, _ := mk(cred)
			return timeit(func() { s.HandleInit(m1) })
		}))
		row(p+"client: process msg2", med(func() time.Duration {
			s, cred, mk := mintB(t, mode, cfg)
			c, m1, _ := mk(cred)
			m2, _, _, _ := s.HandleInit(m1)
			return timeit(func() { c.HandleResp(m2) })
		}))
		row(p+"server: REJECT garbage msg1 (wrong PSK, mac1 fails)", med(func() time.Duration {
			s, cred, mk := mintB(t, mode, cfg)
			bad := cred
			bad.PSK[0] ^= 1
			_, m1, _ := mk(bad)
			return timeit(func() { s.HandleInit(m1) })
		}))
		row(p+"server: REJECT garbage msg1 WITHOUT mac1 (valid mac1, bad KEM/AEAD)", med(func() time.Duration {
			s, cred, mk := mintB(t, mode, cfg)
			_, m1, _ := mk(cred)
			m := append([]byte(nil), m1[:len(m1)-mac1Size]...)
			m[len(m)-1] ^= 1 // break the AEAD tag; KEM work still happens
			m = append(m, mac1(mac1Key(&cred), m)...)
			return timeit(func() { s.HandleInit(m) })
		}))
	}
	d := NewDispatcher(cfg)
	d.MaxOutstanding = 1 << 20
	ids := make([][]byte, 0, 1000)
	for i := 0; i < 1000; i++ {
		c, _ := d.Mint(fmt.Sprint("t", i), B1ServerKEM, serverHello, nil, false)
		ids = append(ids, c.CredID[:])
	}
	_, credX, mkX := mintB(t, B1ServerKEM, cfg)
	_, m1X, _ := mkX(credX) // unknown credential id
	row("dispatcher (1000 outstanding creds): reject unknown cred id", med(func() time.Duration {
		return timeit(func() { d.Handle(m1X, addrB) })
	}))
	m1Y := append([]byte(nil), m1X...)
	copy(m1Y[2:], ids[500]) // known id, wrong mac1
	row("dispatcher (1000 outstanding creds): known id, bad mac1", med(func() time.Duration {
		return timeit(func() { d.Handle(m1Y, addrB) })
	}))
	_, ssk, _ := ed25519.GenerateKey(rand.Reader)
	_, csk, _ := ed25519.GenerateKey(rand.Reader)
	var sid [16]byte
	sid0 := AIdentity{SessionID: sid, Self: ssk, Peer: csk.Public().(ed25519.PublicKey)}
	cid0 := AIdentity{SessionID: sid, Self: csk, Peer: ssk.Public().(ed25519.PublicKey)}
	row("A  client: build msg1", med(func() time.Duration {
		return timeit(func() { NewAClient(cid0, clientHello, cfg) })
	}))
	row("A  server: mac1 check if A had one (HMAC-SHA256 over msg1)", med(func() time.Duration {
		_, m1, _ := NewAClient(cid0, clientHello, cfg)
		k := make([]byte, 32)
		return timeit(func() { mac1(k, m1) })
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
