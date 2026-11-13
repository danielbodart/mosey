package hs

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"
)

var (
	clientHello = Hello{Proto: 1, Channels: []string{"terminal", "agent@mosey", "udp-fwd@mosey"}}
	serverHello = Hello{Proto: 1, Channels: []string{"terminal", "agent@mosey"}}
	addrA       = netip.MustParseAddrPort("192.0.2.1:4000")
	addrB       = netip.MustParseAddrPort("198.51.100.7:5000")
	addrS       = netip.MustParseAddrPort("203.0.113.9:60001")
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time      { return c.t }
func (c *fakeClock) add(d time.Duration) { c.t = c.t.Add(d) }
func cfgWith(c *fakeClock) Config        { cfg := DefaultConfig(); cfg.Now = c.now; return cfg }
func mustT(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func handshakeB(t testing.TB, mode BMode, cfg Config) (cli, srv *Session, m1, m2 []byte) {
	t.Helper()
	server, cred, err := NewBServer(mode, serverHello, cfg)
	mustT(t, err)
	// the SSH hop: credentials are serialised and parsed again
	cred2, err := ParseBCredentials(cred.Marshal())
	mustT(t, err)
	client, m1, err := NewBClient(cred2, clientHello, cfg)
	mustT(t, err)
	m2, srv, peer, err := server.HandleInit(m1)
	mustT(t, err)
	if len(peer.Channels) != 3 {
		t.Fatalf("server saw %v", peer)
	}
	cli, got, err := client.HandleResp(m2)
	mustT(t, err)
	if want := []string{"terminal", "agent@mosey"}; len(got.Channels) != 2 || got.Channels[0] != want[0] || got.Channels[1] != want[1] {
		t.Fatalf("negotiated %v", got.Channels)
	}
	cli.Peer, srv.Peer = addrS, addrA
	return
}

func handshakeA(t testing.TB, cfg Config) (cli, srv *Session, m1, m2, m3 []byte) {
	t.Helper()
	_, ssk, _ := ed25519.GenerateKey(rand.Reader)
	_, csk, _ := ed25519.GenerateKey(rand.Reader)
	var sid [16]byte
	rand.Read(sid[:])
	server := NewAServer(AIdentity{SessionID: sid, Self: ssk, Peer: csk.Public().(ed25519.PublicKey)}, serverHello, cfg)
	client, m1, err := NewAClient(AIdentity{SessionID: sid, Self: csk, Peer: ssk.Public().(ed25519.PublicKey)}, clientHello, cfg)
	mustT(t, err)
	m2, err = server.HandleInit(m1)
	mustT(t, err)
	m3, cli, _, err = client.HandleResp(m2)
	mustT(t, err)
	srv, peer, err := server.HandleFin(m3)
	mustT(t, err)
	if len(peer.Channels) != 2 {
		t.Fatalf("server got selection %v", peer.Channels)
	}
	cli.Peer, srv.Peer = addrS, addrA
	return
}

func exchange(t *testing.T, a, b *Session, from netip.AddrPort, msg string) {
	t.Helper()
	p, err := a.Seal([]byte(msg))
	mustT(t, err)
	if len(p) > MaxDatagram {
		t.Fatalf("datagram %d > %d", len(p), MaxDatagram)
	}
	got, err := b.Open(p, from)
	mustT(t, err)
	if string(got) != msg {
		t.Fatalf("got %q", got)
	}
}

func TestHandshakes(t *testing.T) {
	cfg := DefaultConfig()
	for _, mode := range []BMode{B1ServerKEM, B2ClientKEM} {
		cli, srv, m1, m2 := handshakeB(t, mode, cfg)
		exchange(t, cli, srv, addrA, "ls\r")
		exchange(t, srv, cli, addrS, "ls\r\nfoo bar\r\n")
		t.Logf("B%d: msg1=%d msg2=%d bytes", mode, len(m1), len(m2))
	}
	cli, srv, m1, m2, m3 := handshakeA(t, cfg)
	exchange(t, cli, srv, addrA, "hi")
	exchange(t, srv, cli, addrS, "hello")
	t.Logf("A: msg1=%d msg2=%d msg3=%d bytes", len(m1), len(m2), len(m3))
}

func TestBRetransmitAndSingleUse(t *testing.T) {
	server, cred, _ := NewBServer(B1ServerKEM, serverHello, DefaultConfig())
	client, m1, _ := NewBClient(cred, clientHello, DefaultConfig())
	m2, s1, _, err := server.HandleInit(m1)
	mustT(t, err)
	// msg2 lost: client resends msg1 byte-for-byte; server answers from cache
	m2b, s2, _, err := server.HandleInit(m1)
	mustT(t, err)
	if s2 != nil || !bytes.Equal(m2, m2b) {
		t.Fatal("retransmission must be answered from cache without new state")
	}
	// a second, different client with the same (stolen) credentials loses
	_, m1x, _ := NewBClient(cred, clientHello, DefaultConfig())
	if _, _, _, err := server.HandleInit(m1x); err != ErrState {
		t.Fatalf("credential reuse accepted: %v", err)
	}
	c, _, err := client.HandleResp(m2b)
	mustT(t, err)
	c.Peer, s1.Peer = addrS, addrA
	exchange(t, c, s1, addrA, "x")
}

func TestBWrongCredentialsLeaveStateUntouched(t *testing.T) {
	for _, mode := range []BMode{B1ServerKEM, B2ClientKEM} {
		server, cred, _ := NewBServer(mode, serverHello, DefaultConfig())
		bad := cred
		bad.PSK[0] ^= 1
		_, m1bad, _ := NewBClient(bad, clientHello, DefaultConfig())
		if _, _, _, err := server.HandleInit(m1bad); err != ErrAuth {
			t.Fatalf("mode %d: wrong PSK: %v", mode, err)
		}
		// state untouched: the genuine client still succeeds
		_, m1, _ := NewBClient(cred, clientHello, DefaultConfig())
		if _, _, _, err := server.HandleInit(m1); err != nil {
			t.Fatalf("mode %d: genuine client after attack: %v", mode, err)
		}
	}
}

func TestBTamperEveryByte(t *testing.T) {
	for _, mode := range []BMode{B1ServerKEM, B2ClientKEM} {
		server, cred, _ := NewBServer(mode, serverHello, DefaultConfig())
		client, m1, _ := NewBClient(cred, clientHello, DefaultConfig())
		for i := range m1 {
			if i >= 2 && i < 6 {
				continue // sender index is authenticated too, but skip for speed
			}
			m := bytes.Clone(m1)
			m[i] ^= 0x80
			if _, _, _, err := server.HandleInit(m); err == nil {
				t.Fatalf("mode %d: tampered msg1 byte %d accepted", mode, i)
			}
		}
		m2, _, _, err := server.HandleInit(m1)
		mustT(t, err)
		for i := range m2 {
			m := bytes.Clone(m2)
			m[i] ^= 0x80
			if _, _, err := client.HandleResp(m); err == nil {
				t.Fatalf("mode %d: tampered msg2 byte %d accepted", mode, i)
			}
		}
		_, _, err = client.HandleResp(m2)
		mustT(t, err)
	}
}

func TestAWrongPeerKey(t *testing.T) {
	_, ssk, _ := ed25519.GenerateKey(rand.Reader)
	_, csk, _ := ed25519.GenerateKey(rand.Reader)
	_, evil, _ := ed25519.GenerateKey(rand.Reader)
	var sid [16]byte
	server := NewAServer(AIdentity{SessionID: sid, Self: evil, Peer: csk.Public().(ed25519.PublicKey)}, serverHello, DefaultConfig())
	client, m1, _ := NewAClient(AIdentity{SessionID: sid, Self: csk, Peer: ssk.Public().(ed25519.PublicKey)}, clientHello, DefaultConfig())
	m2, err := server.HandleInit(m1)
	mustT(t, err)
	if _, _, _, err := client.HandleResp(m2); err != ErrAuth {
		t.Fatalf("impostor server accepted: %v", err)
	}
}

// ---------------------------------------------------------------- replay

func TestReplayWindowAgainstModel(t *testing.T) {
	var w replayWindow
	seen := map[uint64]bool{}
	var top uint64
	any := false
	r := func(n int64) uint64 { v, _ := rand.Int(rand.Reader, big.NewInt(n)); return v.Uint64() }
	for i := 0; i < 200000; i++ {
		var c uint64
		switch r(4) {
		case 0:
			c = top + r(5)
		case 1:
			c = top + r(3*ReplayWindow)
		default:
			if top > ReplayWindow+100 {
				c = top - r(ReplayWindow+100)
			} else {
				c = r(ReplayWindow + 100)
			}
		}
		want := !any || c > top || (top-c < ReplayWindow && !seen[c])
		if got := w.check(c); got != want {
			t.Fatalf("i=%d c=%d top=%d: check=%v want %v", i, c, top, got, want)
		}
		if want {
			w.commit(c)
			seen[c] = true
			if !any || c > top {
				top = c
			}
			any = true
		}
	}
}

func TestForgedPacketDoesNotAdvanceWindow(t *testing.T) {
	cli, srv, _, _ := handshakeB(t, B1ServerKEM, DefaultConfig())
	good, _ := cli.Seal([]byte("a"))
	// forged packet: right index, huge counter, garbage ciphertext
	forged := bytes.Clone(good)
	binary.LittleEndian.PutUint64(forged[5:], 1<<40)
	forged[len(forged)-1] ^= 1
	if _, err := srv.Open(forged, addrB); err != ErrAuth {
		t.Fatalf("forged: %v", err)
	}
	if srv.cur.win.seen || srv.Peer != addrA {
		t.Fatal("receive state/peer address changed by an unauthenticated packet")
	}
	if _, err := srv.Open(good, addrA); err != nil {
		t.Fatalf("genuine packet rejected after forgery: %v", err)
	}
	if _, err := srv.Open(good, addrA); err != ErrReplay {
		t.Fatalf("replay accepted: %v", err)
	}
}

func TestRoaming(t *testing.T) {
	cli, srv, _, _ := handshakeB(t, B1ServerKEM, DefaultConfig())
	old, _ := cli.Seal([]byte("old"))
	p1, _ := cli.Seal([]byte("new"))
	if _, err := srv.Open(p1, addrB); err != nil || srv.Peer != addrB {
		t.Fatalf("did not roam to new address: %v %v", err, srv.Peer)
	}
	// a delayed packet from the old address must not drag us back
	if _, err := srv.Open(old, addrA); err != nil || srv.Peer != addrB {
		t.Fatalf("reordered packet moved peer: %v %v", err, srv.Peer)
	}
	// an attacker replaying p1 from a third address must not move us
	if _, err := srv.Open(p1, netip.MustParseAddrPort("192.0.2.66:1")); err != ErrReplay || srv.Peer != addrB {
		t.Fatalf("replay moved peer: %v %v", err, srv.Peer)
	}
}

// ---------------------------------------------------------------- rekey

func pump(t *testing.T, a, b *Session, fromA, fromB netip.AddrPort) {
	t.Helper()
	for i := 0; i < 8; i++ {
		oa, ob := a.Outbox(), b.Outbox()
		if len(oa)+len(ob) == 0 {
			return
		}
		for _, p := range oa {
			if len(p) > MaxDatagram {
				t.Fatalf("rekey datagram %d > %d", len(p), MaxDatagram)
			}
			if _, err := b.Open(p, fromA); err != nil {
				t.Fatalf("pump a->b: %v", err)
			}
		}
		for _, p := range ob {
			if _, err := a.Open(p, fromB); err != nil {
				t.Fatalf("pump b->a: %v", err)
			}
		}
	}
}

func TestRekeyByTime(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1e9, 0)}
	cfg := cfgWith(clk)
	cli, srv, _, _ := handshakeB(t, B1ServerKEM, cfg)
	oldCliKey := cli.cur.sendKey
	oldIdx := srv.cur.localIdx
	clk.add(cfg.RekeyAfterTime + time.Second)
	p, _ := cli.Seal([]byte("trigger")) // queues REKEY_INIT in outbox
	pump(t, cli, srv, addrA, addrS)     // init -> resp
	if _, err := srv.Open(p, addrA); err != nil {
		t.Fatal(err)
	}
	if cli.Stats.Rekeys != 1 || srv.Stats.Rekeys != 0 || srv.next == nil {
		t.Fatalf("after resp: cli=%d srv=%d", cli.Stats.Rekeys, srv.Stats.Rekeys)
	}
	exchange(t, cli, srv, addrA, "first under new keys") // confirms -> server promotes
	if srv.Stats.Rekeys != 1 || srv.cur.localIdx == oldIdx || cli.cur.sendKey == oldCliKey {
		t.Fatal("server did not promote / keys unchanged")
	}
	exchange(t, srv, cli, addrS, "reply")
	// old keys are forgotten after KeepPrevFor
	clk.add(cfg.KeepPrevFor + time.Second)
	cli.Tick()
	srv.Tick()
	if cli.prev != nil || srv.prev != nil {
		t.Fatal("previous keys retained past KeepPrevFor")
	}
}

func TestRekeyCollisionAndLoss(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1e9, 0)}
	cfg := cfgWith(clk)
	cli, srv, _, _, _ := handshakeA(t, cfg)
	cli.StartRekey()
	srv.StartRekey()
	ci, si := cli.Outbox(), srv.Outbox()
	// both inits cross on the wire
	_, err := srv.Open(ci[0], addrA)
	mustT(t, err)
	_, err = cli.Open(si[0], addrS) // client ignores: client wins
	mustT(t, err)
	resp := srv.Outbox()
	if len(resp) != 1 {
		t.Fatalf("server should answer the client's init, got %d", len(resp))
	}
	// resp is lost; client retransmits init after RekeyRetry
	clk.add(cfg.RekeyRetry)
	cli.Tick()
	re := cli.Outbox()
	_, err = srv.Open(re[0], addrA)
	mustT(t, err)
	resp2 := srv.Outbox()
	_, err = cli.Open(resp2[0], addrS)
	mustT(t, err)
	exchange(t, cli, srv, addrA, "after collision+loss")
	exchange(t, srv, cli, addrS, "ok")
	if cli.Stats.Rekeys != 1 || srv.Stats.Rekeys != 1 {
		t.Fatalf("rekeys cli=%d srv=%d", cli.Stats.Rekeys, srv.Stats.Rekeys)
	}
}

func TestRekeyPacketSizes(t *testing.T) {
	cli, srv, _, _ := handshakeB(t, B1ServerKEM, DefaultConfig())
	cli.StartRekey()
	init := cli.Outbox()[0]
	_, err := srv.Open(init, addrA)
	mustT(t, err)
	resp := srv.Outbox()[0]
	t.Logf("rekey init=%d resp=%d bytes (IPv6-safe limit %d, D5 limit %d)", len(init), len(resp), IPv6SafeDatagram, MaxDatagram)
}

// ---------------------------------------------------------------- resume

func TestResumeOverLocalSocket(t *testing.T) {
	dir := t.TempDir() + "/rt"
	var server *BServer
	rs, err := ListenResume(dir, func() (BCredentials, error) {
		s, c, err := NewBServer(B1ServerKEM, serverHello, DefaultConfig())
		server = s
		return c, err
	})
	mustT(t, err)
	defer rs.Close()
	done := make(chan error, 1)
	go func() { done <- rs.ServeOne() }()
	cred, err := RequestCredentials(rs.Path) // what `mosey-server attach` does over SSH
	mustT(t, err)
	mustT(t, <-done)
	client, m1, err := NewBClient(cred, clientHello, DefaultConfig())
	mustT(t, err)
	m2, _, _, err := server.HandleInit(m1)
	mustT(t, err)
	_, _, err = client.HandleResp(m2)
	mustT(t, err)

	// a peer with another uid is refused
	rs.PeerUID = func(*net.UnixConn) (uint32, error) { return 4242, nil }
	go func() { done <- rs.ServeOne() }()
	RequestCredentials(rs.Path)
	if err := <-done; err != ErrForeignPeer {
		t.Fatalf("foreign uid: %v", err)
	}
}
