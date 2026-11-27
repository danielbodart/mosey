package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/danielbodart/mosey/internal/handshake"
	"github.com/danielbodart/mosey/internal/hostname"
)

var attackerAddr = netip.MustParseAddrPort("203.0.113.99:4444")

// TestALeakedCredentialLineCannotConnectAndForgeriesOnlyDelayTheClient
// plays threat-model.md T9 against the real listener (transport.md §3.8,
// §11): the attacker holds the whole credential line and the client's
// public key, and the moment the genuine msg2 goes out it floods the server
// with forged msg1s, which evict the genuine pending (each with chance 1/4).
// The client's next msg1 resend is answered afresh, it takes the new msg2,
// and it confirms. The attacker never gets a connection: reading any msg2
// takes the client's private key.
func TestALeakedCredentialLineCannotConnectAndForgeriesOnlyDelayTheClient(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 20*time.Millisecond)
		cred, key := s.mint()
		leaked, public := cred, key.PublicKey()
		var msg2s int
		s.net.setTap(func(p memPacket) []memPacket {
			if p.data[0] != handshake.TypeMsg2 || p.to != clientAddr {
				return []memPacket{p}
			}
			msg2s++
			out := []memPacket{p}
			if msg2s == 1 {
				// 40 forgeries leave the genuine pending standing with
				// chance (3/4)^40, about 1 in 100,000.
				for i := range 40 {
					forged := must(handshake.ForgeMsg1(leaked, public, uint32(1000+i)))
					out = append(out, memPacket{from: attackerAddr, to: serverAddr, data: forged, delay: time.Millisecond})
				}
			}
			return out
		})
		csock := s.net.listen(clientAddr.String())
		client, err := Dial(context.Background(), csock, serverAddr, cred, key, nil)
		if err != nil {
			t.Fatalf("the genuine client could not connect: %v", err)
		}
		defer client.Close()
		if n := read(s.net, &msg2s); n < 2 {
			t.Errorf("the client confirmed under its first msg2 (%d msg2s); the forgeries evicted nothing", n)
		}
		server, err := s.l.Accept(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		exchange(t, client, server, "after the forgeries")
		ctx, cancel := context.WithTimeout(context.Background(), handshake.CredentialTTL)
		defer cancel()
		if c, err := s.l.Accept(ctx); err == nil {
			t.Fatalf("the attacker got a connection from %v", c.Peer())
		}
	})
}

func TestDialFailsWhenMsg2ArrivesButTheServerNeverConfirms(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 20*time.Millisecond)
		answered := false
		s.net.setTap(func(p memPacket) []memPacket {
			if p.data[0] == handshake.TypeMsg2 {
				answered = true
				return []memPacket{p}
			}
			if answered && p.to == serverAddr {
				return nil // the confirmation, and every resend, are lost
			}
			return []memPacket{p}
		})
		cred, key := s.mint()
		csock := s.net.listen(clientAddr.String())
		start := time.Now()
		_, err := Dial(context.Background(), csock, serverAddr, cred, key, nil)
		if err == nil || !strings.Contains(err.Error(), "never confirmed") {
			t.Fatalf("got %v", err)
		}
		if took := time.Since(start); took != handshake.CredentialTTL {
			t.Errorf("gave up after %v", took)
		}
	})
}

// TestAMsg2IdenticalToTheAcceptedOneIsIgnored: the server answers a resent
// msg1 from its cache, byte for byte, and the client must not take that as
// a new answer (which would reset its keys and confirm twice).
func TestAMsg2IdenticalToTheAcceptedOneIsIgnored(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 20*time.Millisecond)
		var confirmations int
		s.net.setTap(func(p memPacket) []memPacket {
			if p.data[0] == handshake.TypeMsg2 {
				again := p
				again.delay += 5 * time.Millisecond
				return []memPacket{p, again}
			}
			if p.to == serverAddr && len(p.data) == keepaliveSize {
				confirmations++
			}
			return []memPacket{p}
		})
		client, server, _ := s.connect(clientAddr.String())
		if confirmations != 1 {
			t.Errorf("the client confirmed %d times", confirmations)
		}
		exchange(t, client, server, "once")
	})
}

func TestARefusedMsg1LeavesNoIndexBehind(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 20*time.Millisecond)
		cred, key := s.mint()
		genuine := must(handshake.ForgeMsg1(cred, key.PublicKey(), 7))
		s.l.e.lock()
		defer s.l.e.unlock()
		before := len(s.l.e.table.m)
		for at := range genuine {
			bad := bytes.Clone(genuine)
			bad[at] ^= 0x40
			s.l.handle(bad, clientAddr)
		}
		if after := len(s.l.e.table.m); after != before {
			t.Errorf("refused msg1s left %d indices behind", after-before)
		}
		s.l.handle(genuine, clientAddr)
		if after := len(s.l.e.table.m); after != before+1 {
			t.Errorf("the genuine msg1 registered %d indices", after-before)
		}
	})
}

// A pending given up after MaxFailedOpens forgeries is forgotten by the
// responder too, so a byte-identical resend of its msg1 makes a new
// pending with new keys, never one rebuilt from the wiped keys of the old,
// under which anyone could seal a confirmation.
func TestAPendingGivenUpIsNeverRebuiltFromWipedKeys(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 20*time.Millisecond)
		cred, key := s.mint()
		msg1 := must(handshake.ForgeMsg1(cred, key.PublicKey(), 7))
		s.l.e.lock()
		defer s.l.e.unlock()
		s.l.handle(msg1, clientAddr)
		if len(s.l.pendings) != 1 {
			t.Fatalf("%d pendings after msg1", len(s.l.pendings))
		}
		var old *pending
		for _, pc := range s.l.pendings {
			old = pc
		}
		// One forgery short of the limit, then the last one.
		old.ks.failures = MaxFailedOpens - 1
		forged := make([]byte, Overhead+8)
		forged[0] = TypeData
		binary.LittleEndian.PutUint32(forged[1:], old.ks.local)
		s.l.handle(forged, clientAddr)
		if len(s.l.pendings) != 0 || !old.p.Erased() {
			t.Fatalf("after MaxFailedOpens: %d pendings, the old erased %v", len(s.l.pendings), old.p.Erased())
		}

		s.l.handle(msg1, clientAddr)
		if len(s.l.pendings) != 1 {
			t.Fatalf("%d pendings after the resend", len(s.l.pendings))
		}
		for p, pc := range s.l.pendings {
			if p == old.p || pc.root == [32]byte{} {
				t.Fatal("the resend rebuilt the given-up pending")
			}
		}
	})
}

// Whatever the responder returns, the listener builds no key set from
// wiped keys: a pending it has no record of, whose keys are zero, is
// dropped.
func TestAPendingWithWipedKeysIsDropped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 20*time.Millisecond)
		cred, key := s.mint()
		msg1 := must(handshake.ForgeMsg1(cred, key.PublicKey(), 7))
		s.l.e.lock()
		defer s.l.e.unlock()
		s.l.handle(msg1, clientAddr)
		// The listener forgets its pending without telling the responder:
		// the bug Evict closes.
		for p, pc := range s.l.pendings {
			pc.erase(s.l.e)
			delete(s.l.pendings, p)
		}
		before := len(s.l.e.table.m)
		s.l.handle(msg1, clientAddr)
		if len(s.l.pendings) != 0 || len(s.l.e.table.m) != before {
			t.Fatalf("a pending was rebuilt from wiped keys: %d pendings, %d indices", len(s.l.pendings), len(s.l.e.table.m)-before)
		}
	})
}

func TestTheIndexOfAPendingIsFreedWhenItsCredentialExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 20*time.Millisecond)
		cred, key := s.mint()
		s.l.e.lock()
		before := len(s.l.e.table.m)
		s.l.handle(must(handshake.ForgeMsg1(cred, key.PublicKey(), 7)), clientAddr)
		during := len(s.l.e.table.m)
		s.l.e.unlock()
		time.Sleep(handshake.CredentialTTL + 2*time.Second)
		s.l.e.lock()
		after := len(s.l.e.table.m)
		pendings := len(s.l.pendings)
		s.l.e.unlock()
		if during != before+1 || after != before || pendings != 0 {
			t.Errorf("indices %d → %d → %d, %d pendings left", before, during, after, pendings)
		}
	})
}

func TestARevokedClientIsToldWhoTookOverAndWhen(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 20*time.Millisecond)
		first, firstServer, _ := s.connect(clientAddr.String())
		elsewhere := netip.MustParseAddrPort("198.51.100.200:50000")
		at := time.Now()
		second, secondServer, _ := s.connect(elsewhere.String())
		time.Sleep(time.Second)
		var revoked []Revoked
		for _, ev := range events(first) {
			if r, ok := ev.(Revoked); ok {
				revoked = append(revoked, r)
			}
		}
		// The takeover happens when the server confirms the new client:
		// msg1 out, msg2 back and the confirmation out, 60 ms after Dial.
		if len(revoked) != 1 || revoked[0].By != elsewhere || !revoked[0].At.Equal(at.Add(60*time.Millisecond)) {
			t.Fatalf("revocations %+v; want one by %v at %v", revoked, elsewhere, at)
		}
		if _, err := first.Recv(context.Background()); !errors.Is(err, ErrRevoked) {
			t.Errorf("the revoked client's Recv: %v", err)
		}
		if _, err := firstServer.Recv(context.Background()); !errors.Is(err, ErrRevoked) {
			t.Errorf("the revoked connection's Recv on the server: %v", err)
		}
		if firstServer.cur != nil || firstServer.root != ([32]byte{}) {
			t.Error("revocation left the server's keys behind")
		}
		exchange(t, second, secondServer, "taken over")
	})
}

// The REVOKED frame names the new client's host when it claimed one, the
// name its credential was minted with, beside its address (§8.3).
func TestRevokedNamesTheNewClientsHost(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 20*time.Millisecond)
		first, _, _ := s.connect(clientAddr.String())
		s.host = "blade"
		elsewhere := netip.MustParseAddrPort("198.51.100.200:50000")
		_, secondServer, _ := s.connect(elsewhere.String())
		time.Sleep(time.Second)
		var revoked []Revoked
		for _, ev := range events(first) {
			if r, ok := ev.(Revoked); ok {
				revoked = append(revoked, r)
			}
		}
		if len(revoked) != 1 || revoked[0].By != elsewhere || revoked[0].Host != "blade" {
			t.Fatalf("revocations %+v; want one by blade at %v", revoked, elsewhere)
		}
		if h := secondServer.ClientHost(); h != "blade" {
			t.Errorf("the server's connection says its client is %q", h)
		}
	})
}

// TestARevokedClientsLaterPacketsDrawAtMostThreeCopies: the first REVOKED
// is lost, so the old client carries on sending; its packets reach the
// tombstone, which answers with the three copies sealed before the keys
// were erased, at most one per 250 ms, and then nothing. A copy that names
// the longest host still goes: it is under 3x the packets that draw it.
func TestARevokedClientsLaterPacketsDrawAtMostThreeCopies(t *testing.T) {
	for name, host := range map[string]string{"no host": "", "the longest host": strings.Repeat("h", hostname.Max)} {
		t.Run(name, func(t *testing.T) { revokedCopiesDrawn(t, host) })
	}
}

func revokedCopiesDrawn(t *testing.T, host string) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 20*time.Millisecond)
		first, _, _ := s.connect(clientAddr.String())
		revokedSize := 30 + 15 // an IPv4 REVOKED frame
		if host != "" {
			revokedSize += 1 + len(host)
		}
		s.host = host
		var copies int
		s.net.setTap(func(p memPacket) []memPacket {
			if p.to == clientAddr && len(p.data) == revokedSize {
				copies++
				return nil
			}
			return []memPacket{p}
		})
		s.connect("198.51.100.200:50000")
		for range 10 {
			first.Send([]byte("still typing"))
			time.Sleep(300 * time.Millisecond)
		}
		if n := read(s.net, &copies); n != revokedCopies {
			t.Errorf("%d REVOKED packets went to the old client, not %d", n, revokedCopies)
		}
	})
}
