package transport

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"net"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/danielbodart/mosey/internal/handshake"
	"github.com/danielbodart/mosey/internal/wire"
)

func TestAClientAndServerHandshakeAndExchangePayloads(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 20*time.Millisecond)
		client, server, _ := s.connect(clientAddr.String())
		exchange(t, client, server, "hello")
		if server.Peer() != clientAddr {
			t.Errorf("the server sends to %v, not the address msg2 went to", server.Peer())
		}
		if client.Peer() != serverAddr {
			t.Errorf("the client sends to %v", client.Peer())
		}
		if s.creds.Live() != 0 {
			t.Error("confirmation left the credential live")
		}
		// Both ends name the credential they were made with, which the
		// greeting's holder and R3's reconnect compare (bootstrap.md §9.2).
		if client.CredentialID() != server.CredentialID() || client.CredentialID() == ([8]byte{}) {
			t.Errorf("credential ids %x and %x", client.CredentialID(), server.CredentialID())
		}
	})
}

func TestDialReturnsOnlyOnceTheServerHasConfirmed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 50*time.Millisecond)
		cred, key := s.mint()
		csock := s.net.listen(clientAddr.String())
		start := time.Now()
		client, err := Dial(context.Background(), csock, serverAddr, cred, key, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		// msg1 out, msg2 back, the confirmation out, its answer back: two
		// round trips of 100 ms.
		if took := time.Since(start); took != 200*time.Millisecond {
			t.Errorf("Dial returned after %v; confirmation takes two round trips", took)
		}
		if _, err := s.l.Accept(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestPacketsAreTheSizesTheSpecSays(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 10*time.Millisecond)
		sizes := map[int]int{}
		s.net.setTap(func(p memPacket) []memPacket {
			sizes[len(p.data)]++
			if len(p.data) > wire.MaxDatagram {
				t.Errorf("a %d-byte datagram", len(p.data))
			}
			if p.data[0] != TypeData && len(p.data) > wire.MaxHandshake {
				t.Errorf("a %d-byte handshake message", len(p.data))
			}
			return []memPacket{p}
		})
		client, server, _ := s.connect(clientAddr.String())
		if err := client.Send(make([]byte, MaxPayload)); err != nil {
			t.Fatal(err)
		}
		if err := client.Send(make([]byte, MaxPayload+1)); err == nil {
			t.Error("a payload over MaxPayload was sent")
		}
		recv(t, server)
		time.Sleep(RekeyAfter)
		exchange(t, client, server, "after a rekey")
		time.Sleep(time.Second)
		var seen map[int]int
		s.net.locked(func() { seen = maps.Clone(sizes) })
		for size, want := range map[int]string{
			1170: "msg1", 1150: "msg2", 31: "keepalive", 1232: "full terminal packet",
			642: "REKEY_INIT half", 1154: "REKEY_RESP",
		} {
			if seen[size] == 0 {
				t.Errorf("no %d-byte %s was seen; sizes %v", size, want, seen)
			}
		}
		if Overhead != 30 || MaxPayload != 1202 {
			t.Errorf("overhead %d, max payload %d", Overhead, MaxPayload)
		}
	})
}

func TestEveryTamperedByteOfADataPacketIsRefusedAndChangesNothing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 10*time.Millisecond)
		client, server, _ := s.connect(clientAddr.String())
		var captured []byte
		s.net.setTap(func(p memPacket) []memPacket {
			if p.to == serverAddr && captured == nil {
				captured = bytes.Clone(p.data)
				return nil
			}
			return []memPacket{p}
		})
		client.Send([]byte("the genuine keystrokes"))
		time.Sleep(time.Second)
		s.net.setTap(nil)
		captured = read(s.net, &captured)

		before := snapshotConn(server)
		for at := range captured {
			for _, flip := range []byte{0x01, 0x80} {
				bad := bytes.Clone(captured)
				bad[at] ^= flip
				s.l.e.lock()
				s.l.handle(bad, victimAddr)
				s.l.e.unlock()
				if after := snapshotConn(server); after != before {
					t.Fatalf("byte %d ^ %#x changed the connection: %+v → %+v", at, flip, before, after)
				}
			}
		}
		// The genuine packet, from the genuine address, still lands.
		s.l.e.lock()
		s.l.handle(captured, clientAddr)
		s.l.e.unlock()
		if got := string(recv(t, server)); got != "the genuine keystrokes" {
			t.Errorf("got %q", got)
		}
	})
}

// connState is everything a refused packet must leave alone (transport.md
// §5): the window, the keys, the epoch, the peer, the amplification
// counters, and the rekey and path state.
type connState struct {
	top           uint64
	seen          bool
	epoch         uint64
	peer          string
	cand          string
	candRecv      int
	candSent      int
	rekey, answer bool
	awaiting      bool
	queued        int
	cur           uint32
	root          [32]byte
}

func snapshotConn(c *Conn) connState {
	c.e.lock()
	defer c.e.unlock()
	return snapshotLocked(c)
}

// snapshotLocked is snapshotConn for a caller that holds the lock.
func snapshotLocked(c *Conn) connState {
	s := connState{epoch: c.epoch, peer: c.peer.String(), rekey: c.rekey != nil, answer: c.answer != nil,
		awaiting: c.awaiting, queued: len(c.recvq), root: c.root}
	if c.cur != nil {
		s.top, s.seen = c.cur.window.Top()
		s.cur = c.cur.local
	}
	if c.cand != nil {
		s.cand, s.candRecv, s.candSent = c.cand.addr.String(), c.cand.recv, c.cand.sent
	}
	return s
}

func TestAReplayedPacketIsDeliveredOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 10*time.Millisecond)
		client, server, _ := s.connect(clientAddr.String())
		s.net.setTap(func(p memPacket) []memPacket {
			later := p
			later.delay = p.delay + 300*time.Millisecond
			return []memPacket{p, later}
		})
		client.Send([]byte("ls\r"))
		time.Sleep(time.Second)
		if got := string(recv(t, server)); got != "ls\r" {
			t.Fatalf("got %q", got)
		}
		if n := len(server.recvq); n != 0 {
			t.Errorf("the replay was delivered too: %d more payloads", n)
		}
		if server.Stats().Dropped[Replay] == 0 {
			t.Error("the replay was not counted")
		}
	})
}

func TestAKeepaliveAskingForAnAnswerGetsExactlyOne(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 10*time.Millisecond)
		client, _, _ := s.connect(clientAddr.String())
		var toClient, toServer int
		s.net.setTap(func(p memPacket) []memPacket {
			if p.to == serverAddr {
				toServer++
			} else {
				toClient++
			}
			return []memPacket{p}
		})
		client.LocalAddressChanged()
		time.Sleep(time.Second)
		if toServer, toClient := read(s.net, &toServer), read(s.net, &toClient); toServer != 1 || toClient != 1 {
			t.Errorf("one keepalive out drew %d back (%d out)", toClient, toServer)
		}
	})
}

func TestUnknownFrameKindsAreIgnoredAfterAuthentication(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 10*time.Millisecond)
		client, server, _ := s.connect(clientAddr.String())
		client.e.lock()
		client.sendFrame(Kind(0x7f), []byte("from a later slice"))
		client.sendFrame(KindChaff, []byte("cover"))
		client.sendFrame(KindKeepalive, []byte{1, 2}) // a known kind, wrong length
		client.e.unlock()
		time.Sleep(time.Second)
		before := snapshotConn(server)
		if !before.seen || before.top < 3 {
			t.Errorf("ignored frames were not committed to the window: top %d", before.top)
		}
		exchange(t, client, server, "still fine")
	})
}

func TestCloseWipesTheKeysAndEndsRecv(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 10*time.Millisecond)
		client, server, _ := s.connect(clientAddr.String())
		client.Close()
		if _, err := client.Recv(context.Background()); !errors.Is(err, net.ErrClosed) {
			t.Errorf("Recv after Close: %v", err)
		}
		if err := client.Send([]byte("x")); !errors.Is(err, net.ErrClosed) {
			t.Errorf("Send after Close: %v", err)
		}
		if client.cur != nil || client.root != ([32]byte{}) {
			t.Error("Close left keys behind")
		}
		s.l.Close()
		if _, err := server.Recv(context.Background()); !errors.Is(err, net.ErrClosed) {
			t.Errorf("the server's Recv after the listener closed: %v", err)
		}
		if _, err := s.l.Accept(context.Background()); !errors.Is(err, net.ErrClosed) {
			t.Errorf("Accept after Close: %v", err)
		}
	})
}

func TestAPacketToAReservedIndexIsDroppedAndChangesNothing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 10*time.Millisecond)
		client, server, _ := s.connect(clientAddr.String())
		s.l.e.lock()
		idx := s.l.e.table.reserve()
		s.l.e.unlock()
		// Seal a genuine packet, then send it to the reserved index.
		client.e.lock()
		pkt, _ := client.cur.seal(KindTerminal, []byte("x"))
		client.e.unlock()
		pkt[1], pkt[2], pkt[3], pkt[4] = byte(idx), byte(idx>>8), byte(idx>>16), byte(idx>>24)
		before := snapshotConn(server)
		drops := s.l.Stats().Dropped[UnknownIndex]
		s.l.e.lock()
		s.l.handle(pkt, clientAddr)
		s.l.e.unlock()
		if snapshotConn(server) != before || s.l.Stats().Dropped[UnknownIndex] != drops+1 {
			t.Error("a packet to a reserved index was not dropped as unknown")
		}
	})
}

func TestARealUDPSocketOnLoopbackWorksToo(t *testing.T) {
	// No synctest: real sockets do not block durably. Nothing here asserts
	// a time; the deadline is only there so a hang fails.
	ssock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("no loopback UDP: %v", err)
	}
	creds := handshake.NewCredentials(nil)
	l := Listen(ssock, creds, nil)
	defer l.Close()
	key := must(handshake.NewOneShotKey())
	cred := must(creds.Mint(must(handshake.NewSessionID()), key.PublicKey()))
	csock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client, err := Dial(ctx, csock, ssock.LocalAddr().(*net.UDPAddr).AddrPort(), cred, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := l.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Send([]byte("over the loopback")); err != nil {
		t.Fatal(err)
	}
	got, err := server.Recv(ctx)
	if err != nil || string(got) != "over the loopback" {
		t.Fatalf("got %q, %v", got, err)
	}
	if server.Peer() != csock.LocalAddr().(*net.UDPAddr).AddrPort() {
		t.Errorf("the server validated %v", server.Peer())
	}
}

func TestDialFailsWithAPlainReasonWhenNothingAnswers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 10*time.Millisecond)
		s.net.setTap(func(memPacket) []memPacket { return nil })
		cred, key := s.mint()
		csock := s.net.listen(clientAddr.String())
		start := time.Now()
		_, err := Dial(context.Background(), csock, serverAddr, cred, key, nil)
		if err == nil || !strings.Contains(err.Error(), "no answer over UDP") {
			t.Fatalf("got %v", err)
		}
		if took := time.Since(start); took != handshake.CredentialTTL {
			t.Errorf("gave up after %v, not the credential's TTL", took)
		}
	})
}

func TestDialFailsWhenCtxIsDone(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 10*time.Millisecond)
		s.net.setTap(func(memPacket) []memPacket { return nil })
		cred, key := s.mint()
		csock := s.net.listen(clientAddr.String())
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := Dial(ctx, csock, serverAddr, cred, key, nil); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("got %v", err)
		}
	})
}
