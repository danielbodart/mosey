package transport

import (
	"net/netip"
	"testing"
	"testing/synctest"
	"time"
)

// Sizes of the path frames on the wire (transport.md §4.2): a keepalive is
// 31 bytes, a PATH_CHALLENGE or PATH_RESPONSE 38.
const (
	keepaliveSize = 31
	pathFrameSize = 38
)

func peerChanges(c *Conn) []PeerChanged {
	var out []PeerChanged
	for _, ev := range events(c) {
		if pc, ok := ev.(PeerChanged); ok {
			out = append(out, pc)
		}
	}
	return out
}

// TestTheS5AdversaryDrawsAtMostThreeTimesWhatItSentAndMovesNothing plays
// S5's attacker (transport.md §7.3, §11): it sees every client packet,
// re-sends a copy from a victim's address and wins the race with it. Under
// the paper's "newest authentic source" rule that pointed the screen at the
// victim; here the victim gets at most 3x what the attacker sent from its
// address, and the client notices nothing.
func TestTheS5AdversaryDrawsAtMostThreeTimesWhatItSentAndMovesNothing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 20*time.Millisecond)
		client, server, _ := s.connect(clientAddr.String())
		var spoofed int
		s.net.setTap(func(p memPacket) []memPacket {
			if p.from != clientAddr || p.to != serverAddr {
				return []memPacket{p}
			}
			copied := p
			copied.from, copied.delay = victimAddr, 5*time.Millisecond
			spoofed += len(p.data)
			return []memPacket{copied, p}
		})
		screen := make([]byte, 1000)
		for i := range 100 {
			if err := client.Send([]byte{byte(i)}); err != nil {
				t.Fatal(err)
			}
			if got := recv(t, server); got[0] != byte(i) {
				t.Fatalf("the server got keystroke %d, not %d", got[0], i)
			}
			if err := server.Send(screen); err != nil {
				t.Fatalf("the server could not send to its client: %v", err)
			}
			recv(t, client)
			time.Sleep(200 * time.Millisecond)
		}
		victim, spoofed := s.net.received(victimAddr), read(s.net, &spoofed)
		if victim > AmplificationFactor*spoofed {
			t.Errorf("the victim received %d bytes for %d spoofed: more than %dx", victim, spoofed, AmplificationFactor)
		}
		if victim == 0 {
			t.Error("the server never challenged the victim: the attack did not reach it")
		}
		if server.Peer() != clientAddr || len(peerChanges(server)) != 0 {
			t.Errorf("the server moved to %v", server.Peer())
		}
	})
}

func TestAGenuineRoamIsValidatedAndTheServerFollows(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 20*time.Millisecond)
		client, server, csock := s.connect(clientAddr.String())
		moved := netip.MustParseAddrPort("198.51.100.99:41000")
		csock.rebind(moved.String())
		client.LocalAddressChanged()
		time.Sleep(200 * time.Millisecond)
		if server.Peer() != moved {
			t.Fatalf("the server still sends to %v", server.Peer())
		}
		if got := peerChanges(server); len(got) != 1 || got[0] != (PeerChanged{From: clientAddr, To: moved}) {
			t.Errorf("events %+v", got)
		}
		exchange(t, client, server, "from the new address")
	})
}

func TestALostChallengeIsResentOnItsTimer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 20*time.Millisecond)
		client, server, csock := s.connect(clientAddr.String())
		moved := netip.MustParseAddrPort("198.51.100.99:41000")
		var challenges []time.Time
		s.net.setTap(func(p memPacket) []memPacket {
			if p.to == moved && len(p.data) == pathFrameSize {
				challenges = append(challenges, time.Now())
				if len(challenges) == 1 {
					return nil
				}
			}
			return []memPacket{p}
		})
		csock.rebind(moved.String())
		start := time.Now()
		// One SSP datagram from the new address, and nothing more: its bytes
		// are the budget the resends spend (a lone 31-byte keepalive earns
		// room for one challenge and the keepalive's answer, no more).
		if err := client.Send(make([]byte, 200)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Second)
		if server.Peer() != moved {
			t.Fatalf("the server still sends to %v after the challenge was lost", server.Peer())
		}
		challenges = read(s.net, &challenges)
		if len(challenges) != 2 {
			t.Fatalf("%d challenges", len(challenges))
		}
		if gap := challenges[1].Sub(challenges[0]); gap != challengeFirst {
			t.Errorf("the challenge was resent after %v, not %v", gap, challengeFirst)
		}
		if took := challenges[1].Sub(start); took > time.Second {
			t.Errorf("the resend took %v", took)
		}
	})
}

func TestAnUnansweredCandidateIsAbandonedAfterTenSeconds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 20*time.Millisecond)
		client, server, csock := s.connect(clientAddr.String())
		moved := netip.MustParseAddrPort("198.51.100.99:41000")
		var challenges int
		s.net.setTap(func(p memPacket) []memPacket {
			if p.to == moved && len(p.data) == pathFrameSize {
				challenges++
				return nil
			}
			return []memPacket{p}
		})
		csock.rebind(moved.String())
		client.LocalAddressChanged()
		time.Sleep(candidateLife + time.Second)
		server.e.lock()
		cand := server.cand
		server.e.unlock()
		if cand != nil {
			t.Error("the candidate outlived its 10 s")
		}
		// The timer fires at 0, 0.25, 0.75, 1.75, 2.75 s and so on, but
		// every send is within the 3x budget of the one 31-byte keepalive:
		// the first challenge (38) and the keepalive's answer (31) fit in
		// 93 bytes, and no resend does.
		if n := read(s.net, &challenges); n != 1 {
			t.Errorf("%d challenges to an address that sent one keepalive", n)
		}
		if received := s.net.received(moved); received > AmplificationFactor*keepaliveSize {
			t.Errorf("the unvalidated address received %d bytes for %d", received, keepaliveSize)
		}
	})
}

// TestAConfirmationFromTheOneAddressMsg2WentToValidatesIt is the common
// case of transport.md §7.3: S = {X}, so the address is validated at once
// with no challenge.
func TestAConfirmationFromTheOneAddressMsg2WentToValidatesIt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 20*time.Millisecond)
		var challenges int
		s.net.setTap(func(p memPacket) []memPacket {
			if len(p.data) == pathFrameSize {
				challenges++
			}
			return []memPacket{p}
		})
		_, server, _ := s.connect(clientAddr.String())
		challenges = read(s.net, &challenges)
		if server.Peer() != clientAddr || challenges != 0 || len(peerChanges(server)) != 0 {
			t.Errorf("peer %v after %d challenges", server.Peer(), challenges)
		}
	})
}

// TestAMsg1FromTwoAddressesMakesTheConfirmationChallenged: msg1 arrived
// from the client and, replayed, from a victim, so msg2 went to both and
// the confirmation cannot say which was read. The client's address is
// validated only by a challenge.
func TestAMsg1FromTwoAddressesMakesTheConfirmationChallenged(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 20*time.Millisecond)
		s.net.setTap(func(p memPacket) []memPacket {
			if p.data[0] == TypeMsg1 {
				replayed := p
				replayed.from, replayed.delay = victimAddr, 10*time.Millisecond
				return []memPacket{replayed, p}
			}
			return []memPacket{p}
		})
		client, server, _ := s.connect(clientAddr.String())
		time.Sleep(200 * time.Millisecond)
		if got := peerChanges(server); len(got) != 1 || got[0].To != clientAddr || got[0].From.IsValid() {
			t.Errorf("the client was not validated by a challenge: %+v", got)
		}
		if server.Peer() != clientAddr {
			t.Errorf("peer %v", server.Peer())
		}
		exchange(t, client, server, "validated")
	})
}

// TestARelayedMsg2DoesNotValidateTheVictim is relayed validation (a) of
// transport.md §11: an attacker re-sources the client's msg1 from a victim,
// so msg2 goes only to the victim, and relays that msg2 to the client,
// which confirms from its own address. The confirmation proves someone read
// msg2, not that the victim did, so the victim is not validated.
func TestARelayedMsg2DoesNotValidateTheVictim(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 20*time.Millisecond)
		var spoofed int
		s.net.setTap(func(p memPacket) []memPacket {
			switch {
			case p.data[0] == TypeMsg1:
				p.from = victimAddr
				spoofed += len(p.data)
				return []memPacket{p}
			case p.data[0] == TypeMsg2 && p.to == victimAddr:
				relayed := p
				relayed.to = clientAddr
				return []memPacket{p, relayed}
			}
			return []memPacket{p}
		})
		client, server, _ := s.connect(clientAddr.String())
		time.Sleep(time.Second)
		if server.Peer() == victimAddr {
			t.Fatal("the victim was validated")
		}
		for _, pc := range peerChanges(server) {
			if pc.To == victimAddr {
				t.Fatal("the server moved to the victim")
			}
		}
		if server.Peer() != clientAddr {
			t.Errorf("the client's own address was not validated by its challenge: %v", server.Peer())
		}
		exchange(t, client, server, "after the relay")
		if victim, spoofed := s.net.received(victimAddr), read(s.net, &spoofed); victim > AmplificationFactor*spoofed {
			t.Errorf("the victim received %d bytes for %d spoofed", victim, spoofed)
		}
	})
}

// TestARelayedChallengeDoesNotValidateTheVictim is relayed validation (b):
// a client packet re-sourced from a victim makes the victim the candidate,
// and the attacker relays the challenge sent there to the client. The
// client's answer comes from the client's own address, not the victim's,
// so it validates nothing (stricter than QUIC; threat-model.md §4.4).
func TestARelayedChallengeDoesNotValidateTheVictim(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 20*time.Millisecond)
		client, server, _ := s.connect(clientAddr.String())
		var copied bool
		s.net.setTap(func(p memPacket) []memPacket {
			switch {
			case p.from == clientAddr && p.to == serverAddr && !copied:
				copied = true
				spoofed := p
				spoofed.from, spoofed.delay = victimAddr, 5*time.Millisecond
				return []memPacket{spoofed, p}
			case p.to == victimAddr && len(p.data) == pathFrameSize:
				relayed := p
				relayed.to = clientAddr
				return []memPacket{p, relayed}
			}
			return []memPacket{p}
		})
		client.Send([]byte("a keystroke"))
		time.Sleep(2 * time.Second)
		if server.Peer() != clientAddr || len(peerChanges(server)) != 0 {
			t.Fatalf("the server moved to %v", server.Peer())
		}
		drain(server)
		exchange(t, client, server, "unmoved")
	})
}
