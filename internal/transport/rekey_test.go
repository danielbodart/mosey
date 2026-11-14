package transport

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"testing"
	"testing/synctest"
	"time"
)

// Sizes that pick rekey frames out of the traffic, as an on-path attacker
// can (threat-model.md §4.3). Test payloads are kept small so nothing else
// has these sizes.
const (
	initHalfSize = 30 + 612
	respSize     = 30 + 1124
)

func isRekeyFrame(p memPacket) bool {
	return len(p.data) == initHalfSize || len(p.data) == respSize
}

// setAge makes a connection's current keys look as old as age, as if time
// had passed for them alone.
func setAge(c *Conn, age time.Duration) {
	c.e.lock()
	defer c.e.unlock()
	c.cur.installed = time.Now().Add(-age)
}

// ageBy makes a connection's current keys look older by d, so random
// schedules reach RekeyAfter, and sometimes RejectAfterTime, quickly.
func ageBy(c *Conn, d time.Duration) {
	c.e.lock()
	defer c.e.unlock()
	c.cur.installed = c.cur.installed.Add(-d)
}

// drain throws away the terminal payloads waiting for Recv.
func drain(c *Conn) {
	for {
		select {
		case <-c.recvq:
		default:
			return
		}
	}
}

func roots(c *Conn) (root [32]byte, epoch uint64, inFlight bool) {
	c.e.lock()
	defer c.e.unlock()
	return c.root, c.epoch, c.rekey != nil || c.next != nil || c.awaiting
}

func TestKeysAreReplacedEveryTwoMinutesAndBothSidesAgree(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 30*time.Millisecond)
		client, server, _ := s.connect(clientAddr.String())
		root0, _, _ := roots(client)
		for i := range 10 {
			time.Sleep(25 * time.Second) // SSP's heartbeat is 3 s; any sending will do
			exchange(t, client, server, fmt.Sprint(i))
		}
		time.Sleep(5 * time.Second)
		croot, cepoch, cflight := roots(client)
		sroot, sepoch, sflight := roots(server)
		if cepoch != 2 || sepoch != 2 {
			t.Errorf("after 250 s the epochs are %d and %d, not 2", cepoch, sepoch)
		}
		if croot != sroot || croot == root0 {
			t.Error("the roots disagree, or never changed")
		}
		if cflight || sflight {
			t.Error("a rekey is still in flight")
		}
		var rekeyed int
		for _, ev := range append(events(client), events(server)...) {
			if _, ok := ev.(Rekeyed); ok {
				rekeyed++
			}
		}
		if rekeyed != 4 {
			t.Errorf("%d Rekeyed events across both ends, not 2 each", rekeyed)
		}
		if client.HandshakeHash() != server.HandshakeHash() {
			t.Error("a rekey changed the handshake hash")
		}
	})
}

func TestThePreviousKeysAreWipedTenSecondsAfterARotation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 10*time.Millisecond)
		client, server, _ := s.connect(clientAddr.String())
		// The server's epoch is past the responder floor, so it answers the
		// first INIT rather than its resend.
		setAge(server, 10*time.Second)
		setAge(client, RekeyAfter)
		exchange(t, client, server, "rekey now")
		time.Sleep(time.Second)
		client.e.lock()
		prev := client.prev
		client.e.unlock()
		if prev == nil {
			t.Fatal("no previous keys after the rotation")
		}
		time.Sleep(KeepPrevFor)
		client.e.lock()
		defer client.e.unlock()
		if client.prev != nil || prev.send != ([32]byte{}) || prev.recv != ([32]byte{}) {
			t.Error("the previous keys outlived KeepPrevFor")
		}
		if client.e.table.get(prev.local) != nil {
			t.Error("the previous keys' index was not freed")
		}
	})
}

func TestWhenBothSidesStartARekeyTheClientsWins(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 50*time.Millisecond)
		client, server, _ := s.connect(clientAddr.String())
		setAge(client, RekeyAfter+5*time.Second)
		setAge(server, serverRekeyAfter+5*time.Second)
		// Both send before either INIT can arrive.
		client.Send([]byte("c"))
		server.Send([]byte("s"))
		client.e.lock()
		clientIdx := client.rekey.Index()
		client.e.unlock()
		time.Sleep(5 * time.Second)
		drain(client)
		drain(server)
		exchange(t, client, server, "after the collision")
		croot, cepoch, cflight := roots(client)
		sroot, sepoch, sflight := roots(server)
		if croot != sroot || cepoch != 1 || sepoch != 1 || cflight || sflight {
			t.Fatalf("epochs %d/%d, roots agree %v, in flight %v/%v", cepoch, sepoch, croot == sroot, cflight, sflight)
		}
		client.e.lock()
		defer client.e.unlock()
		if client.cur.local != clientIdx {
			t.Error("the new epoch is not the client's rekey")
		}
	})
}

func TestARekeyRespondersFloorAnswersAtMostOnceASecond(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 10*time.Millisecond)
		client, server, _ := s.connect(clientAddr.String())
		var answers []time.Time
		s.net.setTap(func(p memPacket) []memPacket {
			if len(p.data) == respSize {
				answers = append(answers, time.Now())
			}
			return []memPacket{p}
		})
		// A hostile client that starts a fresh rekey the moment the last one
		// completes.
		start := time.Now()
		for time.Since(start) < 20*time.Second {
			setAge(client, RekeyAfter)
			client.Send([]byte("x"))
			time.Sleep(50 * time.Millisecond)
			drain(server)
		}
		answers = read(s.net, &answers)
		if len(answers) == 0 || len(answers) > 21 {
			t.Fatalf("%d answers in 20 s", len(answers))
		}
		for i := 1; i < len(answers); i++ {
			if gap := answers[i].Sub(answers[i-1]); gap < RekeyMinEpochAge {
				t.Errorf("two answers %v apart", gap)
			}
		}
	})
}

func TestAnINITUnderAYoungEpochIsIgnoredAndItsResendAnswered(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 10*time.Millisecond)
		client, server, _ := s.connect(clientAddr.String())
		setAge(server, 10*time.Second)
		setAge(client, RekeyAfter)
		exchange(t, client, server, "first rekey")
		time.Sleep(100 * time.Millisecond)
		_, epoch, _ := roots(server)
		if epoch != 1 {
			t.Fatalf("epoch %d", epoch)
		}
		var answered time.Time
		s.net.setTap(func(p memPacket) []memPacket {
			if len(p.data) == respSize && answered.IsZero() {
				answered = time.Now()
			}
			return []memPacket{p}
		})
		started := time.Now()
		setAge(client, RekeyAfter)
		client.Send([]byte("again at once"))
		time.Sleep(3 * time.Second)
		answered = read(s.net, &answered)
		if answered.IsZero() {
			t.Fatal("the resent INIT was never answered")
		}
		if wait := answered.Sub(started); wait < RekeyRetry {
			t.Errorf("an INIT under a %v-old epoch was answered after %v", 100*time.Millisecond, wait)
		}
		_, epoch, _ = roots(server)
		if epoch != 2 {
			t.Errorf("epoch %d after the resend", epoch)
		}
	})
}

func TestBlockingOnlyTheRekeyFramesStallsTheTerminalUntilTheyGetThrough(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 20*time.Millisecond)
		client, server, _ := s.connect(clientAddr.String())
		blocking := true
		s.net.setTap(func(p memPacket) []memPacket {
			if blocking && isRekeyFrame(p) {
				return nil
			}
			return []memPacket{p}
		})
		start := time.Now()
		var blockedAt time.Duration
		for time.Since(start) < RejectAfterTime+10*time.Second {
			time.Sleep(3 * time.Second)
			if err := client.Send([]byte("heartbeat")); err != nil {
				if !errors.Is(err, ErrBlocked) {
					t.Fatalf("Send: %v", err)
				}
				if blockedAt == 0 {
					blockedAt = time.Since(start)
				}
				continue
			}
			recv(t, server)
		}
		if blockedAt == 0 || blockedAt > RejectAfterTime+3*time.Second {
			t.Fatalf("Send was first held back at %v, not at RejectAfterTime", blockedAt)
		}
		var overdue int
		for _, ev := range events(client) {
			if _, ok := ev.(RekeyOverdue); ok {
				overdue++
			}
		}
		if overdue != 1 {
			t.Errorf("RekeyOverdue reported %d times", overdue)
		}
		// The keepalives and path frames are exempt, and received terminal
		// frames are still accepted: only what a side seals is limited.

		s.net.locked(func() { blocking = false })
		time.Sleep(3 * time.Second)
		exchange(t, client, server, "after the rekey got through")
		_, epoch, _ := roots(client)
		if epoch != 1 {
			t.Errorf("epoch %d once the rekey got through", epoch)
		}
	})
}

// TestRekeyInterleavingsProperty is S1's property test carried over to the
// production transport and extended to the split INIT (transport.md §6.6):
// random schedules of loss, duplication and reordering, each half of the
// INIT treated separately, crossing rekeys, and traffic both ways at
// random. Whatever happens, no genuine packet ever fails to authenticate,
// and once the network heals both roots match, nothing is in flight, and
// data flows both ways.
func TestRekeyInterleavingsProperty(t *testing.T) {
	schedules := 60
	if testing.Short() {
		schedules = 10
	}
	var rekeys uint64
	for seed := range uint64(schedules) {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				rekeys += runSchedule(t, seed)
			})
		})
	}
	t.Logf("%d schedules, %d rekeys", schedules, rekeys)
}

func runSchedule(t *testing.T, seed uint64) uint64 {
	rng := rand.New(rand.NewPCG(seed, 0x5eed))
	loss := rng.Float64() * 0.4
	dup := rng.Float64() * 0.2
	reorder := rng.Float64() * 0.3
	s := newSetup(t, 20*time.Millisecond)
	client, server, _ := s.connect(clientAddr.String())
	healed := false
	s.net.setTap(func(p memPacket) []memPacket {
		if healed {
			return []memPacket{p}
		}
		if rng.Float64() < loss {
			return nil
		}
		out := []memPacket{p}
		if rng.Float64() < reorder {
			out[0].delay += time.Duration(rng.IntN(400)) * time.Millisecond
		}
		if rng.Float64() < dup {
			d := p
			d.delay += time.Duration(rng.IntN(600)) * time.Millisecond
			out = append(out, d)
		}
		return out
	})
	start := time.Now()
	for time.Since(start) < 10*time.Minute {
		time.Sleep(time.Duration(200+rng.IntN(3000)) * time.Millisecond)
		switch rng.IntN(5) {
		case 0:
			ageBy(client, time.Duration(rng.IntN(int(RekeyAfter))))
		case 1:
			ageBy(server, time.Duration(rng.IntN(int(serverRekeyAfter))))
		}
		client.Send([]byte("c"))
		server.Send([]byte("s"))
		drain(client)
		drain(server)
	}

	s.net.locked(func() { healed = true })
	// Long enough for a rekey to finish at RekeyRetry, and for any keys
	// past RejectAfterTime to be replaced by one.
	for range 10 {
		client.Send([]byte("c"))
		server.Send([]byte("s"))
		time.Sleep(time.Second)
	}
	drain(client)
	drain(server)
	exchange(t, client, server, "healed")
	// That exchange may itself have started a rekey; with no more sends,
	// the timers alone must finish it.
	time.Sleep(5 * RekeyRetry)

	if d := client.Stats().Dropped[Auth]; d != 0 {
		t.Errorf("seed %d: the client failed to authenticate %d genuine packets", seed, d)
	}
	if d := server.Stats().Dropped[Auth]; d != 0 {
		t.Errorf("seed %d: the server failed to authenticate %d genuine packets", seed, d)
	}
	croot, cepoch, cflight := roots(client)
	sroot, sepoch, sflight := roots(server)
	if croot != sroot {
		t.Errorf("seed %d: the roots differ (epochs %d and %d)", seed, cepoch, sepoch)
	}
	if cflight || sflight {
		t.Errorf("seed %d: a rekey is still in flight", seed)
	}
	return cepoch
}
