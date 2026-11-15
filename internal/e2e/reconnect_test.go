//go:build linux

package e2e

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/danielbodart/mosey/internal/client"
	"github.com/danielbodart/mosey/internal/server"
)

// R3 (D8, bootstrap.md §9.2.2) end to end on netsim, in virtual time: a
// running client whose UDP path dies for good resumes its own session by
// itself, with no user action, and the server's side of the silence
// (SilentAfter) is what lets R1 give a session back after a crash. The
// SSH half of a try is played by minting a credential for the same
// session, as proto does for a resume; the launcher's rules for it are
// internal/server's tests.

var movedAddr = netip.MustParseAddrPort("10.0.0.5:50000")

// reconnecting is the first client of a resume world, with R3 set to
// answer from answer.
func (w *resumeWorld) reconnecting(name string, answer func(ctx context.Context, holder [8]byte) (*client.Reattach, error)) *party {
	ctx, cancel := context.WithCancel(context.Background())
	p := &party{t: w.t, name: "first", user: newUser(), leave: cancel}
	p.done = w.n.connectWith(ctx, p.user, func(c *client.Session) {
		c.Name = name
		c.Reconnect = answer
	})
	w.t.Cleanup(func() { cancel(); close(p.user.keys) })
	return p
}

// A client whose path dies for good, as when a NAT drops the flow while
// SSH still works, hears nothing, and after ReconnectAfter resumes its
// own session in the background, from a new socket: the first try fails
// (ssh cannot get through yet) and is tried again after the backoff. The
// new transport is swapped in with the screen as it was and keys reaching
// the same shell, and the session never ended (D8 R3).
func TestAClientWhosePathDiesReconnectsByItselfAndKeepsItsScreen(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	synctest.Test(t, func(t *testing.T) {
		w := newResumeWorld(t)
		var mu sync.Mutex
		var tries []time.Time
		var holders [][8]byte
		a := w.reconnecting("work", func(ctx context.Context, holder [8]byte) (*client.Reattach, error) {
			mu.Lock()
			defer mu.Unlock()
			tries, holders = append(tries, time.Now()), append(holders, holder)
			if len(tries) == 1 {
				return nil, errors.New("ssh to far failed")
			}
			d := w.n.device(w.t, "moved", movedAddr)
			return &client.Reattach{Conn: d.conn, Server: serverAddr, Credential: d.cred, Key: d.key}, nil
		})
		a.sees("$")
		a.typeLine("echo before")
		a.sees("BEFORE")

		cut := time.Now()
		w.cut(true)
		// Keys typed into the silence are dropped at the swap (§9.2.2),
		// so the user types once the screen is back.
		for deadline := time.Now().Add(10 * time.Minute); ; time.Sleep(time.Second) {
			mu.Lock()
			n := len(tries)
			mu.Unlock()
			if n >= 2 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%d tries in 10 virtual minutes", n)
			}
		}
		time.Sleep(5 * time.Second)
		a.typeLine("echo after")
		a.sees("AFTER")
		w.stillServing()
		mu.Lock()
		defer mu.Unlock()
		if len(tries) != 2 {
			t.Fatalf("%d tries", len(tries))
		}
		if first := tries[0].Sub(cut); first < client.ReconnectAfter-time.Second || first > client.ReconnectAfter+5*time.Second {
			t.Errorf("the first try came %v after the cut, not about ReconnectAfter (from the last packet heard)", first)
		}
		if gap := tries[1].Sub(tries[0]); gap < 2*time.Second || gap > 3*time.Second {
			t.Errorf("the second try came %v after the first", gap)
		}
		if holders[0] != w.n.cred.ID {
			t.Errorf("the try named credential %x, not its own %x", holders[0], w.n.cred.ID)
		}
		a.sees("BEFORE") // the screen as it was, over the new transport
		mu.Unlock()
		w.exitShell(a)
		mu.Lock()
	})
}

// A try that finds the session gone (its shell exited while the client
// was cut off) ends the client with a message naming it; one that finds
// another client holding it ends the client as taken over (§9.2.2).
func TestAReconnectThatFindsTheSessionGoneOrTakenEndsTheClient(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	at := time.Unix(1794650000, 0)
	for name, answer := range map[string]error{"gone": client.ErrSessionGone, "taken": &client.TakenOverError{At: at}} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newResumeWorld(t)
				a := w.reconnecting("work", func(context.Context, [8]byte) (*client.Reattach, error) { return nil, answer })
				a.sees("$")
				w.cut(true)
				err := a.ends()
				var gone *client.GoneError
				var taken *client.TakenOverError
				switch {
				case name == "gone" && errors.As(err, &gone) && gone.Name == "work" && client.ExitStatus(err) == client.StatusFailed:
				case name == "taken" && errors.As(err, &taken) && taken.Name == "work" && taken.At.Equal(at) &&
					client.ExitStatus(err) == client.StatusTakenOver:
				default:
					t.Errorf("ended with %v", err)
				}
			})
		})
	}
}

// The server counts a client it has not heard from for SilentAfter as
// detached, keeping its connection; when the client is heard again it is
// attached again, with the same credential, and carries on (D8 R1).
func TestASilentClientCountsAsDetachedUntilItIsHeardAgain(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	synctest.Test(t, func(t *testing.T) {
		w := &resumeWorld{t: t}
		newResumeWorldWith(t, w, func(s *server.Session) {
			s.Attached = func(_ netip.AddrPort, cred [8]byte) { w.record("attached", cred) }
			s.Detached = func() { w.record("detached", [8]byte{}) }
		})
		a := w.first()
		a.sees("$")
		w.cut(true)
		time.Sleep(server.SilentAfter + 2*time.Second)
		w.cut(false)
		a.typeLine("echo back")
		a.sees("BACK")
		time.Sleep(2 * time.Second) // proto looks for a silent client's return each second
		got := w.recorded()
		cred := w.n.cred.ID
		want := []string{"attached " + string(cred[:]), "detached", "attached " + string(cred[:])}
		if len(got) != len(want) {
			t.Fatalf("the server said %q", got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("event %d: %q, want %q", i, got[i], want[i])
			}
		}
		w.exitShell(a)
	})
}
