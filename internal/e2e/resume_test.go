//go:build linux

package e2e

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/danielbodart/mosey/internal/client"
	"github.com/danielbodart/mosey/internal/netsim"
	"github.com/danielbodart/mosey/internal/server"
)

// Resume (D8) and exclusive attach (D26), end to end in one process: a
// server Session, and clients on devices of their own, each with a
// credential minted for the same session as a resume mints it. Network
// behaviour on netsim, in virtual time (D18).

var (
	phoneAddr  = netip.MustParseAddrPort("10.0.0.3:50000")
	laptopAddr = netip.MustParseAddrPort("10.0.0.4:50000")
)

// party is one client of the session: its user's terminal, its end, and
// how its user leaves.
type party struct {
	t     *testing.T
	name  string
	user  *userTerminal
	done  <-chan error
	leave context.CancelFunc
}

func newUser() *userTerminal {
	return &userTerminal{keys: make(chan []byte), resized: make(chan struct{})}
}

// sees waits, in virtual time, until the party's screen shows want.
func (p *party) sees(want string) {
	p.t.Helper()
	for deadline := time.Now().Add(10 * time.Minute); !strings.Contains(screenOf(p.user.bytes(), 80, 24), want); {
		if time.Now().After(deadline) {
			p.t.Fatalf("%s: no %q after 10 virtual minutes; on the screen:\n%s", p.name, want, screenOf(p.user.bytes(), 80, 24))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (p *party) typeLine(line string) {
	p.t.Helper()
	select {
	case p.user.keys <- []byte(line + "\r"):
	case <-time.After(10 * time.Minute):
		p.t.Fatalf("%s: the client stopped reading its terminal", p.name)
	}
}

// ends waits for the party's client to end and returns how.
func (p *party) ends() error {
	p.t.Helper()
	select {
	case err := <-p.done:
		return err
	case <-time.After(10 * time.Minute):
		p.t.Fatalf("%s: the client did not end", p.name)
		return nil
	}
}

// resumeWorld is a session served on netsim, with its first client on a
// LAN whose two links a test can cut, as a dead spot or a reboot does.
type resumeWorld struct {
	t        *testing.T
	n        *simNet
	prog     *shell
	served   <-chan error
	up, down *netsim.Link
	stop     context.CancelFunc
	// events is what the server's Attached and Detached said, for a
	// test that records them.
	mu     sync.Mutex
	events []string
}

func (w *resumeWorld) record(what string, cred [8]byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if cred != ([8]byte{}) {
		what += " " + string(cred[:])
	}
	w.events = append(w.events, what)
}

func (w *resumeWorld) recorded() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.events...)
}

func newResumeWorld(t *testing.T) *resumeWorld {
	return newResumeWorldWith(t, &resumeWorld{t: t}, nil)
}

// newResumeWorldWith is newResumeWorld into w, with a hook on the
// server's Session.
func newResumeWorldWith(t *testing.T, w *resumeWorld, hook func(*server.Session)) *resumeWorld {
	cuttable := netsim.Profile{Name: "lan", Setup: func(n *netsim.Network, c, s *netsim.Host, _ *netsim.Conn) {
		l := netsim.LinkParams{Delay: 250 * time.Microsecond, MTU: netsim.ProfileMTU}
		w.up, w.down = n.Connect(c, s, l), n.Connect(s, c, l)
	}}
	w.n = newSimNet(t, cuttable)
	w.prog = newShell()
	ctx, cancel := context.WithCancel(context.Background())
	w.stop = cancel
	w.served = w.n.serveWith(t, ctx, w.prog, hook)
	t.Cleanup(func() {
		cancel()
		w.prog.Close()
	})
	return w
}

// first is the client that started the session.
func (w *resumeWorld) first() *party {
	ctx, cancel := context.WithCancel(context.Background())
	p := &party{t: w.t, name: "first", user: newUser(), leave: cancel}
	p.done = w.n.connect(ctx, p.user)
	w.t.Cleanup(func() { cancel(); close(p.user.keys) })
	return p
}

// another is a client on a device of its own resuming the session.
func (w *resumeWorld) another(name string, addr netip.AddrPort) *party {
	ctx, cancel := context.WithCancel(context.Background())
	p := &party{t: w.t, name: name, user: newUser(), leave: cancel}
	p.done = w.n.resume(ctx, w.n.device(w.t, name, addr), p.user)
	w.t.Cleanup(func() { cancel(); close(p.user.keys) })
	return p
}

// cut makes the first client's network lose everything, both ways.
func (w *resumeWorld) cut(lost bool) {
	l := netsim.LinkParams{Delay: 250 * time.Microsecond, MTU: netsim.ProfileMTU}
	if lost {
		l.Loss = 1
	}
	w.up.SetParams(l)
	w.down.SetParams(l)
}

// stillServing says the session has not ended.
func (w *resumeWorld) stillServing() {
	w.t.Helper()
	select {
	case err := <-w.served:
		w.t.Fatalf("the session ended (%v) when it should have waited for a resume", err)
	default:
	}
}

// exitShell ends the session the way it always ends: the shell exits.
func (w *resumeWorld) exitShell(p *party) {
	w.t.Helper()
	p.typeLine("exit")
	if err := p.ends(); err != nil {
		w.t.Errorf("%s ended with %v after the shell exited", p.name, err)
	}
	if err := <-w.served; err != nil {
		w.t.Errorf("the session ended with %v", err)
	}
}

// A client that leaves (its user closed the terminal, or it was killed)
// detaches: it tells the server, exits with *DetachedError naming the
// session, and the session runs on. A client on another device then
// resumes it and sees the screen as the shell left it, and its keys reach
// the same shell (bootstrap.md §9.3, D8).
func TestALeavingClientDetachesAndAnotherResumesTheSession(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	synctest.Test(t, func(t *testing.T) {
		w := newResumeWorld(t)
		a := w.first()
		a.sees("$")
		a.typeLine("echo before")
		a.sees("BEFORE")
		a.leave()
		var d *client.DetachedError
		if err := a.ends(); !errors.As(err, &d) {
			t.Fatalf("the first client ended with %v, not a detach from the session", err)
		}
		// Long after the credential TTL and the spawner's backstop: a
		// session that has had a client never ends for want of one.
		time.Sleep(10 * time.Minute)
		w.stillServing()

		b := w.another("phone", phoneAddr)
		b.sees("BEFORE")
		b.typeLine("echo after")
		b.sees("AFTER")
		w.exitShell(b)
	})
}

// A new attach takes the session over (D26): the client that had it is
// told who took it and when, and exits with *TakenOverError rather than
// reconnect, while the new one carries on with the same shell.
func TestANewDeviceTakesTheSessionOverAndTheOldClientIsTold(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	synctest.Test(t, func(t *testing.T) {
		w := newResumeWorld(t)
		a := w.first()
		a.sees("$")
		a.typeLine("echo mine")
		a.sees("MINE")

		attachedAt := time.Now()
		b := w.another("laptop", laptopAddr)
		var taken *client.TakenOverError
		if err := a.ends(); !errors.As(err, &taken) {
			t.Fatalf("the first client ended with %v, not taken over", err)
		}
		if taken.By != laptopAddr {
			t.Errorf("taken over by %s, not the laptop at %s", taken.By, laptopAddr)
		}
		if taken.At.Before(attachedAt.Add(-time.Second)) || taken.At.After(time.Now()) {
			t.Errorf("taken over at %v, not when the laptop attached (%v)", taken.At, attachedAt)
		}
		if client.ExitStatus(taken) != client.StatusTakenOver {
			t.Errorf("exit status %d", client.ExitStatus(taken))
		}
		b.sees("MINE")
		b.typeLine("echo yours")
		b.sees("YOURS")
		w.exitShell(b)
	})
}

// A client whose network dies says nothing: the server still counts it
// attached. The user resumes from a new socket (a reboot, another device);
// that takes over, and when the old client's network comes back the
// tombstone of its revoked connection tells it it was taken over
// (transport.md §8.3), so it exits rather than hang on.
func TestAResumeAfterTheNetworkDiedTakesOverAndTheOldClientLearnsOfItLater(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	synctest.Test(t, func(t *testing.T) {
		w := newResumeWorld(t)
		a := w.first()
		a.sees("$")
		a.typeLine("echo kept")
		a.sees("KEPT")

		w.cut(true)
		time.Sleep(time.Minute)
		w.stillServing()
		b := w.another("rebooted", phoneAddr)
		b.sees("KEPT")
		b.typeLine("echo again")
		b.sees("AGAIN")

		// The old client has been probing through the outage; once its
		// network is back, a probe reaches the revoked index and draws a
		// sealed REVOKED copy, within the tombstone's life.
		w.cut(false)
		var taken *client.TakenOverError
		if err := a.ends(); !errors.As(err, &taken) || taken.By != phoneAddr {
			t.Fatalf("the old client ended with %v, not taken over by %s", err, phoneAddr)
		}
		w.exitShell(b)
	})
}

// With nobody attached the shell can still exit (a job finishing, a kill),
// and that ends the session: there is nobody to tell, and nothing to
// resume.
func TestTheShellExitingWhileDetachedEndsTheSession(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	synctest.Test(t, func(t *testing.T) {
		w := newResumeWorld(t)
		a := w.first()
		a.sees("$")
		a.leave()
		a.ends()
		w.prog.Close()
		select {
		case err := <-w.served:
			if err != nil {
				t.Errorf("the session ended with %v", err)
			}
		case <-time.After(time.Minute):
			t.Fatal("the session outlived its shell")
		}
	})
}
