package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/danielbodart/mosey/internal/ipc"
)

// The adopter's checks of what an older session sends (server.md §2.8,
// "What spawner-N checks"), against a forged session at the other end of
// an attach connection: each lie is refused before anything starts, and
// every fd the adopter received is closed again.

// forgery is one HandoffState, its agent listener and its screen, as a
// session (honest or not) would send them.
type forgery struct {
	st     ipc.HandoffState
	agent  *os.File
	screen []byte
}

// adoptFixture is an adopter for session sid under a runtime directory of
// its own, and an honest forgery for it: a real pty master, a pidfd for a
// live process named by its pid, the session's attach listener and a
// 20x3 screen. Every fd is the test's, closed at its end.
type adoptFixture struct {
	t       *testing.T
	sid     [16]byte
	runtime string
	s       *spawner
	shell   *child
}

func newAdoptFixture(t *testing.T, sid [16]byte) *adoptFixture {
	t.Helper()
	runtime := runtimeDir(t)
	f := &adoptFixture{t: t, sid: sid, runtime: runtime,
		s: newSpawner(SpawnerConfig{Version: "0.2.1", Environ: []string{"XDG_RUNTIME_DIR=" + runtime}})}
	f.shell = f.idle()
	return f
}

// idle is a live process that ends with the test.
func (f *adoptFixture) idle() *child {
	r, w, err := os.Pipe()
	if err != nil {
		f.t.Fatal(err)
	}
	c := startIdle(f.t, "shell", r)
	r.Close()
	f.t.Cleanup(func() { w.Close(); c.cmd.Process.Kill() })
	return c
}

func (f *adoptFixture) keep(file *os.File) *os.File {
	f.t.Cleanup(func() { file.Close() })
	return file
}

func (f *adoptFixture) pidfd(c *child) *os.File {
	fd, err := unix.PidfdOpen(c.pid(), 0)
	if err != nil {
		f.t.Skipf("pidfd_open: %v", err)
	}
	return f.keep(os.NewFile(uintptr(fd), "pidfd"))
}

func (f *adoptFixture) master() *os.File {
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		f.t.Skipf("no pty: %v", err)
	}
	return f.keep(m)
}

// listener is an attach listener for sid under this fixture's runtime.
func (f *adoptFixture) listener(sid [16]byte) *os.File {
	l, err := listenAttach(filepath.Join(f.runtime, "mosey"), sid)
	if err != nil {
		f.t.Fatal(err)
	}
	return f.keep(l.f)
}

func (f *adoptFixture) agentListener(dir string) *os.File {
	l, err := listenAgent(dir)
	if err != nil {
		f.t.Fatal(err)
	}
	return f.keep(l.f)
}

func (f *adoptFixture) honest() forgery {
	screen := snapshotOf("adopt me")
	return forgery{
		st: ipc.HandoffState{
			Version: 1, SessionID: f.sid, Started: 1794650000, State: 3, Since: 1794651234,
			Cols: 20, Rows: 3, ShellPID: uint32(f.shell.pid()), ScreenLen: uint32(len(screen)), Name: stubName,
			PTY: f.master(), Pidfd: f.pidfd(f.shell), Listener: f.listener(f.sid),
		},
		screen: screen,
	}
}

// openFDs is how many fds this process has open.
func openFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

// adopt sends g down an attach connection and runs the adopter's
// requestHandoff on the other end. It returns the adoption or the
// refusal, and how many more fds the process has open afterwards.
func (f *adoptFixture) adopt(g forgery) (*adoption, error, int) {
	f.t.Helper()
	ours, theirs, err := ipc.Pair()
	if err != nil {
		f.t.Fatal(err)
	}
	attach, _ := ipc.NewConn(ours, ipc.Launcher, ipc.Spawner)
	defer attach.Close()
	session, _ := ipc.NewConn(theirs, ipc.Spawner, ipc.Launcher)
	defer session.Close()
	// Everything goes before the adopter asks; fds in flight are in no
	// process's table, so the count before is this process's own.
	if err := session.Send(g.st); err != nil {
		f.t.Fatal(err)
	}
	if g.st.Agent {
		if err := session.Send(ipc.HandoffAgent{Listener: g.agent}); err != nil {
			f.t.Fatal(err)
		}
	}
	if err := session.Send(ipc.HandoffScreen{Fragment: g.screen}); err != nil {
		f.t.Fatal(err)
	}
	before := openFDs(f.t)
	a, err := f.s.requestHandoff(attach, f.sid)
	return a, err, openFDs(f.t) - before
}

// An honest session's state is adopted, with every fd it sent, and with
// its agent listener when it has one.
func TestAnAdopterTakesAnHonestSessionsState(t *testing.T) {
	for _, agent := range []bool{false, true} {
		f := newAdoptFixture(t, [16]byte{0x5a, 1})
		g := f.honest()
		if agent {
			g.st.Agent = true
			g.agent = f.agentListener(sessionDir(filepath.Join(f.runtime, "mosey"), f.sid))
		}
		a, err, more := f.adopt(g)
		if err != nil {
			t.Fatalf("agent %v: an honest session refused: %v", agent, err)
		}
		if want := 3 + map[bool]int{false: 0, true: 1}[agent]; more != want {
			t.Errorf("agent %v: %d fds held, not %d", agent, more, want)
		}
		if (a.agent != nil) != agent || string(a.snapshot) != string(g.screen) || a.state.Name != stubName {
			t.Errorf("agent %v: adopted %+v", agent, a)
		}
		a.close()
	}
}

// Each lie a session can tell is refused before anything starts, saying
// what was wrong, and leaves no fd of it open in the adopter.
func TestAnAdopterRefusesAForgedStateAndClosesEveryFDItWasSent(t *testing.T) {
	for _, c := range []struct {
		name  string
		forge func(*adoptFixture, *forgery)
		want  string
	}{
		{"another session's id", func(f *adoptFixture, g *forgery) { g.st.SessionID = [16]byte{0x5a, 0xee} }, "another session"},
		{"a pipe for the pty master", func(f *adoptFixture, g *forgery) {
			r, w, err := os.Pipe()
			if err != nil {
				f.t.Fatal(err)
			}
			f.keep(r)
			g.st.PTY = f.keep(w)
		}, "pty master"},
		{"a pidfd for another process", func(f *adoptFixture, g *forgery) { g.st.Pidfd = f.pidfd(f.idle()) }, "names pid"},
		{"a pty master for the pidfd", func(f *adoptFixture, g *forgery) { g.st.Pidfd = f.master() }, "pidfd"},
		{"a listener of another session", func(f *adoptFixture, g *forgery) { g.st.Listener = f.listener([16]byte{0x5a, 0xef}) }, "attach socket"},
		{"a pty master for the listener", func(f *adoptFixture, g *forgery) { g.st.Listener = f.master() }, "attach socket"},
		{"a screen of another size", func(f *adoptFixture, g *forgery) { g.st.Cols = 30 }, "20x3 screen for a 30x3"},
		{"a screen longer than said", func(f *adoptFixture, g *forgery) { g.st.ScreenLen-- }, "longer"},
		{"a screen shorter than said", func(f *adoptFixture, g *forgery) { g.st.ScreenLen++ }, "shorter"},
		{"an attach listener for the agent's", func(f *adoptFixture, g *forgery) {
			g.st.Agent, g.agent = true, f.listener([16]byte{0x5a, 0xf0})
		}, "agent socket"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newAdoptFixture(t, [16]byte{0x5a, 2})
			g := f.honest()
			c.forge(f, &g)
			a, err, more := f.adopt(g)
			if err == nil {
				a.close()
				t.Fatal("adopted")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("refused with %q, which does not say %q", err, c.want)
			}
			if more != 0 {
				t.Errorf("%d fds of the forged session left open", more)
			}
		})
	}
}
