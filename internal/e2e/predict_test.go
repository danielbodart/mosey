//go:build linux

package e2e

import (
	"context"
	"io"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/danielbodart/mosey/internal/netsim"
)

// slowPath is a clean path with a 400 ms round trip: long enough that
// every key would take visibly long to echo without prediction.
func slowPath() netsim.Profile {
	return netsim.Profile{
		Name: "400ms",
		Setup: func(n *netsim.Network, client, server *netsim.Host, _ *netsim.Conn) {
			l := netsim.LinkParams{Delay: 200 * time.Millisecond, MTU: netsim.ProfileMTU}
			n.Connect(client, server, l)
			n.Connect(server, client, l)
		},
	}
}

// mishearer is a shell-like program with two quirks prediction has to
// cope with: it echoes x as X, which no prediction can guess, and after
// the line "pw" it asks for a password with echo off (!ECHO && ICANON),
// echoing nothing until Enter.
type mishearer struct {
	out    chan []byte
	mu     sync.Mutex
	line   string
	secret bool
	closed bool
}

func newMishearer() *mishearer {
	m := &mishearer{out: make(chan []byte, 256)}
	m.out <- []byte("$ ")
	return m
}

func (m *mishearer) Read(p []byte) (int, error) {
	b, ok := <-m.out
	if !ok {
		return 0, io.EOF
	}
	return copy(p, b), nil
}

func (m *mishearer) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, io.ErrClosedPipe
	}
	for _, c := range p {
		switch {
		case c == '\r' && m.line == "pw" && !m.secret:
			m.secret = true
			m.out <- []byte("\r\nPassword: ")
		case c == '\r':
			m.secret = false
			m.out <- []byte("\r\n$ ")
		case m.secret:
			// No echo.
		case c == 'x':
			m.out <- []byte("X")
		default:
			m.out <- []byte{c}
		}
		if c == '\r' {
			m.line = ""
		} else {
			m.line += string(c)
		}
	}
	return len(p), nil
}

func (m *mishearer) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.closed = true
		close(m.out)
	}
	return nil
}

func (m *mishearer) Resize(cols, rows int) error { return nil }

func (m *mishearer) EchoOff() (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.secret, nil
}

// predicting is a session on the slow path with the mishearer for a
// shell, the client predicting as it does by default (adaptive).
type predicting struct {
	t      *testing.T
	user   *userTerminal
	prog   *mishearer
	client <-chan error
	stats  *statsLog
	end    sync.Once
}

// statsLog keeps the client's prediction stats, which it logs as it
// leaves: how a test sees what the engine did, not only what it drew.
type statsLog struct {
	mu    sync.Mutex
	stats string
}

func (l *statsLog) Enabled(context.Context, slog.Level) bool { return true }
func (l *statsLog) WithAttrs([]slog.Attr) slog.Handler       { return l }
func (l *statsLog) WithGroup(string) slog.Handler            { return l }
func (l *statsLog) Handle(_ context.Context, r slog.Record) error {
	if r.Message != "prediction" {
		return nil
	}
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "stats" {
			l.mu.Lock()
			l.stats = a.Value.String()
			l.mu.Unlock()
		}
		return true
	})
	return nil
}

func startPredicting(t *testing.T) *predicting {
	t.Helper()
	n := newSimNet(t, slowPath())
	ctx, cancel := context.WithCancel(context.Background())
	p := &predicting{t: t, user: &userTerminal{keys: make(chan []byte), resized: make(chan struct{})}, prog: newMishearer(), stats: &statsLog{}}
	n.log = slog.New(p.stats)
	server := n.serve(t, ctx, p.prog)
	p.client = n.connect(ctx, p.user)
	t.Cleanup(func() {
		cancel()
		p.leave()
		p.prog.Close()
		<-server
	})
	p.wait("prompt", func(s string) bool { return strings.HasPrefix(s, "$") })
	return p
}

// leave ends the user's input, so the client detaches and logs its
// stats.
func (p *predicting) leave() {
	p.end.Do(func() {
		close(p.user.keys)
		<-p.client
	})
}

// predicted is how many key events the client predicted anything for,
// once it has left.
func (p *predicting) predicted() int {
	p.t.Helper()
	p.leave()
	p.stats.mu.Lock()
	defer p.stats.mu.Unlock()
	m := regexp.MustCompile(`Predicted:(\d+)`).FindStringSubmatch(p.stats.stats)
	if m == nil {
		p.t.Fatalf("the client logged no prediction stats: %q", p.stats.stats)
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

func (p *predicting) screen() string { return screenOf(p.user.bytes(), 80, 24) }

// key types one key, a read of its own, and lets the client handle it
// without any virtual time passing.
func (p *predicting) key(k string) {
	p.t.Helper()
	select {
	case p.user.keys <- []byte(k):
	case <-time.After(time.Minute):
		p.t.Fatal("the client stopped reading its terminal")
	}
	synctest.Wait()
}

func (p *predicting) wait(what string, cond func(string) bool) time.Duration {
	p.t.Helper()
	start := time.Now()
	for !cond(p.screen()) {
		if time.Since(start) > time.Minute {
			p.t.Fatalf("no %s after a virtual minute; on the screen:\n%s", what, p.screen())
		}
		time.Sleep(5 * time.Millisecond)
	}
	return time.Since(start)
}

// settle types keys one at a time, waiting for each echo and the echo
// ack after it. The first founds the engine on the server's screen, the
// second is predicted in a tentative epoch its echo confirms, so the next
// keys are drawn at once (prediction.md §4, §8).
func (p *predicting) settle(keys string) {
	p.t.Helper()
	line := "$ "
	for _, k := range keys {
		p.key(string(k))
		line += string(k)
		p.wait(line, func(s string) bool { return strings.HasPrefix(s, line) })
		time.Sleep(time.Second)
	}
}

func TestKeystrokesAppearAtOnceOnASlowPath(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	synctest.Test(t, func(t *testing.T) {
		p := startPredicting(t)
		p.settle("ec")
		// Each key is on the screen before any time has passed at all,
		// against 400 ms for the server's echo.
		for _, k := range []string{"h", "o"} {
			before := p.screen()
			p.key(k)
			if got := p.screen(); !strings.HasPrefix(got, strings.SplitN(before, "\n", 2)[0]+k) {
				t.Fatalf("after %q the screen shows %q", k, strings.SplitN(got, "\n", 2)[0])
			}
		}
		// And the server's echo agrees, so nothing is taken back.
		p.wait("echo", func(s string) bool { return strings.HasPrefix(s, "$ echo") })
		time.Sleep(2 * time.Second)
		if got := strings.SplitN(p.screen(), "\n", 2)[0]; got != "$ echo" {
			t.Fatalf("the line settled as %q", got)
		}
	})
}

func TestAWrongPredictionIsRepairedWithinARoundTrip(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	synctest.Test(t, func(t *testing.T) {
		p := startPredicting(t)
		p.settle("ec")
		p.key("x")
		if got := strings.SplitN(p.screen(), "\n", 2)[0]; got != "$ ecx" {
			t.Fatalf("the guess was not drawn at once: %q", got)
		}
		// The program echoes X: the guess is taken back once the frame
		// with the echo ack arrives, a round trip plus the 50 ms wait and
		// the server's pacing.
		took := p.wait("repair", func(s string) bool { return strings.HasPrefix(s, "$ ecX") })
		t.Logf("the wrong guess stayed up %v on a 400 ms round trip", took)
		if took > time.Second {
			t.Errorf("the wrong guess stayed up %v", took)
		}
	})
}

func TestNothingIsPredictedAtAPasswordPrompt(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	synctest.Test(t, func(t *testing.T) {
		p := startPredicting(t)
		p.settle("pw")
		p.key("\r")
		p.wait("password prompt", func(s string) bool { return strings.Contains(s, "Password:") })
		time.Sleep(time.Second)
		for _, k := range []string{"s", "e", "c", "r", "e", "t"} {
			p.key(k)
			if strings.Contains(p.screen(), "Password: "+k) {
				t.Fatalf("a password key was drawn:\n%s", p.screen())
			}
			time.Sleep(120 * time.Millisecond)
			if strings.ContainsAny(strings.SplitN(strings.SplitN(p.screen(), "Password:", 2)[1], "\n", 2)[0], "secrt") {
				t.Fatalf("a password key was drawn:\n%s", p.screen())
			}
		}
		// Not drawn is the epoch rules' doing as much as the echo-off
		// bit's: no secret key echoes, so none could confirm. The bit's
		// own promise is that none was even guessed (prediction.md
		// §13.1): only "p" and "w" could have been.
		if n := p.predicted(); n > 2 {
			t.Fatalf("the client predicted %d key events, so it guessed at the password", n)
		}
	})
}
