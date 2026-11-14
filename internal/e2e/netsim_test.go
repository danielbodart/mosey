//go:build linux

package e2e

import (
	"bytes"
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/danielbodart/mosey/internal/client"
	"github.com/danielbodart/mosey/internal/emu"
	"github.com/danielbodart/mosey/internal/handshake"
	"github.com/danielbodart/mosey/internal/netsim"
	"github.com/danielbodart/mosey/internal/server"
	"github.com/danielbodart/mosey/internal/transport"
)

// shell is a shell-like program on the server's side of a fake pty: it
// echoes what it is typed, and answers "echo WORDS" with WORDS in capitals
// (so the answer is told apart from the echo), so a session can be
// driven and checked without a real pty or shell.
type shell struct {
	out    chan []byte
	mu     sync.Mutex
	line   []byte
	resize [2]int
}

func newShell() *shell {
	s := &shell{out: make(chan []byte, 64)}
	s.out <- []byte("$ ")
	return s
}

func (s *shell) Read(p []byte) (int, error) {
	b, ok := <-s.out
	if !ok {
		return 0, context.Canceled
	}
	return copy(p, b), nil
}

// Write is the program reading its input: it echoes, and on Enter runs
// "echo WORDS" as a shell would.
func (s *shell) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range p {
		if c != '\r' {
			s.line = append(s.line, c)
			s.out <- []byte{c}
			continue
		}
		reply := "\r\n"
		if words, ok := bytes.CutPrefix(s.line, []byte("echo ")); ok {
			reply += strings.ToUpper(string(words)) + "\r\n"
		}
		s.out <- []byte(reply + "$ ")
		s.line = s.line[:0]
	}
	return len(p), nil
}

func (s *shell) Resize(cols, rows int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resize = [2]int{cols, rows}
	return nil
}

func (s *shell) EchoOff() (bool, error) { return false, nil }

// userTerminal is the client's terminal: keys the test types, and what
// the renderer draws.
type userTerminal struct {
	keys    chan []byte
	resized chan struct{}
	mu      sync.Mutex
	drawn   bytes.Buffer
}

func (u *userTerminal) Read(p []byte) (int, error) {
	k, ok := <-u.keys
	if !ok {
		return 0, context.Canceled
	}
	return copy(p, k), nil
}

func (u *userTerminal) Write(p []byte) (int, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.drawn.Write(p)
}

func (u *userTerminal) String() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.drawn.String()
}

func (u *userTerminal) Size() (int, int, error)  { return 80, 24, nil }
func (u *userTerminal) Resized() <-chan struct{} { return u.resized }
func (u *userTerminal) Raw() error               { return nil }
func (u *userTerminal) Restore() error           { return nil }

var (
	clientAddr = netip.MustParseAddrPort("10.0.0.1:50000")
	serverAddr = netip.MustParseAddrPort("10.0.0.2:60001")
)

// A client.Session and a server.Session in one process, over every
// netsim profile, in virtual time (D18): what the user types reaches the
// program, and what the program prints reaches the user's screen.
func TestAShellSessionOverEveryNetworkProfile(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	for _, p := range netsim.Profiles() {
		t.Run(p.Name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { runShellSession(t, p) })
		})
	}
}

func runShellSession(t *testing.T, p netsim.Profile) {
	log := slog.New(slog.DiscardHandler)
	n := netsim.New(1)
	defer n.Close()
	ch, sh := n.NewHost("client"), n.NewHost("server")
	cc, err := ch.Listen(clientAddr)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := sh.Listen(serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	p.Setup(n, ch, sh, cc)

	// The bootstrap, as proto and the client do it, minus SSH.
	key, err := handshake.NewOneShotKey()
	if err != nil {
		t.Fatal(err)
	}
	creds := handshake.NewCredentials(log)
	cred, err := creds.Mint([16]byte{1}, key.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	em, err := emu.New(80, 24, emu.Options{ScrollbackCells: emu.DefaultScrollbackCells})
	if err != nil {
		t.Fatal(err)
	}
	prog := newShell()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	srv := &server.Session{Listener: transport.Listen(sc, creds, log), Terminal: prog, Emulator: em, Log: log}
	go srv.Run(ctx)

	user := &userTerminal{keys: make(chan []byte), resized: make(chan struct{})}
	cli := &client.Session{Conn: cc, Server: serverAddr, Credential: cred, Key: key, Terminal: user, Log: log, UTF8: true}
	done := make(chan error, 1)
	go func() { done <- cli.Run(ctx) }()

	// Virtual time: a profile's outages pass in no real time at all.
	wait := func(what string, cond func() bool) {
		for deadline := time.Now().Add(10 * time.Minute); !cond(); {
			if time.Now().After(deadline) {
				t.Fatalf("%s: no %s after 10 virtual minutes; drawn %q", p.Name, what, user.String())
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	wait("prompt", func() bool { return strings.Contains(user.String(), "$") })
	user.keys <- []byte("echo over-the-network\r")
	wait("the answer", func() bool { return strings.Contains(user.String(), "OVER-THE-NETWORK") })
	cancel()
	close(user.keys)
	close(prog.out)
	if err := <-done; err != nil {
		t.Errorf("client: %v", err)
	}
}
