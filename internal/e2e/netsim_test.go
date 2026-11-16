//go:build linux

package e2e

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
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
	"github.com/danielbodart/mosey/internal/render"
	"github.com/danielbodart/mosey/internal/screen"
	"github.com/danielbodart/mosey/internal/server"
	"github.com/danielbodart/mosey/internal/terminal"
	"github.com/danielbodart/mosey/internal/transport"
)

// shell is a shell-like program on the server's side of a fake pty: it
// echoes what it is typed, answers "echo WORDS" with WORDS in capitals (so
// the answer is told apart from the echo), and ends on "exit", so a session
// can be driven and checked without a real pty or shell. It keeps all it
// has printed, so a test can work out the screen the server should have.
type shell struct {
	out     chan []byte
	mu      sync.Mutex
	line    []byte
	printed bytes.Buffer
	exited  bool
	resize  [2]int
	// rest is output a read had no room for; only the reader touches it.
	rest []byte
}

func newShell() *shell {
	s := &shell{out: make(chan []byte, 64)}
	s.print("$ ")
	return s
}

// print queues output; the caller holds mu, or is newShell.
func (s *shell) print(b string) {
	s.printed.WriteString(b)
	s.out <- []byte(b)
}

func (s *shell) Read(p []byte) (int, error) {
	b := s.rest
	if len(b) == 0 {
		var ok bool
		if b, ok = <-s.out; !ok {
			return 0, io.EOF // the slave closed: what a pty says once the shell is gone
		}
	}
	// What does not fit is the next read's, as a pty keeps it.
	n := copy(p, b)
	s.rest = b[n:]
	return n, nil
}

// Write is the program reading its input: it echoes, and on Enter runs
// "echo WORDS" or "exit" as a shell would.
func (s *shell) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.exited {
		return 0, io.ErrClosedPipe
	}
	for _, c := range p {
		if c != '\r' {
			s.line = append(s.line, c)
			s.print(string(c))
			continue
		}
		if string(s.line) == "exit" {
			s.print("\r\n")
			s.exited = true
			close(s.out)
			return len(p), nil
		}
		reply := "\r\n"
		if words, ok := bytes.CutPrefix(s.line, []byte("echo ")); ok {
			reply += strings.ToUpper(string(words)) + "\r\n"
		}
		if n, ok := bytes.CutPrefix(s.line, []byte("seq ")); ok {
			reply += numbered(1, atoi(string(n)))
		}
		s.print(reply + "$ ")
		s.line = s.line[:0]
	}
	return len(p), nil
}

// numbered is the lines line-FROM to line-TO, as seq would print them
// with a prefix, each ended by CR LF.
func numbered(from, to int) string {
	var b strings.Builder
	for i := from; i <= to; i++ {
		fmt.Fprintf(&b, "line-%04d\r\n", i)
	}
	return b.String()
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

// flood prints text as if a program the shell runs had, unasked.
func (s *shell) flood(text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.print(text)
}

// Close is the server closing the pty's master: the shell is hung up.
func (s *shell) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.exited {
		s.exited = true
		close(s.out)
	}
	return nil
}

// output is everything the shell has printed so far.
func (s *shell) output() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.printed.Bytes())
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

func (u *userTerminal) bytes() []byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	return bytes.Clone(u.drawn.Bytes())
}

func (u *userTerminal) Size() (int, int, error)  { return 80, 24, nil }
func (u *userTerminal) Resized() <-chan struct{} { return u.resized }
func (u *userTerminal) Raw() error               { return nil }
func (u *userTerminal) Restore() error           { return nil }

var (
	clientAddr = netip.MustParseAddrPort("10.0.0.1:50000")
	serverAddr = netip.MustParseAddrPort("10.0.0.2:60001")
)

// simSession is a client.Session and a server.Session in one process, over
// a netsim network shaped by a profile, inside a synctest bubble: the
// bootstrap as proto and the client do it, minus SSH.
type simSession struct {
	t       *testing.T
	profile string
	user    *userTerminal
	// prog is the shell when it is a *shell; term is the shell whatever
	// it is.
	prog   *shell
	term   program
	cc     *netsim.Conn
	client <-chan error
	server <-chan error
	quit   context.CancelFunc // the client's: the user quitting
	cancel context.CancelFunc // the server's
	stop   sync.Once
}

// simNet is a client's and a server's socket on a netsim network shaped
// by a profile, and a credential for the client, minted as proto mints it:
// the bootstrap, minus SSH.
type simNet struct {
	net    *netsim.Network
	sh     *netsim.Host
	cc, sc *netsim.Conn
	creds  *handshake.Credentials
	cred   handshake.Credential
	key    *handshake.OneShotKey
	log    *slog.Logger
	// links are the first client's, up then down, for a test to cut.
	links []*netsim.Link
}

// sessionID is the one session every sim test serves.
var sessionID = [16]byte{1}

func newSimNet(t *testing.T, p netsim.Profile) *simNet {
	t.Helper()
	log := slog.New(slog.DiscardHandler)
	n := netsim.New(1)
	t.Cleanup(func() { n.Close() })
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

	key, err := handshake.NewOneShotKey()
	if err != nil {
		t.Fatal(err)
	}
	creds := handshake.NewCredentials(log)
	cred, err := creds.Mint(sessionID, key.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return &simNet{net: n, sh: sh, cc: cc, sc: sc, creds: creds, cred: cred, key: key, log: log}
}

// serve runs proto's Session over the server's socket, with prog as the
// shell's pty and the in-process emulator; its end arrives on the channel.
func (n *simNet) serve(t *testing.T, ctx context.Context, prog server.Terminal) <-chan error {
	t.Helper()
	return n.serveWith(t, ctx, prog, nil)
}

// serveWith is serve with a hook to set the Session's callbacks.
func (n *simNet) serveWith(t *testing.T, ctx context.Context, prog server.Terminal, hook func(*server.Session)) <-chan error {
	t.Helper()
	em, err := emu.New(80, 24, emu.Options{ScrollbackCells: emu.DefaultScrollbackCells})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	srv := &server.Session{Listener: transport.Listen(n.sc, n.creds, n.log), Terminal: prog, Emulator: em, Log: n.log}
	if hook != nil {
		hook(srv)
	}
	go func() { done <- srv.Run(ctx) }()
	return done
}

// device is another client of the same session: a host of its own on a
// LAN link to the server, a fresh one-shot key, and a credential minted
// for the same session id, as proto mints one for a resume
// (transport.md §8.1). Nothing of the first client's is reused.
type device struct {
	conn *netsim.Conn
	addr netip.AddrPort
	key  *handshake.OneShotKey
	cred handshake.Credential
}

func (n *simNet) device(t *testing.T, name string, addr netip.AddrPort) *device {
	t.Helper()
	h := n.net.NewHost(name)
	c, err := h.Listen(addr)
	if err != nil {
		t.Fatal(err)
	}
	netsim.LAN().Setup(n.net, h, n.sh, c)
	key, err := handshake.NewOneShotKey()
	if err != nil {
		t.Fatal(err)
	}
	cred, err := n.creds.Mint(sessionID, key.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return &device{conn: c, addr: addr, key: key, cred: cred}
}

// resume runs a client Session from d, on user's terminal; its end
// arrives on the channel.
func (n *simNet) resume(ctx context.Context, d *device, user terminal.Terminal) <-chan error {
	done := make(chan error, 1)
	cli := &client.Session{Conn: d.conn, Server: serverAddr, Credential: d.cred, Key: d.key, Terminal: user, Log: n.log,
		Capabilities: render.Capabilities{UTF8: true, Colors256: true}}
	go func() { done <- cli.Run(ctx) }()
	return done
}

// connect runs the client's Session over the client's socket, on user's
// terminal; its end arrives on the channel.
func (n *simNet) connect(ctx context.Context, user terminal.Terminal) <-chan error {
	return n.connectWith(ctx, user, nil)
}

// connectWith is connect with a hook to set the client Session's fields:
// its name and R3's Reconnect.
func (n *simNet) connectWith(ctx context.Context, user terminal.Terminal, hook func(*client.Session)) <-chan error {
	done := make(chan error, 1)
	cli := &client.Session{Conn: n.cc, Server: serverAddr, Credential: n.cred, Key: n.key, Terminal: user, Log: n.log,
		Capabilities: render.Capabilities{UTF8: true, Colors256: true}}
	if hook != nil {
		hook(cli)
	}
	go func() { done <- cli.Run(ctx) }()
	return done
}

// program is a fake shell on the server's side of a fake pty.
type program interface {
	server.Terminal
	io.Closer
	// output is what the server has been given to read: the screen it
	// should have.
	output() []byte
}

func startSimSession(t *testing.T, p netsim.Profile) *simSession {
	sh := newShell()
	s := startSimSessionWith(t, p, sh, nil)
	s.prog = sh
	return s
}

// startSimSessionWith is startSimSession with prog as the shell and a hook
// on the server's Session.
func startSimSessionWith(t *testing.T, p netsim.Profile, prog program, hook func(*server.Session)) *simSession {
	n := newSimNet(t, p)
	ctx, cancel := context.WithCancel(context.Background())
	cctx, quit := context.WithCancel(ctx)
	s := &simSession{
		t:       t,
		profile: p.Name,
		user:    &userTerminal{keys: make(chan []byte), resized: make(chan struct{})},
		term:    prog,
		cc:      n.cc,
		quit:    quit,
		cancel:  cancel,
	}
	s.server = n.serveWith(t, ctx, prog, hook)
	s.client = n.connect(cctx, s.user)
	// However the test ends, end both sessions and release what they wait
	// on, so the bubble has nothing left blocked.
	t.Cleanup(s.end)
	return s
}

func (s *simSession) end() {
	s.stop.Do(func() {
		s.cancel()
		close(s.user.keys)
		s.term.Close()
	})
}

// wait sleeps in virtual time until cond holds. A profile's outages pass in
// no real time at all; the bound is generous because an outage on the
// train lasts up to 45 s and SSP's probes back off to 1 s (D11).
func (s *simSession) wait(what string, cond func() bool) {
	s.t.Helper()
	for deadline := time.Now().Add(10 * time.Minute); !cond(); {
		if time.Now().After(deadline) {
			s.t.Fatalf("%s: no %s after 10 virtual minutes; on the screen:\n%s", s.profile, what, s.clientScreen())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// typeLine types line and Enter, as the user would.
func (s *simSession) typeLine(line string) {
	s.t.Helper()
	select {
	case s.user.keys <- []byte(line + "\r"):
	case <-time.After(10 * time.Minute):
		s.t.Fatalf("%s: the client stopped reading its terminal", s.profile)
	}
}

// clientScreen is what the user sees: the bytes the client's renderer
// wrote, played into a reference terminal. The client itself never parses
// them (D9); the test does, to check what they show.
func (s *simSession) clientScreen() string {
	return screenOf(s.user.bytes(), 80, 24)
}

// serverScreen is the screen the shell's output makes, played into a
// terminal of its own: what the server's emulator holds.
func (s *simSession) serverScreen() string {
	return screenOf(s.term.output(), 80, 24)
}

// converge waits until the user sees exactly the screen the server has:
// SSP delivers the latest state, whatever was lost on the way (D11).
func (s *simSession) converge() {
	s.t.Helper()
	s.wait("screen matching the server's", func() bool { return s.clientScreen() == s.serverScreen() })
}

// exit types exit, and the session must end: the server delivers the
// screen the shell left, then says so with an END frame, and the client
// returns nil (server.md §2.4, transport.md §8.4). It returns how long the
// client took to end after exit was typed, in virtual time.
func (s *simSession) exit() time.Duration {
	s.t.Helper()
	s.typeLine("exit")
	typed := time.Now()
	select {
	case err := <-s.client:
		if err != nil {
			s.t.Errorf("%s: the client ended with %v", s.profile, err)
		}
	case <-time.After(10 * time.Minute):
		s.t.Fatalf("%s: the client did not end after the shell exited", s.profile)
	}
	took := time.Since(typed)
	if err := <-s.server; err != nil {
		s.t.Errorf("%s: the server ended with %v", s.profile, err)
	}
	// The last screen the user saw, before the client put the terminal
	// back, is the one the shell left: "exit" echoed included.
	drawn := s.user.bytes()
	if i := bytes.LastIndex(drawn, []byte("\x1b[?25h\x1b[?7h")); i >= 0 {
		drawn = drawn[:i]
	}
	if got, want := screenOf(drawn, 80, 24), s.serverScreen(); got != want {
		s.t.Errorf("%s: the final screen was not delivered; the user saw:\n%s\nthe server had:\n%s", s.profile, got, want)
	}
	return took
}

// screenOf plays b into a terminal of cols by rows and returns its text, a
// line a row with trailing blanks trimmed.
func screenOf(b []byte, cols, rows int) string {
	t, err := emu.New(cols, rows, emu.Options{})
	if err != nil {
		panic(err)
	}
	defer t.Close()
	t.Write(b)
	g := screen.NewGrid(0, 0)
	t.Snapshot(g)
	cols, rows = g.Size()
	var out strings.Builder
	for y := range rows {
		var line strings.Builder
		for x := range cols {
			switch c := g.Cell(x, y); {
			case c.Width == 0:
			case c.Text == "":
				line.WriteByte(' ')
			default:
				line.WriteString(c.Text)
			}
		}
		out.WriteString(strings.TrimRight(line.String(), " "))
		out.WriteByte('\n')
	}
	return out.String()
}

// What the user types reaches the program, what the program prints reaches
// the user's screen, which converges on the server's, and when the shell
// exits the client ends: over every netsim profile, in virtual time (D18).
func TestAShellSessionOverEveryNetworkProfile(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	for _, p := range netsim.Profiles() {
		t.Run(p.Name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := startSimSession(t, p)
				s.wait("prompt", func() bool { return strings.Contains(s.clientScreen(), "$") })
				s.typeLine("echo over-the-network")
				s.wait("answer", func() bool { return strings.Contains(s.clientScreen(), "OVER-THE-NETWORK") })
				s.converge()
				s.exit()
			})
		})
	}
}

// On a good network a shell's exit ends the client within a round trip or
// two, the final screen delivered and acknowledged, not after T6 spent
// waiting for an acknowledgement that could never come (server.md §2.4).
func TestTheShellsLastWordsReachTheClientPromptly(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	synctest.Test(t, func(t *testing.T) {
		s := startSimSession(t, netsim.LAN())
		s.wait("prompt", func() bool { return strings.Contains(s.clientScreen(), "$") })
		s.typeLine("echo before")
		s.wait("answer", func() bool { return strings.Contains(s.clientScreen(), "BEFORE") })
		s.converge()
		// LAN's round trip is a few ms; the client's delayed ack is 100 ms
		// and the server's collection interval 8 ms (D11).
		if took := s.exit(); took >= server.T6/2 {
			t.Errorf("the client ended %v after exit was typed; T6 is %v", took, server.T6)
		}
	})
}

// A session nobody connects to ends by itself once its one credential has
// expired unconfirmed, since nothing can ever connect to it after that
// (bootstrap.md §4.5, server.md §2.4): proto's Session returns ErrNoClient,
// on which the spawner tears everything down.
func TestASessionNobodyConnectsToEnds(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	synctest.Test(t, func(t *testing.T) {
		n := newSimNet(t, netsim.LAN())
		prog := newShell()
		start := time.Now()
		served := n.serve(t, context.Background(), prog)
		select {
		case err := <-served:
			if !errors.Is(err, server.ErrNoClient) {
				t.Fatalf("the server ended with %v, not ErrNoClient", err)
			}
			if took := time.Since(start); took < handshake.CredentialTTL {
				t.Errorf("it ended %v in, before the credential expired", took)
			}
		case <-time.After(handshake.CredentialTTL + time.Minute):
			t.Fatal("a session nobody connected to is still running")
		}
	})
}

// A long session on the train and in the hotel: through outages of up to
// 45 s and changes of the client's address, every line typed is answered,
// and the screen converges (D11, D21).
func TestASessionRidesOutOutagesAndRoams(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	for _, p := range netsim.Profiles() {
		if p.Name != "train" && p.Name != "hotel-wifi" {
			continue
		}
		t.Run(p.Name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := startSimSession(t, p)
				first := s.cc.LocalAddr().String()
				s.wait("prompt", func() bool { return strings.Contains(s.clientScreen(), "$") })
				start := time.Now()
				for i := 0; time.Since(start) < 25*time.Minute; i++ {
					word := fmt.Sprintf("line-%d", i)
					s.typeLine("echo " + word)
					s.wait("answer to "+word, func() bool { return strings.Contains(s.clientScreen(), strings.ToUpper(word)) })
					time.Sleep(20 * time.Second)
				}
				if p.Name == "train" && s.cc.LocalAddr().String() == first {
					t.Errorf("the client never roamed from %s: the profile's roams did not happen", first)
				}
				s.converge()
				s.exit()
			})
		})
	}
}
