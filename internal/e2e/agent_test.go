//go:build linux

package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/danielbodart/mosey/internal/agent"
	"github.com/danielbodart/mosey/internal/client"
	"github.com/danielbodart/mosey/internal/emu"
	"github.com/danielbodart/mosey/internal/netsim"
	"github.com/danielbodart/mosey/internal/render"
	"github.com/danielbodart/mosey/internal/server"
	"github.com/danielbodart/mosey/internal/transport"
)

// agentFrame is an agent protocol message with its length prefix.
func agentFrame(body []byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(body))), body...)
}

func sshString(b, s []byte) []byte {
	return append(binary.BigEndian.AppendUint32(b, uint32(len(s))), s...)
}

// testBind is a session-bind as ssh sends one at the bootstrap: a
// throwaway host key's signature over a session id, for forwarding.
func testBind(t *testing.T) agent.Bind {
	t.Helper()
	key, err := ssh.NewSignerFromKey(mustEd25519(t))
	if err != nil {
		t.Fatal(err)
	}
	sid := bytes.Repeat([]byte{0x5a}, 32)
	sig, err := key.Sign(rand.Reader, sid)
	if err != nil {
		t.Fatal(err)
	}
	body := sshString([]byte{27}, []byte(agent.SessionBindExtension))
	body = sshString(body, key.PublicKey().Marshal())
	body = sshString(body, sid)
	body = sshString(body, ssh.Marshal(sig))
	b, err := agent.ParseBind(agentFrame(append(body, 1)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func readAgentFrame(r io.Reader) ([]byte, error) {
	var l [4]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	f := make([]byte, 4+binary.BigEndian.Uint32(l[:]))
	copy(f, l[:])
	_, err := io.ReadFull(r, f[4:])
	return f, err
}

// agentSession is a client and a server Session over netsim, as in
// netsim_test.go, with the client forwarding to fwd (nil for none) and
// the server's Session kept so a test can hand it agent connections.
func agentSession(t *testing.T, p netsim.Profile, fwd *agent.Forwarder) *server.Session {
	t.Helper()
	return agentSessionAfter(t, p, fwd, nil)
}

// agentSessionAfter is agentSession with early run on the server's
// Session after it starts and before the client does.
func agentSessionAfter(t *testing.T, p netsim.Profile, fwd *agent.Forwarder, early func(*server.Session)) *server.Session {
	t.Helper()
	n := newSimNet(t, p)
	ctx, cancel := context.WithCancel(context.Background())
	em, err := emu.New(80, 24, emu.Options{ScrollbackCells: emu.DefaultScrollbackCells})
	if err != nil {
		t.Fatal(err)
	}
	prog := newShell()
	srv := &server.Session{Listener: transport.Listen(n.sc, n.creds, n.log), Terminal: prog, Emulator: em, Log: n.log}
	served := make(chan error, 1)
	go func() { served <- srv.Run(ctx) }()
	if early != nil {
		early(srv)
	}
	user := &userTerminal{keys: make(chan []byte), resized: make(chan struct{})}
	cli := &client.Session{Conn: n.cc, Server: serverAddr, Credential: n.cred, Key: n.key, Terminal: user, Log: n.log,
		Capabilities: render.Capabilities{UTF8: true}, Agent: fwd}
	ran := make(chan error, 1)
	go func() { ran <- cli.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		close(user.keys)
		prog.Close()
		<-served
		<-ran
	})
	// The session is up once the user sees the shell's prompt.
	for !bytes.Contains(user.bytes(), []byte("$")) {
		time.Sleep(50 * time.Millisecond)
	}
	return srv
}

// A program on the far host talks to the user's agent over the session,
// as under ssh -A: the agent first sees ssh's bind, replayed, and its
// answer to it never reaches the program; then a request and an
// extension message (provenance-v00@bodar.com, D28) arrive byte for byte,
// and the agent's answers go back byte for byte, over a LAN and over a
// lossy hotel wifi (agent.md §1, §3).
func TestAFarProgramReachesTheUsersAgentThroughTheSession(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	for _, p := range []netsim.Profile{netsim.LAN(), netsim.HotelWifi()} {
		t.Run(p.Name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				bind := testBind(t)
				agentSide, forwarded := net.Pipe()
				srv := agentSession(t, p, &agent.Forwarder{Bind: bind, Dial: func(context.Context) (net.Conn, error) { return forwarded, nil }})

				requests := [][]byte{
					agentFrame([]byte{11}), // REQUEST_IDENTITIES
					agentFrame(append(sshString([]byte{27}, []byte("provenance-v00@bodar.com")), bytes.Repeat([]byte{0, 0x1b, 0x9b, 0xff}, 2300)...)),
				}
				answers := [][]byte{
					agentFrame([]byte{12, 0, 0, 0, 0}),
					agentFrame(append([]byte{6}, bytes.Repeat([]byte("signed statement "), 600)...)),
				}
				agentErr := make(chan error, 1)
				go func() {
					got, err := readAgentFrame(agentSide)
					if err != nil || !bytes.Equal(got, bind.Frame()) {
						agentErr <- errors.New("the agent's first message is not the replayed bind")
						return
					}
					agentSide.Write(agentFrame([]byte{5})) // an agent that does not know session-bind
					for i, want := range requests {
						got, err := readAgentFrame(agentSide)
						if err != nil || !bytes.Equal(got, want) {
							agentErr <- errors.New("a request was changed on the way")
							return
						}
						agentSide.Write(answers[i])
					}
					agentErr <- nil
				}()

				program, local := net.Pipe()
				srv.AgentConn(local)
				for i, req := range requests {
					program.Write(req)
					got, err := readAgentFrame(program)
					if err != nil || !bytes.Equal(got, answers[i]) {
						t.Fatalf("answer %d: %d bytes, %v", i, len(got), err)
					}
				}
				if err := <-agentErr; err != nil {
					t.Fatal(err)
				}
				program.Close()
			})
		})
	}
}

// A client that forwards no agent offers no agent channel, so the far
// program's connection is closed at once (agent.md §2.4, §4.2).
func TestWithoutAnAgentTheFarConnectionIsClosed(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	synctest.Test(t, func(t *testing.T) {
		srv := agentSession(t, netsim.LAN(), nil)
		program, local := net.Pipe()
		srv.AgentConn(local)
		go program.Write(agentFrame([]byte{11}))
		if _, err := program.Read(make([]byte, 1)); err == nil {
			t.Error("the far program read an answer from no agent")
		}
	})
}

// A program the login rc runs, such as `ssh-add -l`, connects before the
// client has finished its handshake; it is held until the client attaches
// and then reaches the agent, as under ssh -A, where the agent is there
// from the shell's first line (agent.md §4.2).
func TestAnAgentConnectionMadeBeforeTheClientAttachesWaitsForIt(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	synctest.Test(t, func(t *testing.T) {
		bind := testBind(t)
		agentSide, forwarded := net.Pipe()
		go func() {
			if _, err := readAgentFrame(agentSide); err != nil {
				return
			}
			agentSide.Write(agentFrame([]byte{6})) // the bind's answer
			if _, err := readAgentFrame(agentSide); err != nil {
				return
			}
			agentSide.Write(agentFrame([]byte{12, 0, 0, 0, 0}))
		}()
		program, local := net.Pipe()
		agentSessionAfter(t, netsim.LAN(), &agent.Forwarder{Bind: bind, Dial: func(context.Context) (net.Conn, error) { return forwarded, nil }},
			func(srv *server.Session) {
				srv.AgentConn(local)
				// The connection waits a while for the client, not at once.
				time.Sleep(time.Second)
			})
		go program.Write(agentFrame([]byte{11}))
		got, err := readAgentFrame(program)
		if err != nil || !bytes.Equal(got, agentFrame([]byte{12, 0, 0, 0, 0})) {
			t.Fatalf("the early program's answer: %x, %v", got, err)
		}
		program.Close()
	})
}

// If no client attaches within AgentStartupHold, a connection held for
// one is closed, so a requester does not wait for ever (agent.md §4.2).
func TestAnAgentConnectionWithNoClientIsClosedAfterTheHold(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	synctest.Test(t, func(t *testing.T) {
		n := newSimNet(t, netsim.LAN())
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		em, err := emu.New(80, 24, emu.Options{ScrollbackCells: emu.DefaultScrollbackCells})
		if err != nil {
			t.Fatal(err)
		}
		prog := newShell()
		defer prog.Close()
		srv := &server.Session{Listener: transport.Listen(n.sc, n.creds, n.log), Terminal: prog, Emulator: em, Log: n.log}
		served := make(chan error, 1)
		go func() { served <- srv.Run(ctx) }()
		program, local := net.Pipe()
		start := time.Now()
		srv.AgentConn(local)
		go program.Write(agentFrame([]byte{11}))
		if _, err := program.Read(make([]byte, 1)); err == nil {
			t.Error("the far program read an answer from no client")
		}
		if waited := time.Since(start); waited < server.AgentStartupHold || waited > server.AgentStartupHold+time.Second {
			t.Errorf("closed after %v, want %v", waited, server.AgentStartupHold)
		}
		cancel()
		<-served
	})
}

func mustEd25519(t *testing.T) any {
	t.Helper()
	_, priv, err := ed25519GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

var ed25519GenerateKey = func() (any, any, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	return pub, priv, err
}
