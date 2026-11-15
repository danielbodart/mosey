package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/sys/unix"

	"github.com/danielbodart/mosey/internal/bootstrap"
	"github.com/danielbodart/mosey/internal/ipc"
)

// The spawner's side of a resume (server.md §2.6), driven through its real
// attach socket and its real supervision loop, with this test in proto's
// place on the control socket. proto and the shell are idle copies of this
// test binary, so that "proto is killed" is a process really killed, and
// the teardown that follows is the real one.

func init() { roleChildren["idle"] = childIdle }

// childIdle waits for its stdin to close: a process that does nothing
// until it is killed or its parent lets go.
func childIdle() error {
	_, err := io.Copy(io.Discard, os.Stdin)
	return err
}

// syncBuffer is a log the spawner writes from several goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

// stubSession is a spawner past its bootstrap, supervising, with the test
// holding proto's end of the control socket.
type stubSession struct {
	t        *testing.T
	s        *spawner
	proto    *ipc.Conn // the stub proto's end
	protoCmd *exec.Cmd
	protoIn  *os.File // closing it lets the idle proto exit
	runtime  string
	log      *syncBuffer
	ended    chan struct{}
}

const (
	stubVersion = "resumetest"
	stubName    = "stub"
)

var stubAddr = netip.MustParseAddr("127.0.0.1")

const stubPort = 60123

// startIdle starts an idle child reading stdin, as a spawner's child.
func startIdle(t *testing.T, role string, stdin *os.File) *child {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self)
	cmd.Env = append(os.Environ(), roleChildEnv+"=idle")
	cmd.Stdin = stdin
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	c := &child{role: role, cmd: cmd, born: time.Now(), done: make(chan *os.ProcessState, 1)}
	go func() {
		cmd.Wait()
		c.done <- cmd.ProcessState
	}()
	return c
}

func startStubSession(t *testing.T, sid [16]byte) *stubSession {
	t.Helper()
	return startStubSessionWith(t, sid, SpawnerConfig{Version: stubVersion}, 0)
}

// startStubSessionWith is startStubSession with the spawner's config, for
// its idle timeout, and how long a resume holds the greeting (0 is the
// credential's TTL).
func startStubSessionWith(t *testing.T, sid [16]byte, cfg SpawnerConfig, hold time.Duration) *stubSession {
	t.Helper()
	return startStubSessionSetUp(t, sid, cfg, hold, nil)
}

// startStubSessionSetUp is startStubSessionWith with setUp run on the
// spawner before it starts supervising, for what a test must set first.
func startStubSessionSetUp(t *testing.T, sid [16]byte, cfg SpawnerConfig, hold time.Duration, setUp func(*spawner)) *stubSession {
	t.Helper()
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = IdleTimeout
	}
	runtime := runtimeDir(t)
	local, remote, err := ipc.Pair()
	if err != nil {
		t.Fatal(err)
	}
	ctl, err := ipc.NewConn(local, ipc.Spawner, ipc.Proto)
	if err != nil {
		t.Fatal(err)
	}
	stub, err := ipc.NewConn(remote, ipc.Proto, ipc.Spawner)
	if err != nil {
		t.Fatal(err)
	}
	protoR, protoW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	shellR, master, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	proto := startIdle(t, "proto", protoR)
	protoR.Close()
	// The teardown's closing the master is the shell's hangup.
	shell := startIdle(t, "shell", shellR)
	shellR.Close()

	log := &syncBuffer{}
	now := time.Now()
	s := &spawner{
		cfg: cfg, start: newStarter(),
		log: slog.New(slog.NewTextHandler(log, nil)),
		ctl: ctl, advertised: stubAddr, port: stubPort, master: master,
		proto: proto, shell: shell, ready: true,
		sid: sid, name: stubName, started: now, state: bootstrap.SessionNew, since: now,
		resumes: make(chan resumeRequest), hangups: make(chan struct{}, 1), holdTTL: hold,
		handoffs: make(chan *handoffJob), handoffDropped: make(chan struct{}, 1),
		handoffCommit: make(chan struct{}), takenWait: T2,
	}
	if s.attach, err = listenAttach(filepath.Join(runtime, "mosey"), sid); err != nil {
		t.Fatal(err)
	}
	s.readCtl()
	if setUp != nil {
		setUp(s)
	}
	ss := &stubSession{t: t, s: s, proto: stub, protoCmd: proto.cmd, protoIn: protoW,
		runtime: runtime, log: log, ended: make(chan struct{})}
	go func() {
		defer close(ss.ended)
		s.supervise(context.Background())
	}()
	t.Cleanup(func() {
		protoW.Close()
		select {
		case <-ss.ended:
		case <-time.After(30 * time.Second):
			proto.cmd.Process.Kill()
			shell.cmd.Process.Kill()
			t.Error("the session did not end")
		}
		stub.Close()
	})
	return ss
}

// launch runs a launcher resuming sid with a fresh key, and returns the
// key and, once it is done, what it printed and how it ended.
type launchResult struct {
	public []byte
	out    string
	err    error
}

func (ss *stubSession) launch(sid [16]byte) (public []byte, result <-chan launchResult) {
	ss.t.Helper()
	return ss.launchLine(bootstrap.ClientLine{SoftwareVersion: stubVersion, Attach: bootstrap.AttachResume, SessionID: sid})
}

// launchLine is launch with the client's line, to which it adds the size
// and a fresh key.
func (ss *stubSession) launchLine(cl bootstrap.ClientLine) (public []byte, result <-chan launchResult) {
	ss.t.Helper()
	public = oneShotKey(ss.t)
	cl.Cols, cl.Rows, cl.Public = 80, 24, public
	line := bootstrap.MarshalClientLine(cl)
	ch := make(chan launchResult, 1)
	go func() {
		var stdout, stderr bytes.Buffer
		l := &Launcher{Stdin: bytes.NewReader(line), Stdout: &stdout, Stderr: &stderr,
			Version: stubVersion, Env: []string{"XDG_RUNTIME_DIR=" + ss.runtime}}
		err := l.Run(context.Background())
		ch <- launchResult{public, stdout.String(), err}
	}()
	return public, ch
}

// recv is the next message the spawner sends the stub proto.
func (ss *stubSession) recv() ipc.Message {
	ss.t.Helper()
	ss.proto.File().SetReadDeadline(time.Now().Add(10 * time.Second))
	m, err := ss.proto.Recv()
	if err != nil {
		ss.t.Fatalf("the stub proto: %v\nlog:\n%s", err, ss.log.String())
	}
	return m
}

func (ss *stubSession) recvResume() ipc.Resume {
	ss.t.Helper()
	m := ss.recv()
	r, ok := m.(ipc.Resume)
	if !ok {
		ss.t.Fatalf("proto got %T, not Resume", m)
	}
	return r
}

func (ss *stubSession) send(m ipc.Message) {
	ss.t.Helper()
	if err := ss.proto.Send(m); err != nil {
		ss.t.Fatal(err)
	}
}

// credential is a line §3.4 accepts for this session, told apart by id.
func credential(t *testing.T, sid [16]byte, id byte) bootstrap.CredentialLine {
	return bootstrap.CredentialLine{
		SoftwareVersion: stubVersion, Addr: stubAddr, Port: stubPort,
		CredentialID: [bootstrap.CredentialIDSize]byte{id}, SessionID: sid,
		Name: stubName, Public: oneShotKey(t),
	}
}

func wait(t *testing.T, ch <-chan launchResult) launchResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(30 * time.Second):
		t.Fatal("the launcher did not finish")
		return launchResult{}
	}
}

// protoKilled waits for the session to end and says whether proto died of
// SIGKILL: the spawner's answer to a violation.
func (ss *stubSession) protoKilled() bool {
	ss.t.Helper()
	select {
	case <-ss.ended:
	case <-time.After(30 * time.Second):
		ss.t.Fatalf("the session did not end\nlog:\n%s", ss.log.String())
	}
	ws, ok := ss.protoCmd.ProcessState.Sys().(syscall.WaitStatus)
	return ok && ws.Signaled() && ws.Signal() == syscall.SIGKILL
}

func TestAResumeReachesProtoAndItsCredentialReachesTheLauncher(t *testing.T) {
	sid := [16]byte{0x5e, 1}
	ss := startStubSession(t, sid)
	public, done := ss.launch(sid)
	if r := ss.recvResume(); !bytes.Equal(r.ClientPublic, public) {
		t.Errorf("proto was asked to mint for another key")
	}
	want := bootstrap.MarshalCredentialLine(credential(t, sid, 1))
	ss.send(ipc.Credential{Line: bytes.Clone(want)})
	if r := wait(t, done); r.err != nil || r.out != string(want) {
		t.Fatalf("the launcher: %v, printed %q\nlog:\n%s", r.err, r.out, ss.log.String())
	}
}

// A Credential that is not for this resume, of this session, from this
// spawner, is a violation (server.md §3.4, §2.6): proto is killed, and the
// launcher waiting on it is told the resume failed.
func TestACredentialForAnotherSessionAddressPortOrVersionKillsProto(t *testing.T) {
	for name, spoil := range map[string]func(*bootstrap.CredentialLine){
		"sessionid": func(c *bootstrap.CredentialLine) { c.SessionID[15] ^= 1 },
		"addr":      func(c *bootstrap.CredentialLine) { c.Addr = netip.MustParseAddr("127.0.0.2") },
		"port":      func(c *bootstrap.CredentialLine) { c.Port++ },
		"swver":     func(c *bootstrap.CredentialLine) { c.SoftwareVersion = "other" },
		"name":      func(c *bootstrap.CredentialLine) { c.Name = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			sid := [16]byte{0x5e, 2}
			ss := startStubSession(t, sid)
			_, done := ss.launch(sid)
			ss.recvResume()
			c := credential(t, sid, 1)
			spoil(&c)
			ss.send(ipc.Credential{Line: bootstrap.MarshalCredentialLine(c)})
			r := wait(t, done)
			if r.err == nil {
				t.Errorf("the launcher printed %q", r.out)
			} else if e, err := bootstrap.ParseErrorLine([]byte(r.out)); err != nil {
				t.Errorf("the launcher printed %q, not an ErrorLine: %v", r.out, err)
			} else if e.Code != bootstrap.CodeInternal {
				t.Errorf("the launcher's code: %s", e.Code)
			}
			if !ss.protoKilled() {
				t.Errorf("proto lives on after a bad credential\nlog:\n%s", ss.log.String())
			}
		})
	}
}

func TestACredentialNobodyAskedForKillsProto(t *testing.T) {
	sid := [16]byte{0x5e, 3}
	ss := startStubSession(t, sid)
	ss.send(ipc.Credential{Line: bootstrap.MarshalCredentialLine(credential(t, sid, 1))})
	if !ss.protoKilled() {
		t.Errorf("proto lives on after an unasked-for credential\nlog:\n%s", ss.log.String())
	}
}

// direct is a resume straight to the spawner's attach socket, as a
// launcher without the lock would make it: the spawner must still answer
// resumes that wait together in order.
func (ss *stubSession) direct(sid [16]byte) (public []byte, result <-chan launchResult) {
	ss.t.Helper()
	public = oneShotKey(ss.t)
	line := bootstrap.MarshalClientLine(bootstrap.ClientLine{
		SoftwareVersion: stubVersion, Attach: bootstrap.AttachResume, SessionID: sid,
		Cols: 80, Rows: 24, Public: public,
	})
	ch := make(chan launchResult, 1)
	go func() {
		f, _, err := dialAttach(sessionDir(filepath.Join(ss.runtime, "mosey"), sid))
		if err != nil {
			ch <- launchResult{public, "", err}
			return
		}
		defer f.Close()
		conn, _ := ipc.NewConn(f, ipc.Launcher, ipc.Spawner)
		if err := conn.Send(ipc.ClientLine{Line: line}); err != nil {
			ch <- launchResult{public, "", err}
			return
		}
		m, err := conn.Recv()
		if r, ok := m.(ipc.Ready); ok {
			ch <- launchResult{public, string(r.Line), nil}
			return
		}
		ch <- launchResult{public, "", fmt.Errorf("%T %v", m, err)}
	}()
	return public, ch
}

// Two resumes waiting on proto at once: proto answers in the order it was
// asked, and each gets the answer to its own.
func TestResumesWaitingTogetherAreAnsweredInOrder(t *testing.T) {
	sid := [16]byte{0x5e, 4}
	ss := startStubSession(t, sid)
	_, doneA := ss.direct(sid)
	_, doneB := ss.direct(sid)
	first, second := ss.recvResume(), ss.recvResume()
	lineFirst := bootstrap.MarshalCredentialLine(credential(t, sid, 1))
	lineSecond := bootstrap.MarshalCredentialLine(credential(t, sid, 2))
	ss.send(ipc.Credential{Line: bytes.Clone(lineFirst)})
	ss.send(ipc.Credential{Line: bytes.Clone(lineSecond)})
	want := map[string]string{
		string(first.ClientPublic):  string(lineFirst),
		string(second.ClientPublic): string(lineSecond),
	}
	if len(want) != 2 {
		t.Fatal("proto was asked twice for the same key")
	}
	for _, r := range []launchResult{wait(t, doneA), wait(t, doneB)} {
		if r.err != nil {
			t.Errorf("a launcher: %v\nlog:\n%s", r.err, ss.log.String())
		} else if r.out != want[string(r.public)] {
			t.Errorf("a launcher got the answer to another's resume")
		}
	}
}

// greetingOf reads the session's greeting as a lister does, and closes.
func (ss *stubSession) greetingOf() bootstrap.SessionLine {
	ss.t.Helper()
	f, line, err := dialAttach(sessionDir(filepath.Join(ss.runtime, "mosey"), ss.s.sid))
	if err != nil {
		ss.t.Fatal(err)
	}
	f.Close()
	g, err := bootstrap.ParseSessionLine(line)
	if err != nil {
		ss.t.Fatal(err)
	}
	return g
}

// The greeting follows proto's Attached and Detached, and a detach keeps
// the last peer; a lister that reads it and closes reaches nothing.
func TestTheGreetingFollowsAttachAndDetachAndAListerChangesNothing(t *testing.T) {
	sid := [16]byte{0x5e, 5}
	ss := startStubSession(t, sid)
	if g := ss.greetingOf(); g.State != bootstrap.SessionNew || g.SessionID != sid || g.SoftwareVersion != stubVersion {
		t.Errorf("a new session's greeting: %+v", g)
	}
	peer := netip.MustParseAddrPort("192.0.2.9:40000")
	until := func(want bootstrap.SessionState) bootstrap.SessionLine {
		deadline := time.Now().Add(10 * time.Second)
		for {
			g := ss.greetingOf()
			if g.State == want || time.Now().After(deadline) {
				return g
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	ss.send(ipc.Attached{Credential: [8]byte{7}, Peer: peer})
	if g := until(bootstrap.SessionAttached); g.State != bootstrap.SessionAttached || g.Peer != peer ||
		!g.HasHolder || g.Holder != [8]byte{7} || g.Name != stubName {
		t.Errorf("after Attached: %+v", g)
	}
	ss.send(ipc.Detached{})
	if g := until(bootstrap.SessionDetached); g.State != bootstrap.SessionDetached || g.Peer != peer || g.HasHolder {
		t.Errorf("after Detached: %+v", g)
	}
	// The listers above reached nothing: the first thing proto hears is
	// the resume that follows them.
	public, done := ss.launch(sid)
	if r := ss.recvResume(); !bytes.Equal(r.ClientPublic, public) {
		t.Error("proto heard something other than the resume")
	}
	line := bootstrap.MarshalCredentialLine(credential(t, sid, 1))
	ss.send(ipc.Credential{Line: bytes.Clone(line)})
	if r := wait(t, done); r.err != nil || r.out != string(line) {
		t.Errorf("a resume after listers: %v %q", r.err, r.out)
	}
}

// Once a resume's credential is out, the greeting says the session is
// attached, held by that credential, before its client has confirmed, so
// the next plain mosey does not take it too; with nobody confirming, the
// hold ends and the greeting says what it said before (bootstrap.md §9.2
// "The lock").
func TestAResumesCredentialHoldsTheSessionUntilItCouldNoLongerBeConfirmed(t *testing.T) {
	sid := [16]byte{0x5e, 7}
	ss := startStubSessionWith(t, sid, SpawnerConfig{Version: stubVersion}, 500*time.Millisecond)
	ss.send(ipc.Detached{})
	for ss.greetingOf().State != bootstrap.SessionDetached {
		time.Sleep(10 * time.Millisecond)
	}
	_, done := ss.launch(sid)
	ss.recvResume()
	ss.send(ipc.Credential{Line: bootstrap.MarshalCredentialLine(credential(t, sid, 9))})
	if r := wait(t, done); r.err != nil {
		t.Fatal(r.err)
	}
	if g := ss.greetingOf(); g.State != bootstrap.SessionAttached || !g.HasHolder || g.Holder != [8]byte{9} {
		t.Errorf("while the credential is out: %+v", g)
	}
	deadline := time.Now().Add(10 * time.Second)
	for ss.greetingOf().State != bootstrap.SessionDetached {
		if time.Now().After(deadline) {
			t.Fatalf("the hold never ended: %+v", ss.greetingOf())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A reconnect's hold is the reconnecting client's: the greeting names the
// credential that client last had, so if its try is dropped because the
// old path was heard again, and the path then goes quiet once more, its
// next try still takes the session instead of being told it was taken
// over by a credential nobody used (bootstrap.md §9.2.2). Another
// client's reconnect is still refused.
func TestAReconnectsHoldIsTheReconnectingClientsOwn(t *testing.T) {
	sid := [16]byte{0x5e, 0x0a}
	ss := startStubSession(t, sid)
	mine := [8]byte{7}
	ss.send(ipc.Attached{Credential: mine})
	for g := ss.greetingOf(); g.State != bootstrap.SessionAttached; g = ss.greetingOf() {
		time.Sleep(10 * time.Millisecond)
	}
	reconnect := func(holder [8]byte) <-chan launchResult {
		_, done := ss.launchLine(bootstrap.ClientLine{SoftwareVersion: stubVersion, Attach: bootstrap.AttachResume,
			SessionID: sid, Holder: holder, HasHolder: true})
		return done
	}
	// The first try gets credential 9, which its client never uses.
	done := reconnect(mine)
	ss.recvResume()
	ss.send(ipc.Credential{Line: bootstrap.MarshalCredentialLine(credential(t, sid, 9))})
	if r := wait(t, done); r.err != nil {
		t.Fatal(r.err)
	}
	if g := ss.greetingOf(); g.State != bootstrap.SessionAttached || !g.HasHolder || g.Holder != mine {
		t.Errorf("while the reconnect's credential is out: %+v, not held for its client", g)
	}
	// Another client's reconnect is refused as taken, and proto hears
	// nothing of it.
	if r := wait(t, reconnect([8]byte{8})); r.err == nil || !strings.HasPrefix(r.out, "MOSEY-ERROR 1 taken ") {
		t.Errorf("another client's reconnect: %v, %q", r.err, r.out)
	}
	// The same client's next try is its own again.
	done = reconnect(mine)
	ss.recvResume()
	line := bootstrap.MarshalCredentialLine(credential(t, sid, 10))
	ss.send(ipc.Credential{Line: bytes.Clone(line)})
	if r := wait(t, done); r.err != nil || r.out != string(line) {
		t.Errorf("the same client's next try: %v, %q", r.err, r.out)
	}
}

// shellHungUp waits for the spawner to tell the stub proto the shell has
// exited, which the idle shell does on SIGHUP.
func (ss *stubSession) shellHungUp(within time.Duration) bool {
	ss.t.Helper()
	ss.proto.File().SetReadDeadline(time.Now().Add(within))
	for {
		m, err := ss.proto.Recv()
		if err != nil {
			return false
		}
		if _, ok := m.(ipc.ShellExit); ok {
			return true
		}
	}
}

// A session detached for the idle timeout has its shell hung up (D8 R4,
// bootstrap.md §9.3): the spawner's wiring of the idle clock, whose rule
// (an attach stops it) TestTheIdleClockRunsOnlyWhileDetachedAndAnAttachStopsIt
// checks on virtual time. The timeout is injected short, and nothing here
// asserts that something did not happen within some real time (D18).
func TestADetachedSessionIsHungUpAfterTheIdleTimeout(t *testing.T) {
	sid := [16]byte{0x5e, 8}
	ss := startStubSessionWith(t, sid, SpawnerConfig{Version: stubVersion, IdleTimeout: 100 * time.Millisecond}, 0)
	ss.send(ipc.Detached{})
	if !ss.shellHungUp(30 * time.Second) {
		t.Fatalf("the idle session's shell was not hung up\nlog:\n%s", ss.log.String())
	}
}

// mosey -kill reaches the spawner over its attach socket and hangs the
// shell up (bootstrap.md §9.5), whether or not a client is attached.
func TestKillHangsTheShellUp(t *testing.T) {
	sid := [16]byte{0x5e, 9}
	ss := startStubSession(t, sid)
	ss.send(ipc.Attached{Credential: [8]byte{1}})
	getenv := func(k string) string {
		if k == "XDG_RUNTIME_DIR" {
			return ss.runtime
		}
		return ""
	}
	if err := Kill(io.Discard, getenv, stubName); err != nil {
		t.Fatal(err)
	}
	if !ss.shellHungUp(30 * time.Second) {
		t.Fatalf("the shell was not hung up\nlog:\n%s", ss.log.String())
	}
}

// The peer check on its own (server.md §2.6): the other end of a
// socketpair is this process, so it is this user and no other.
func TestThePeerCheckPassesThisUserOnlyAndCannotBeFooled(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	if err := samePeer(fds[0]); err != nil {
		t.Errorf("this user: %v", err)
	}
	if err := peerIs(fds[0], os.Getuid()+1); !errors.Is(err, errForeignPeer) {
		t.Errorf("as seen by another user: %v", err)
	}
}

// An accept that fails for a reason that may pass is retried; only the
// socket's closing ends the loop, or the session could never be resumed
// again.
func TestTheAttachLoopOutlivesAFailedAcceptAndEndsWhenClosed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := &spawner{log: discardLog()}
		calls := 0
		s.acceptLoop(func() (*os.File, error) {
			calls++
			switch calls {
			case 1:
				return nil, unix.EMFILE
			case 2:
				return nil, unix.ECONNABORTED
			case 3:
				return nil, errForeignPeer
			}
			return nil, fmt.Errorf("the attach socket: %w", os.ErrClosed)
		})
		if calls != 4 {
			t.Errorf("the loop accepted %d times, not 4", calls)
		}
	})
}

func TestAClosedAttachSocketSaysItIsClosed(t *testing.T) {
	l, err := listenAttach(filepath.Join(runtimeDir(t), "mosey"), [16]byte{0x5e, 6})
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan error, 1)
	go func() {
		_, err := l.Accept()
		got <- err
	}()
	l.Close()
	select {
	case err := <-got:
		if !errors.Is(err, os.ErrClosed) {
			t.Errorf("an Accept blocked on a closing socket: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Accept did not return when the socket closed")
	}
	if _, err := l.Accept(); !errors.Is(err, os.ErrClosed) {
		t.Errorf("an Accept after the close: %v", err)
	}
}
