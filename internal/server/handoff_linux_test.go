package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/danielbodart/mosey/internal/bootstrap"
	"github.com/danielbodart/mosey/internal/ipc"
	"github.com/danielbodart/mosey/internal/screen"
)

// The old side of a live upgrade (server.md §2.8), through a stub
// session's real attach socket and supervision loop, with the test in
// proto's place and in the newer spawner's.

const handoffSessionVersion = "0.1.1"

func startHandoffSession(t *testing.T, sid [16]byte) *stubSession {
	t.Helper()
	return startStubSessionWith(t, sid, SpawnerConfig{Version: handoffSessionVersion}, 0)
}

// ask connects to the session's attach socket as a newer spawner would,
// and sends HandoffRequest from version.
func (ss *stubSession) ask(version string) *ipc.Conn {
	ss.t.Helper()
	f, _, err := dialAttach(sessionDir(filepath.Join(ss.runtime, "mosey"), ss.s.sid))
	if err != nil {
		ss.t.Fatal(err)
	}
	conn, err := ipc.NewConn(f, ipc.Launcher, ipc.Spawner)
	if err != nil {
		ss.t.Fatal(err)
	}
	ss.t.Cleanup(func() { conn.Close() })
	if err := conn.Send(ipc.HandoffRequest{Version: 1, SoftwareVersion: version}); err != nil {
		ss.t.Fatal(err)
	}
	return conn
}

func recvFrom(t *testing.T, conn *ipc.Conn) ipc.Message {
	t.Helper()
	conn.File().SetReadDeadline(time.Now().Add(10 * time.Second))
	m, err := conn.Recv()
	if err != nil {
		t.Fatalf("the attach connection: %v", err)
	}
	return m
}

// protoHearsNothing says the stub proto got no message: nothing was
// frozen.
func (ss *stubSession) protoHearsNothing() bool {
	time.Sleep(100 * time.Millisecond) // a look, not a measurement
	return !ss.proto.Pending()
}

// A hand-off asked from a process of another uid is refused on the attach
// socket before proto is frozen or any fd leaves the spawner.
func TestAHandoffFromAnotherUIDIsRefusedBeforeAnyFDLeaves(t *testing.T) {
	ss := startStubSessionSetUp(t, [16]byte{0x4a, 1}, SpawnerConfig{Version: handoffSessionVersion, IdleTimeout: IdleTimeout}, 0,
		func(s *spawner) { s.peerCheck = func(fd int) error { return peerIs(fd, os.Getuid()+1) } })
	conn := ss.ask("0.2.1")
	m := recvFrom(t, conn)
	if f, ok := m.(ipc.Failed); !ok || !strings.Contains(f.Text, "another user") {
		t.Fatalf("got %#v, not a refusal naming the uid", m)
	}
	if !ss.protoHearsNothing() {
		t.Error("proto was frozen for a foreign peer")
	}
	conn.File().SetReadDeadline(time.Now().Add(10 * time.Second))
	if m, err := conn.Recv(); !ipc.IsEOF(err) {
		t.Errorf("after the refusal: %T %v, not the connection closing", m, err)
	}
}

// Upgrades only go forward (D8 V2): a session refuses to hand itself to
// its own version, an older one, or a version with no order.
func TestASessionRefusesAHandoffToABinaryThatIsNotNewer(t *testing.T) {
	ss := startHandoffSession(t, [16]byte{0x4a, 2})
	for _, v := range []string{handoffSessionVersion, "0.1.0", "0.0.9", "dev"} {
		m := recvFrom(t, ss.ask(v))
		if f, ok := m.(ipc.Failed); !ok || !strings.Contains(f.Text, "not newer") {
			t.Errorf("a hand-off to %s: %#v", v, m)
		}
	}
	if !ss.protoHearsNothing() {
		t.Error("proto was frozen for an older binary")
	}
}

// snapshotOf is a small screen as proto would send it.
func snapshotOf(text string) []byte {
	g := screen.NewGrid(20, 3)
	for i, r := range text {
		g.SetCell(i, 0, screen.Cell{Text: string(r), Width: 1})
	}
	return g.Diff(screen.NewGrid(0, 0))
}

// freezeAndAnswer plays proto: it expects Freeze and answers with diff.
func (ss *stubSession) freezeAndAnswer(diff []byte) {
	ss.t.Helper()
	if m := ss.recv(); m != (ipc.Freeze{}) {
		ss.t.Fatalf("proto got %T, not Freeze", m)
	}
	ss.send(ipc.Snapshot{Fragment: diff})
}

// The state a newer spawner is sent: the session's id, name and size,
// the shell's pid with a pidfd for it, the pty master and the attach
// listener, and the screen proto froze. Then, if it never says it took
// the session, proto is thawed and the session goes on as it was.
func TestAHandoffThatIsNotTakenThawsProtoAndTheSessionGoesOn(t *testing.T) {
	sid := [16]byte{0x4a, 3}
	ss := startHandoffSession(t, sid)
	conn := ss.ask("0.2.1")
	diff := snapshotOf("frozen")
	ss.freezeAndAnswer(diff)

	st, ok := recvFrom(t, conn).(ipc.HandoffState)
	if !ok {
		t.Fatal("no HandoffState")
	}
	defer st.PTY.Close()
	defer st.Pidfd.Close()
	defer st.Listener.Close()
	if st.SessionID != sid || st.Name != stubName || st.Cols != 20 || st.Rows != 3 ||
		int(st.ShellPID) != ss.s.shell.pid() || int(st.ScreenLen) != len(diff) || st.Agent {
		t.Errorf("state %+v", st)
	}
	if pid, err := pidfdPid(int(st.Pidfd.Fd())); err != nil || pid != ss.s.shell.pid() {
		t.Errorf("the pidfd names %d (%v), not the shell %d", pid, err, ss.s.shell.pid())
	}
	if err := checkListener(st.Listener, ss.s.attach.path, 5 /* SOCK_SEQPACKET */); err != nil {
		t.Errorf("the attach listener: %v", err)
	}
	if sc, ok := recvFrom(t, conn).(ipc.HandoffScreen); !ok || sc.More || string(sc.Fragment) != string(diff) {
		t.Errorf("the screen: %#v", sc)
	}

	conn.Close() // the newer spawner gives up
	if m := ss.recv(); m != (ipc.Thaw{}) {
		t.Fatalf("proto got %T, not Thaw", m)
	}
	// The session still answers, and serves a resume as before.
	public, done := ss.launch(sid)
	if r := ss.recvResume(); string(r.ClientPublic) != string(public) {
		t.Error("the resume after the abandoned hand-off went astray")
	}
	cred := credential(t, sid, 9)
	cred.SoftwareVersion = handoffSessionVersion
	ss.send(ipc.Credential{Line: bootstrap.MarshalCredentialLine(cred)})
	if r := wait(t, done); r.err != nil {
		t.Fatalf("a resume after an abandoned hand-off: %v\nlog:\n%s", r.err, ss.log.String())
	}
}

// Once the newer spawner says it took the session, the old one goes:
// proto is told (EOF on its control socket), the spawner exits, the
// connection closes only then, and neither the shell nor the attach
// socket is touched: they are the newer spawner's.
func TestATakenHandoffLeavesTheShellAndTheSocketToTheNewerSpawner(t *testing.T) {
	sid := [16]byte{0x4a, 4}
	ss := startHandoffSession(t, sid)
	shell := ss.s.shell
	t.Cleanup(func() { shell.signal(9) })
	path := ss.s.attach.path
	conn := ss.ask("0.2.1")
	ss.freezeAndAnswer(snapshotOf("taken"))
	st := recvFrom(t, conn).(ipc.HandoffState)
	defer st.PTY.Close()
	defer st.Pidfd.Close()
	defer st.Listener.Close()
	recvFrom(t, conn) // the screen
	if err := conn.Send(ipc.HandoffTaken{}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ss.ended:
	case <-time.After(30 * time.Second):
		t.Fatalf("the old spawner did not go\nlog:\n%s", ss.log.String())
	}
	conn.File().SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Recv(); !ipc.IsEOF(err) {
		t.Errorf("the connection after the hand-off: %v", err)
	}
	select {
	case <-shell.done:
		t.Fatal("the shell ended with the old spawner")
	default:
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the attach socket went with the old spawner: %v", err)
	}
	if !strings.Contains(ss.log.String(), "handed the session over") {
		t.Errorf("the log does not say so:\n%s", ss.log.String())
	}
}

// The newer side checks the uid of the session it is about to adopt (the
// process that made the attach listener) and asks nothing of one that is
// not this user's.
func TestAnAdopterAsksNothingOfASessionOfAnotherUID(t *testing.T) {
	ours, theirs, err := ipc.Pair()
	if err != nil {
		t.Fatal(err)
	}
	defer theirs.Close()
	attach, _ := ipc.NewConn(ours, ipc.Launcher, ipc.Spawner)
	defer attach.Close()
	session, _ := ipc.NewConn(theirs, ipc.Spawner, ipc.Launcher)
	s := newSpawner(SpawnerConfig{Version: "0.2.1"})
	s.peerCheck = func(fd int) error { return peerIs(fd, os.Getuid()+1) }
	if _, err := s.requestHandoff(attach, [16]byte{1}); err == nil || !strings.Contains(err.Error(), "another user") {
		t.Fatalf("got %v", err)
	}
	if session.Pending() {
		t.Error("the adopter asked a foreign session for its state")
	}
}

// The launcher upgrades a session only when it is newer than the session
// (bootstrap.md §9.2 step 5): equal, older and unordered versions attach
// as they are, so a session never goes back to an older binary.
func TestTheLauncherUpgradesOnlyASessionOfAnOlderVersion(t *testing.T) {
	for _, c := range []struct {
		launcher, session string
		want              bool
	}{
		{"0.2.1", "0.1.1", true},
		{"0.2.1", "0.2.1", false},
		{"0.1.1", "0.2.1", false}, // an older launcher never downgrades
		{"dev", "0.1.1", false},
		{"0.2.1", "dev", false},
	} {
		l := &Launcher{Version: c.launcher, Self: "/mosey"}
		if got := l.upgrades(bootstrap.SessionLine{SoftwareVersion: c.session}); got != c.want {
			t.Errorf("a %s launcher and a %s session: upgrade %v", c.launcher, c.session, got)
		}
	}
}
