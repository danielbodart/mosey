package server

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// The agent socket is the user's alone (server.md §2.7): 0600 in the
// session's private directory, refused in one that is not private, and
// each connection it accepts comes out non-blocking, for proto to wrap
// inside its sandbox.
func TestTheAgentSocketIsPrivateAndHandsOutNonBlockingConnections(t *testing.T) {
	dir := filepath.Join(runtimeDir(t), "s")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	l, err := listenAgent(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	fi, err := os.Stat(l.path)
	if err != nil || fi.Mode().Perm() != 0o600 || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("the socket: %v %v", fi, err)
	}
	c, err := net.Dial("unix", l.path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	f, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	raw, _ := f.SyscallConn()
	var flags int
	raw.Control(func(fd uintptr) { flags, _ = unix.FcntlInt(fd, unix.F_GETFL, 0) })
	if flags&unix.O_NONBLOCK == 0 {
		t.Error("the accepted connection is blocking")
	}
	l.Close()
	if _, err := os.Stat(l.path); !os.IsNotExist(err) {
		t.Error("the socket outlived Close")
	}
	if _, err := l.Accept(); !errors.Is(err, os.ErrClosed) {
		t.Errorf("Accept after Close: %v", err)
	}

	open := filepath.Join(runtimeDir(t), "open")
	os.Mkdir(open, 0o755)
	if l, err := listenAgent(open); err == nil {
		l.Close()
		t.Error("listened in a directory others can enter")
	}
}

// Only nothing at all at the attester's path is "no attester": anything
// there, or anything that cannot be checked, fails closed (agent.md §4.3).
func TestAnythingAtTheAttesterPathCountsAsAnAttester(t *testing.T) {
	dir := t.TempDir()
	if attesterPresent(filepath.Join(dir, "absent")) {
		t.Error("nothing there is an attester")
	}
	there := filepath.Join(dir, "handoff.sock")
	os.WriteFile(there, nil, 0o600)
	if !attesterPresent(there) {
		t.Error("a file there is not an attester")
	}
	if _, err := handOff(nil); err == nil {
		t.Error("the unimplemented hand-off succeeded")
	}
}

// Teardown leaves nothing of an agent session behind: the session's
// directory goes with both its sockets (server.md §2.7, agent.md §4.1), so
// empty directories do not pile up under the sessions directory.
func TestTeardownRemovesTheDirectoryOfASessionWithTheAgent(t *testing.T) {
	base := filepath.Join(runtimeDir(t), "mosey")
	s := &spawner{log: discardLog()}
	var err error
	if s.attach, err = listenAttach(base, [16]byte{1}); err != nil {
		t.Fatal(err)
	}
	if s.agent, err = listenAgent(s.attach.dir); err != nil {
		t.Fatal(err)
	}
	s.agentDone = make(chan struct{})
	s.teardown("test")
	if _, err := os.Stat(s.attach.dir); !os.IsNotExist(err) {
		t.Errorf("the session's directory outlived teardown: %v", err)
	}
}
