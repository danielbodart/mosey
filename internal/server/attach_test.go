package server

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/danielbodart/mosey/internal/bootstrap"
	"github.com/danielbodart/mosey/internal/ipc"
)

// The attach socket on any platform the server runs on: SOCK_SEQPACKET
// on Linux, framed SOCK_STREAM on darwin (server.md §2.6, §10).

// shortDir is a private directory under /tmp, not $TMPDIR: on macOS
// $TMPDIR is long enough that a session's socket path would not fit in
// sun_path (server.md §10 [M]).
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "mat")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// serveOnce listens like a spawner and runs serve on the first connection.
func serveOnce(t *testing.T, base string, sid [16]byte, serve func(f *os.File)) *attachListener {
	t.Helper()
	l, err := listenAttach(base, sid)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		f, err := l.Accept()
		if err != nil {
			return
		}
		defer f.Close()
		serve(f)
	}()
	return l
}

func TestAnAttachSocketGreetsThenCarriesIPCMessages(t *testing.T) {
	base := filepath.Join(shortDir(t), "mosey")
	sid := [16]byte{0xab, 2}
	greeting := []byte("a greeting, which the launcher reads whole\n")
	got := make(chan error, 1)
	l := serveOnce(t, base, sid, func(f *os.File) {
		if err := ipc.WriteRecord(f, greeting); err != nil {
			got <- err
			return
		}
		conn, _ := ipc.NewConn(f, ipc.Spawner, ipc.Launcher)
		m, err := conn.Recv()
		if err == nil {
			if _, ok := m.(ipc.Hangup); !ok {
				err = errors.New("not a Hangup")
			}
		}
		if err == nil {
			err = conn.Send(ipc.Failed{Text: "no"})
		}
		got <- err
	})
	fi, err := os.Lstat(l.path)
	if err != nil || fi.Mode().Perm() != 0o600 || fi.Mode().Type() != os.ModeSocket {
		t.Fatalf("the socket: %v, %v", fi.Mode(), err)
	}
	f, g, err := dialAttach(sessionDir(base, sid))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if !bytes.Equal(g, greeting) {
		t.Fatalf("greeting %q", g)
	}
	if err := peerIs(int(fdOf(f)), os.Getuid()+1); !errors.Is(err, errForeignPeer) {
		t.Errorf("the peer passed as another user: %v", err)
	}
	conn, _ := ipc.NewConn(f, ipc.Launcher, ipc.Spawner)
	if err := conn.Send(ipc.Hangup{}); err != nil {
		t.Fatal(err)
	}
	m, err := conn.Recv()
	if err != nil || m.(ipc.Failed).Text != "no" {
		t.Fatalf("the answer: %v, %v", m, err)
	}
	if err := <-got; err != nil {
		t.Fatalf("the spawner's side: %v", err)
	}
	l.Close()
	if _, err := os.Lstat(sessionDir(base, sid)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the session's directory is still there: %v", err)
	}
}

func TestAGreetingOverItsBoundIsABadLine(t *testing.T) {
	base := filepath.Join(shortDir(t), "mosey")
	sid := [16]byte{0xab, 3}
	serveOnce(t, base, sid, func(f *os.File) {
		ipc.WriteRecord(f, bytes.Repeat([]byte{'x'}, bootstrap.MaxSessionLine+1))
	})
	f, _, err := dialAttach(sessionDir(base, sid))
	if f != nil {
		f.Close()
	}
	if !errors.Is(err, bootstrap.ErrBadLine) {
		t.Fatalf("got %v", err)
	}
}

func fdOf(f *os.File) uintptr {
	raw, _ := f.SyscallConn()
	var fd uintptr
	raw.Control(func(x uintptr) { fd = x })
	return fd
}
