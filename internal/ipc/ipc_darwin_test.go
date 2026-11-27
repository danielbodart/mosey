package ipc

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// On darwin, Pair is a framed SOCK_STREAM pair (server.md §10).
func TestPairOnDarwinIsAFramedStreamPair(t *testing.T) {
	l, r, err := Pair()
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	defer r.Close()
	if err := CheckSocket(int(fdOf(l))); err != nil {
		t.Fatal(err)
	}
	if fl, _ := unix.FcntlInt(fdOf(l), unix.F_GETFD, 0); fl&unix.FD_CLOEXEC == 0 {
		t.Error("a Pair end is not close-on-exec")
	}
	spawner, err := NewConn(l, Spawner, Proto)
	if err != nil {
		t.Fatal(err)
	}
	proto, err := NewConn(r, Proto, Spawner)
	if err != nil {
		t.Fatal(err)
	}
	if !spawner.framed || !proto.framed {
		t.Fatal("a darwin Conn is not framed")
	}
	udp, udpPeer, _ := Pair()
	defer udpPeer.Close()
	pty, ptyPeer, _ := Pair()
	defer ptyPeer.Close()
	if err := spawner.Send(Start{Cols: 80, Rows: 24, Port: 60000, ClientPublic: key(), Name: "s", UDP: udp, PTY: pty}); err != nil {
		t.Fatal(err)
	}
	m, err := proto.Recv()
	if err != nil {
		t.Fatal(err)
	}
	s := m.(Start)
	if s.UDP == nil || s.PTY == nil {
		t.Fatal("files missing")
	}
	s.UDP.Close()
	s.PTY.Close()
	udp.Close()
	pty.Close()
}

func TestCheckSocketTakesOnlyAStreamSocketOnDarwin(t *testing.T) {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := CheckSocket(fd); err == nil {
		t.Fatal("a datagram socket passed")
	}
	pr, pw, _ := os.Pipe()
	defer pr.Close()
	defer pw.Close()
	if err := CheckSocket(int(fdOf(pr))); err == nil {
		t.Fatal("a pipe passed")
	}
}
