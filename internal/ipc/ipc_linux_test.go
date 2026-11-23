package ipc

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func pairOf(t *testing.T, a, b Peer) (*Conn, *Conn) {
	t.Helper()
	l, r, err := Pair()
	if err != nil {
		t.Fatal(err)
	}
	ca, err := NewConn(l, a, b)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := NewConn(r, b, a)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ca.Close(); cb.Close() })
	return ca, cb
}

func openFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip("no /proc/self/fd")
	}
	return len(entries)
}

func TestMessagesCrossASocketpairWhole(t *testing.T) {
	proto, emu := pairOf(t, Proto, Emu)
	for _, m := range []Message{Init{Cols: 80, Rows: 24, ScrollbackCells: 1}, Output{Data: []byte("hi")}, Flush{}} {
		if err := proto.Send(m); err != nil {
			t.Fatal(err)
		}
		got, err := emu.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if got.typ() != m.typ() {
			t.Fatalf("got %T, want %T", got, m)
		}
	}
	big := Update{More: true, Fragment: make([]byte, MaxFragment)}
	if err := emu.Send(big); err != nil {
		t.Fatal(err)
	}
	got, err := proto.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if u := got.(Update); !u.More || len(u.Fragment) != MaxFragment {
		t.Fatalf("got %d bytes, more %v", len(u.Fragment), u.More)
	}
}

func TestStartCarriesTheSocketAndThePTYMaster(t *testing.T) {
	spawner, proto := pairOf(t, Spawner, Proto)
	udp, other, _ := Pair()
	defer other.Close()
	pty, ptyPeer, _ := Pair()
	defer ptyPeer.Close()
	before := openFDs(t)
	err := spawner.Send(Start{Cols: 80, Rows: 24, Port: 60000, ClientPublic: key(), Name: "s", UDP: udp, PTY: pty})
	if err != nil {
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
	if openFDs(t) != before+2 {
		t.Fatalf("fds: %d before, %d after", before, openFDs(t))
	}
	// The received pty end works: write through it, read at its peer.
	if _, err := s.PTY.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	ptyPeer.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 8)
	if n, err := ptyPeer.Read(buf); err != nil || n != 1 {
		t.Fatalf("read %d, %v", n, err)
	}
	if fl, _ := unix.FcntlInt(fdOf(s.PTY), unix.F_GETFD, 0); fl&unix.FD_CLOEXEC == 0 {
		t.Error("a received fd is not close-on-exec")
	}
	s.UDP.Close()
	s.PTY.Close()
	udp.Close()
	pty.Close()
}

func fdOf(f *os.File) uintptr {
	raw, _ := f.SyscallConn()
	var fd uintptr
	raw.Control(func(x uintptr) { fd = x })
	return fd
}

// A message that carries the wrong number of fds is refused and every fd
// that came with it is closed, so a compromised peer cannot fill the
// receiver's fd table.
func TestAMessageWithTheWrongFDsIsRefusedAndItsFDsClosed(t *testing.T) {
	spawner, proto := pairOf(t, Spawner, Proto)
	a, b, _ := Pair()
	defer a.Close()
	defer b.Close()
	send := func(payload []byte, files ...*os.File) {
		t.Helper()
		fds := make([]int, len(files))
		for i, f := range files {
			fds[i] = int(fdOf(f))
		}
		var rights []byte
		if len(fds) > 0 {
			rights = unix.UnixRights(fds...)
		}
		if err := unix.Sendmsg(int(fdOf(spawner.File())), payload, rights, nil, 0); err != nil {
			t.Fatal(err)
		}
	}
	shellExit, _ := Marshal(ShellExit{Status: 1})
	emuLink, _ := Marshal(EmuLink{Generation: 1})
	before := openFDs(t)
	for _, c := range []struct {
		payload []byte
		files   []*os.File
	}{
		{shellExit, []*os.File{a}},
		{emuLink, nil},
		{emuLink, []*os.File{a, b}},
		{[]byte{0x7f}, []*os.File{a, b}},
	} {
		send(c.payload, c.files...)
		if _, err := proto.Recv(); !errors.Is(err, ErrMalformed) {
			t.Errorf("%x with %d fds: %v", c.payload, len(c.files), err)
		}
		if after := openFDs(t); after != before {
			t.Errorf("%x with %d fds: %d fds open, was %d", c.payload, len(c.files), after, before)
		}
	}
}

// emu reads with read(2), for which the kernel closes any fds that came
// with a message: nothing reaches it.
func TestAReaderThatExpectsNoFDsKeepsNone(t *testing.T) {
	l, r, _ := Pair()
	emu, _ := NewConn(r, Emu, Proto)
	defer l.Close()
	defer emu.Close()
	a, b, _ := Pair()
	defer a.Close()
	defer b.Close()
	before := openFDs(t)
	out, _ := Marshal(Flush{})
	if err := unix.Sendmsg(int(fdOf(l)), out, unix.UnixRights(int(fdOf(a))), nil, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := emu.Recv(); err != nil {
		t.Fatal(err)
	}
	if after := openFDs(t); after != before {
		t.Fatalf("%d fds open, was %d", after, before)
	}
}

// On an attach socket a message of a later release that may be ignored is
// read past, its fds closed, and the next message is the one Recv returns;
// at most MaxSkipped of them, then the connection is refused (server.md
// §2.8). One of a critical type is refused at once.
func TestRecvReadsPastAnAttachMessageItMayIgnore(t *testing.T) {
	for _, recvmsg := range []bool{true, false} {
		l, r, _ := Pair()
		self, peer := Spawner, Launcher // the spawner reads with recvmsg
		if !recvmsg {
			self, peer = Launcher, Spawner
		}
		c, _ := NewConn(r, self, peer)
		next := []byte{typeHangup}
		if !recvmsg {
			next = []byte{typeFailed, 'n', 'o'}
		}
		for range MaxSkipped {
			l.Write([]byte{0x4c, 9, 9, 9})
		}
		l.Write(next)
		if m, err := c.Recv(); err != nil || m.typ() != next[0] {
			t.Errorf("recvmsg %v: %v, %v", recvmsg, m, err)
		}
		l.Write([]byte{0x48})
		if _, err := c.Recv(); !errors.Is(err, ErrMalformed) {
			t.Errorf("recvmsg %v: one past MaxSkipped: %v", recvmsg, err)
		}
		l.Close()
		c.Close()
	}
	l, r, _ := Pair()
	defer l.Close()
	c, _ := NewConn(r, Spawner, Launcher)
	defer c.Close()
	l.Write([]byte{0x44})
	if _, err := c.Recv(); !errors.Is(err, ErrMalformed) {
		t.Errorf("a critical attach type: %v", err)
	}
}

func TestAMessageOverMaxMessageOnTheWireIsRefused(t *testing.T) {
	for _, recvmsg := range []bool{false, true} {
		l, r, _ := Pair()
		self, peer := Proto, Emu
		if recvmsg {
			self, peer = Proto, Spawner
		}
		c, _ := NewConn(r, self, peer)
		b := make([]byte, MaxMessage+1)
		b[0] = typeUpdate
		if _, err := l.Write(b); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Recv(); !errors.Is(err, ErrMalformed) {
			t.Errorf("recvmsg %v: %v", recvmsg, err)
		}
		l.Close()
		c.Close()
	}
}

func TestEOFWhenThePeerCloses(t *testing.T) {
	for _, peer := range []Peer{Spawner, Emu} {
		l, r, _ := Pair()
		c, _ := NewConn(r, Proto, peer)
		l.Close()
		if _, err := c.Recv(); !errors.Is(err, io.EOF) || !IsEOF(err) {
			t.Errorf("from %s: %v", peer, err)
		}
		c.Close()
	}
}

// A Conn its own process closes is gone, not faulty, whichever way it
// reads: proto closes C on its way out while its C reader may still be in
// Recv (server.md §2.4).
func TestRecvOnAConnClosedHereIsEOF(t *testing.T) {
	for _, self := range []Peer{Proto, Emu} {
		peer := Spawner
		if self == Emu {
			peer = Proto
		}
		_, c := pairOf(t, peer, self)
		c.Close()
		if _, err := c.Recv(); !errors.Is(err, os.ErrClosed) || !IsEOF(err) {
			t.Errorf("%s from %s (recvmsg %v): %v", self, peer, c.recvmsg, err)
		}
	}
}

func TestADeadlineEndsAWaitingRecv(t *testing.T) {
	_, emu := pairOf(t, Proto, Emu)
	emu.File().SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, err := emu.Recv(); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
}

func TestRecvUntilGivesWayToACancelledContext(t *testing.T) {
	_, emu := pairOf(t, Proto, Emu)
	ctx, cancel := context.WithCancelCause(context.Background())
	stopped := errors.New("SIGTERM")
	time.AfterFunc(20*time.Millisecond, func() { cancel(stopped) })
	start := time.Now()
	if _, err := emu.RecvUntil(ctx, time.Now().Add(time.Hour)); !errors.Is(err, stopped) {
		t.Fatalf("got %v, want the context's cause", err)
	}
	if waited := time.Since(start); waited > 10*time.Second {
		t.Fatalf("waited %v for an hour's deadline", waited)
	}
}

func TestRecvUntilStillTimesOutAndThenReadsAgain(t *testing.T) {
	proto, emu := pairOf(t, Proto, Emu)
	if _, err := emu.RecvUntil(context.Background(), time.Now().Add(20*time.Millisecond)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("got %v, want the deadline", err)
	}
	// The deadline is cleared on return: a later Recv waits as long as it
	// takes, here for a message sent after it would have expired.
	time.AfterFunc(50*time.Millisecond, func() { proto.Send(Flush{}) })
	if _, err := emu.Recv(); err != nil {
		t.Fatalf("a Recv after RecvUntil: %v", err)
	}
}

func TestSendRefusesAMessageItsSideDoesNotSend(t *testing.T) {
	proto, _ := pairOf(t, Proto, Emu)
	if err := proto.Send(Update{}); err == nil {
		t.Fatal("proto sent an Update to emu")
	}
}

func TestCheckSeqpacket(t *testing.T) {
	l, r, _ := Pair()
	defer l.Close()
	defer r.Close()
	if err := CheckSeqpacket(int(fdOf(l))); err != nil {
		t.Fatal(err)
	}
	fds, _ := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	if err := CheckSeqpacket(fds[0]); err == nil {
		t.Fatal("a stream socket passed")
	}
	pr, pw, _ := os.Pipe()
	defer pr.Close()
	defer pw.Close()
	if err := CheckSeqpacket(int(fdOf(pr))); err == nil {
		t.Fatal("a pipe passed")
	}
}

// The credential line crosses from proto to the spawner and on to the
// launcher, PSK and all; the receiving Conn's buffer keeps no copy of it
// once Recv has returned (threat-model.md §4.10).
func TestRecvKeepsNoCopyOfTheCredentialLine(t *testing.T) {
	spawner, proto := pairOf(t, Spawner, Proto)
	secret := []byte("MOSEY-CREDENTIAL this-stands-for-the-psk\n")
	if err := proto.Send(Credential{Line: append([]byte(nil), secret...)}); err != nil {
		t.Fatal(err)
	}
	m, err := spawner.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if got := m.(Credential).Line; string(got) != string(secret) {
		t.Fatalf("got %q", got)
	}
	for i, b := range spawner.buf {
		if b != 0 {
			t.Fatalf("the receive buffer still holds byte %#x at %d", b, i)
		}
	}
}
