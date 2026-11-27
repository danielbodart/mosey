package ipc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Conns framed on a SOCK_STREAM pair, as darwin's are (server.md §10).
// These run on Linux too, so the framing on real sockets is tested on
// every host.

func openFDs(t *testing.T) int {
	t.Helper()
	for _, dir := range []string{"/proc/self/fd", "/dev/fd"} {
		if entries, err := os.ReadDir(dir); err == nil {
			return len(entries)
		}
	}
	t.Skip("no /proc/self/fd or /dev/fd")
	return 0
}

func fdOf(f *os.File) uintptr {
	raw, _ := f.SyscallConn()
	var fd uintptr
	raw.Control(func(x uintptr) { fd = x })
	return fd
}

// framedConn wraps f as a framed Conn, whatever this platform's default.
func framedConn(t *testing.T, f *os.File, self, peer Peer) *Conn {
	t.Helper()
	c, err := NewConn(f, self, peer)
	if err != nil {
		t.Fatal(err)
	}
	c.framed = true
	return c
}

func streamPairOf(t *testing.T, a, b Peer) (*Conn, *Conn) {
	t.Helper()
	l, r, err := streamPair()
	if err != nil {
		t.Fatal(err)
	}
	ca, cb := framedConn(t, l, a, b), framedConn(t, r, b, a)
	t.Cleanup(func() { ca.Close(); cb.Close() })
	return ca, cb
}

// rawStream is one end of a stream pair to write raw bytes on, and a
// framed Conn at the other end.
func rawStream(t *testing.T, self, peer Peer) (*os.File, *Conn) {
	t.Helper()
	l, r, err := streamPair()
	if err != nil {
		t.Fatal(err)
	}
	c := framedConn(t, r, self, peer)
	t.Cleanup(func() { l.Close(); c.Close() })
	return l, c
}

func TestFramedMessagesCrossAStreamPairWhole(t *testing.T) {
	proto, emu := streamPairOf(t, Proto, Emu)
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
	// Several of the largest messages at once: more than the socket's
	// buffers hold, so the writer waits and the reader takes them in
	// short reads.
	done := make(chan error, 1)
	go func() {
		for i := range 8 {
			frag := bytes.Repeat([]byte{byte(i)}, MaxFragment)
			if err := emu.Send(Update{More: true, Fragment: frag}); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	for i := range 8 {
		got, err := proto.Recv()
		if err != nil {
			t.Fatal(err)
		}
		u := got.(Update)
		if !u.More || len(u.Fragment) != MaxFragment || u.Fragment[0] != byte(i) || u.Fragment[MaxFragment-1] != byte(i) {
			t.Fatalf("message %d: %d bytes, more %v", i, len(u.Fragment), u.More)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// fds sent with SCM_RIGHTS arrive with the message they were sent with,
// several such messages back to back.
func TestFramedMessagesKeepTheirFDs(t *testing.T) {
	spawner, proto := streamPairOf(t, Spawner, Proto)
	udp, udpPeer, _ := streamPair()
	defer udpPeer.Close()
	pty, ptyPeer, _ := streamPair()
	defer ptyPeer.Close()
	emuEnd, emuPeer, _ := streamPair()
	defer emuPeer.Close()
	before := openFDs(t)
	if err := spawner.Send(Start{Cols: 80, Rows: 24, Port: 60000, ClientPublic: key(), Name: "s", UDP: udp, PTY: pty}); err != nil {
		t.Fatal(err)
	}
	if err := spawner.Send(ShellExit{Status: 1}); err != nil {
		t.Fatal(err)
	}
	if err := spawner.Send(EmuLink{Generation: 1, Conn: emuEnd}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := spawner.Send(AgentConn{Conn: emuEnd}); err != nil {
			t.Fatal(err)
		}
	}
	m, err := proto.Recv()
	if err != nil {
		t.Fatal(err)
	}
	s := m.(Start)
	if _, err := s.PTY.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	ptyPeer.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 8)
	if n, err := ptyPeer.Read(buf); err != nil || n != 1 {
		t.Fatalf("read %d, %v through the received pty end", n, err)
	}
	if fl, _ := unix.FcntlInt(fdOf(s.PTY), unix.F_GETFD, 0); fl&unix.FD_CLOEXEC == 0 {
		t.Error("a received fd is not close-on-exec")
	}
	if m, err := proto.Recv(); err != nil || m.typ() != typeShellExit {
		t.Fatalf("after Start: %v, %v", m, err)
	}
	for i := range 3 {
		m, err := proto.Recv()
		if err != nil {
			t.Fatal(err)
		}
		fs := files(m)
		if (i == 0) != (m.typ() == typeEmuLink) || len(fs) != 1 || fs[0] == nil {
			t.Fatalf("message %d after ShellExit: %+v", i, m)
		}
		fs[0].Close()
	}
	s.UDP.Close()
	s.PTY.Close()
	if after := openFDs(t); after != before {
		t.Errorf("%d fds open, was %d", after, before)
	}
	udp.Close()
	pty.Close()
	emuEnd.Close()
}

// sendRaw sends b on f with fds, as a compromised peer might.
func sendRaw(t *testing.T, f *os.File, b []byte, files ...*os.File) {
	t.Helper()
	var rights []byte
	if len(files) > 0 {
		fds := make([]int, len(files))
		for i, g := range files {
			fds[i] = int(fdOf(g))
		}
		rights = unix.UnixRights(fds...)
	}
	if err := unix.Sendmsg(int(fdOf(f)), b, rights, nil, 0); err != nil {
		t.Fatal(err)
	}
}

func TestAFramedMessageWithTheWrongFDsIsRefusedAndItsFDsClosed(t *testing.T) {
	raw, proto := rawStream(t, Proto, Spawner)
	a, b, _ := streamPair()
	defer a.Close()
	defer b.Close()
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
		sendRaw(t, raw, appendFrame(nil, c.payload), c.files...)
		if _, err := proto.Recv(); !errors.Is(err, ErrMalformed) {
			t.Errorf("%x with %d fds: %v", c.payload, len(c.files), err)
		}
		if after := openFDs(t); after != before {
			t.Errorf("%x with %d fds: %d fds open, was %d", c.payload, len(c.files), after, before)
		}
	}
	// The stream kept its place through each refusal of a whole message.
	sendRaw(t, raw, appendFrame(nil, shellExit))
	if m, err := proto.Recv(); err != nil || m.typ() != typeShellExit {
		t.Fatalf("after the refusals: %v, %v", m, err)
	}
}

// darwin's read(2) would put fds that came into the reader's fd table,
// unseen, so a framed Conn reads with recvmsg even where none may come:
// emu refuses a message with an fd, and keeps none.
func TestAFramedReaderThatExpectsNoFDsKeepsNone(t *testing.T) {
	raw, emu := rawStream(t, Emu, Proto)
	a, b, _ := streamPair()
	defer a.Close()
	defer b.Close()
	before := openFDs(t)
	flush, _ := Marshal(Flush{})
	sendRaw(t, raw, appendFrame(nil, flush), a)
	if _, err := emu.Recv(); !errors.Is(err, ErrMalformed) {
		t.Fatalf("a Flush with an fd: %v", err)
	}
	if after := openFDs(t); after != before {
		t.Fatalf("%d fds open, was %d", after, before)
	}
}

// A length out of bounds is refused before anything is read of the body,
// and the refusal is final: the message after it never arrives, and its
// fds are closed.
func TestAFramedLengthOutOfBoundsIsRefusedForGood(t *testing.T) {
	for _, l := range []uint32{0, MaxMessage + 1, 0xffffffff} {
		raw, proto := rawStream(t, Proto, Spawner)
		a, b, _ := streamPair()
		before := openFDs(t)
		sendRaw(t, raw, binary.BigEndian.AppendUint32(nil, l), a)
		shellExit, _ := Marshal(ShellExit{Status: 1})
		sendRaw(t, raw, appendFrame(nil, shellExit))
		if _, err := proto.Recv(); !errors.Is(err, ErrMalformed) {
			t.Errorf("length %d: %v", l, err)
		}
		if after := openFDs(t); after != before {
			t.Errorf("length %d: %d fds open, was %d", l, after, before)
		}
		if m, err := proto.Recv(); !errors.Is(err, ErrMalformed) {
			t.Errorf("length %d: the next Recv gave %v, %v", l, m, err)
		}
		a.Close()
		b.Close()
	}
}

// A deadline may stop a Recv part-way through a message. The next Recv
// goes on from there, and Pending says a message is on its way meanwhile.
func TestAFramedRecvStoppedPartWayGoesOnFromThere(t *testing.T) {
	raw, proto := rawStream(t, Proto, Emu)
	update, _ := Marshal(Update{Fragment: []byte("the screen")})
	framed := appendFrame(nil, update)
	for _, cut := range []int{2, frameHeader, frameHeader + 3} {
		raw.Write(framed[:cut])
		proto.File().SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		if _, err := proto.Recv(); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("cut at %d: %v", cut, err)
		}
		if !proto.Pending() {
			t.Errorf("cut at %d: Pending says nothing is on its way", cut)
		}
		raw.Write(framed[cut:])
		proto.File().SetReadDeadline(time.Time{})
		m, err := proto.Recv()
		if err != nil {
			t.Fatalf("cut at %d: %v", cut, err)
		}
		if u := m.(Update); string(u.Fragment) != "the screen" {
			t.Fatalf("cut at %d: %q", cut, u.Fragment)
		}
		if proto.Pending() {
			t.Errorf("cut at %d: Pending after the whole message", cut)
		}
	}
}

// A peer that closes part-way through a message is gone (IsEOF), not
// misbehaving: emu killed at its memory limit as it writes is that.
func TestAStreamThatEndsWithinAMessageIsThePeerGone(t *testing.T) {
	for _, recvmsg := range []bool{false, true} {
		self, peer := Proto, Emu
		if recvmsg {
			peer = Spawner
		}
		l, r, _ := streamPair()
		c := framedConn(t, r, self, peer)
		a, b, _ := streamPair()
		before := openFDs(t)
		emuLink, _ := Marshal(EmuLink{Generation: 1})
		sendRaw(t, l, appendFrame(nil, emuLink)[:3], a)
		l.Close()
		if _, err := c.Recv(); !IsEOF(err) {
			t.Errorf("recvmsg %v: %v", recvmsg, err)
		}
		if after := openFDs(t); after != before-1 {
			t.Errorf("recvmsg %v: %d fds open, want %d", recvmsg, after, before-1)
		}
		c.Close()
		a.Close()
		b.Close()
	}
}

func TestAFramedConnSeesEOFWhenThePeerCloses(t *testing.T) {
	raw, emu := rawStream(t, Emu, Proto)
	raw.Close()
	if _, err := emu.Recv(); !IsEOF(err) {
		t.Fatalf("got %v", err)
	}
}

// The attach greeting is a record before the Conn takes over; reading it
// leaves the stream at the first message.
func TestAFramedRecordLeavesTheStreamAtTheNextMessage(t *testing.T) {
	l, r, _ := streamPair()
	defer l.Close()
	launcher := framedConn(t, l, Launcher, Spawner)
	spawner := framedConn(t, r, Spawner, Launcher)
	defer spawner.Close()
	if err := writeRecord(r, []byte("MOSEY-SESSION ..."), true); err != nil {
		t.Fatal(err)
	}
	if err := spawner.Send(Failed{Text: "no"}); err != nil {
		t.Fatal(err)
	}
	if g, err := readRecord(l, 100, true); err != nil || string(g) != "MOSEY-SESSION ..." {
		t.Fatalf("greeting %q, %v", g, err)
	}
	if m, err := launcher.Recv(); err != nil || m.(Failed).Text != "no" {
		t.Fatalf("after the greeting: %v, %v", m, err)
	}
}

// A peer that sends a message a byte at a time, each byte with fds, is
// refused at the second byte, with every fd closed: it cannot fill the
// receiver's fd table before the message ends.
func TestFDsAfterTheFirstByteOfAFramedMessageAreRefused(t *testing.T) {
	raw, proto := rawStream(t, Proto, Spawner)
	a, b, _ := streamPair()
	defer a.Close()
	defer b.Close()
	before := openFDs(t)
	emuLink := appendFrame(nil, []byte{typeEmuLink, 0, 0, 0, 0, 0, 0, 0, 1})
	for i := range emuLink[:frameHeader+2] {
		sendRaw(t, raw, emuLink[i:i+1], a, a, a)
	}
	if _, err := proto.Recv(); !errors.Is(err, ErrMalformed) {
		t.Fatalf("got %v", err)
	}
	if _, err := proto.Recv(); !errors.Is(err, ErrMalformed) {
		t.Fatalf("after the refusal: %v", err)
	}
	// Only the first two sends were read: the rest wait in the socket,
	// and close with it.
	proto.Close()
	raw.Close()
	if after := openFDs(t); after != before-2 {
		t.Errorf("%d fds open, want %d", after, before-2)
	}
}

// The credential line leaves no copy in the frame either.
func TestAFramedRecvKeepsNoCopyOfTheCredentialLine(t *testing.T) {
	spawner, proto := streamPairOf(t, Spawner, Proto)
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
	if !bytes.Equal(spawner.buf, make([]byte, len(spawner.buf))) {
		t.Fatal("the receive buffer still holds the line")
	}
}
