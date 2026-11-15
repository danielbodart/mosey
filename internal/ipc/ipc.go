package ipc

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// Conn is one end of a seqpacket socketpair, made for one peer.
//
// Send and Recv may be called from different goroutines; each from one at
// a time.
type Conn struct {
	f          *os.File
	raw        syscall.RawConn
	self, peer Peer
	// recvmsg is whether Recv reads with recvmsg, to take and close fds,
	// or with read, for which the kernel discards any that come
	// (server.md §3.1, "Who reads with what").
	recvmsg bool
	buf     []byte
}

// NewConn wraps f, one end of a SOCK_SEQPACKET pair, as self's connection
// to peer. f should be non-blocking (Pair's and Wrap's are), so reads can
// have deadlines. It makes no syscall a sandboxed role is denied.
func NewConn(f *os.File, self, peer Peer) (*Conn, error) {
	raw, err := f.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("ipc: wrapping %s: %w", f.Name(), err)
	}
	return &Conn{
		f: f, raw: raw, self: self, peer: peer,
		// The end that connected to an attach socket (Launcher) may be
		// sent HandoffState's fds (server.md §2.8).
		recvmsg: self == Spawner || self == Launcher || (self == Proto && peer == Spawner),
		// One more than the largest message, so one that fills the buffer
		// is known to be too long rather than cut.
		buf: make([]byte, MaxMessage+1),
	}, nil
}

// File is the underlying socket, for deadlines.
func (c *Conn) File() *os.File { return c.f }

// Pair makes a connected socketpair, close-on-exec and non-blocking on
// both ends: one end for this process, one to pass to a child, where
// exec.Cmd.ExtraFiles clears close-on-exec on the child's copy only.
func Pair() (local, remote *os.File, err error) {
	return pair()
}

// Wrap makes fd, inherited or received, a pollable *os.File: it sets
// O_NONBLOCK with fcntl (F_GETFL, F_SETFL, both in every role's policy)
// rather than trust the sender to have, then os.NewFile registers it with
// the poller. Never net.FileConn, whose getsockopt, getsockname and
// getpeername no sandbox allows (server.md §3.6).
func Wrap(fd int, name string) (*os.File, error) {
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("ipc: making %s non-blocking: %w", name, err)
	}
	return os.NewFile(uintptr(fd), name), nil
}

// CheckSeqpacket says whether fd is a SOCK_SEQPACKET socket. Roles call it
// on the fd they were started with, before their sandbox, which denies
// getsockopt.
func CheckSeqpacket(fd int) error {
	t, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil {
		return fmt.Errorf("ipc: fd %d is not a socket: %w", fd, err)
	}
	if t != unix.SOCK_SEQPACKET {
		return fmt.Errorf("ipc: fd %d is a socket of type %d, not SOCK_SEQPACKET", fd, t)
	}
	return nil
}

// Send sends m, with its fds attached if it carries any. Only the spawner
// and the launcher (Adopt) send fds, and with sendmsg; everything else is
// one write(2), which is all proto's and emu's policies allow.
func (c *Conn) Send(m Message) error {
	r := routes[m.typ()]
	if r.from != c.self || r.to != c.peer {
		return fmt.Errorf("ipc: %s does not send %T to %s", c.self, m, c.peer)
	}
	b, err := Marshal(m)
	if err != nil {
		return err
	}
	// Credential and Ready carry the credential line, PSK and all: no
	// copy of it outlives the send (threat-model.md §4.10).
	defer clear(b)
	fs := files(m)
	if len(fs) == 0 {
		_, err := c.f.Write(b)
		return err
	}
	fds := make([]int, len(fs))
	for i, f := range fs {
		if f == nil {
			return fmt.Errorf("ipc: %T is missing a file", m)
		}
		raw, err := f.SyscallConn()
		if err != nil {
			return err
		}
		// Control, not Fd: Fd would switch a non-blocking file to
		// blocking mode, and the description is shared with whoever gets
		// the fd (server.md §2.3).
		raw.Control(func(fd uintptr) { fds[i] = int(fd) })
	}
	rights := unix.UnixRights(fds...)
	var serr error
	err = c.raw.Write(func(fd uintptr) bool {
		serr = unix.Sendmsg(int(fd), b, rights, nil, 0)
		return serr != unix.EAGAIN
	})
	// The files must stay open, and so their fds valid, until sendmsg has
	// copied them into the message.
	runtime.KeepAlive(fs)
	if err != nil {
		return err
	}
	return serr
}

// Recv receives the next message from the peer. io.EOF means the peer has
// closed its end. A message that fails to parse, comes from the wrong
// direction, or carries the wrong number of fds is refused with an error
// wrapping ErrMalformed, and every fd that came with it is closed.
func (c *Conn) Recv() (Message, error) {
	n, fds, err := c.read()
	if err != nil {
		return nil, err
	}
	closeAll := func() {
		for _, fd := range fds {
			unix.Close(fd)
		}
	}
	if n > MaxMessage {
		closeAll()
		return nil, malformed("over %d bytes", MaxMessage)
	}
	m, err := Parse(c.peer, c.self, c.buf[:n])
	want := routes[c.buf[0]].fds
	// Parse copies what it keeps; the buffer may have held the credential
	// line, which is wiped as soon as it is read (threat-model.md §4.10).
	clear(c.buf[:n])
	if err != nil {
		closeAll()
		return nil, err
	}
	if len(fds) != want {
		closeAll()
		return nil, malformed("%T came with %d fds, not %d", m, len(fds), want)
	}
	if want == 0 {
		return m, nil
	}
	fs := make([]*os.File, len(fds))
	for i, fd := range fds {
		f, err := Wrap(fd, fmt.Sprintf("fd from %s", c.peer))
		if err != nil {
			for _, g := range fs[:i] {
				g.Close()
			}
			for _, fd := range fds[i:] {
				unix.Close(fd)
			}
			return nil, err
		}
		fs[i] = f
	}
	return withFiles(m, fs), nil
}

// read reads one message into c.buf, with any fds that came with it.
func (c *Conn) read() (n int, fds []int, err error) {
	if !c.recvmsg {
		n, err = c.f.Read(c.buf)
		return n, nil, err
	}
	oob := make([]byte, unix.CmsgSpace(4*4))
	var oobn, flags int
	var rerr error
	err = c.raw.Read(func(fd uintptr) bool {
		n, oobn, flags, _, rerr = unix.Recvmsg(int(fd), c.buf, oob, recvFlags)
		return rerr != unix.EAGAIN
	})
	if err == nil {
		err = rerr
	}
	if err != nil {
		return 0, nil, err
	}
	if oobn > 0 {
		cmsgs, perr := unix.ParseSocketControlMessage(oob[:oobn])
		if perr != nil {
			return 0, nil, malformed("control message: %v", perr)
		}
		for _, cm := range cmsgs {
			got, perr := unix.ParseUnixRights(&cm)
			if perr != nil {
				continue
			}
			fds = append(fds, got...)
		}
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		for _, fd := range fds {
			unix.Close(fd)
		}
		return 0, nil, malformed("truncated (flags %#x)", flags)
	}
	if n == 0 && len(fds) == 0 {
		// recvmsg cannot tell an empty message from a closed peer, and an
		// empty message is never valid, so both end the conversation.
		return 0, nil, io.EOF
	}
	return n, fds, nil
}

// Pending says whether a message is waiting, without taking it: proto
// asks before each emu request, because emu never speaks unasked and a
// message while idle is a violation (server.md §3.5). It peeks with
// recvmsg, which proto's policy has.
func (c *Conn) Pending() bool {
	var pending bool
	c.raw.Control(func(fd uintptr) {
		var b [1]byte
		n, _, _, _, err := unix.Recvmsg(int(fd), b[:], nil, unix.MSG_PEEK|unix.MSG_DONTWAIT)
		// A peer that closed reads as 0 with no error: that is EOF, not a
		// message, and the next Recv reports it.
		pending = err == nil && n > 0
	})
	return pending
}

// Close closes the socket. A Recv blocked on it returns an error.
func (c *Conn) Close() error { return c.f.Close() }

// IsEOF says whether err means the peer is gone rather than misbehaving.
func IsEOF(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, unix.ECONNRESET) || errors.Is(err, os.ErrClosed)
}
