package ipc

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Conn is one end of a socketpair, made for one peer: SOCK_SEQPACKET on
// Linux, SOCK_STREAM with each message framed on darwin (server.md §3.1,
// §10).
//
// Send and Recv may be called from different goroutines; each from one at
// a time.
type Conn struct {
	f          *os.File
	raw        syscall.RawConn
	self, peer Peer
	// recvmsg is whether Recv reads with recvmsg, to take and close fds,
	// or with read, for which the kernel discards any that come
	// (server.md §3.1, "Who reads with what"). A framed Conn always reads
	// with recvmsg (readFramed).
	recvmsg bool
	// framed is whether each message has its length before it, on a
	// stream socket (frame.go); fr is where the read of one stands.
	framed bool
	// frMu is held while a Recv reads a framed message, so Close can
	// close the fds of a message part-read when a deadline stopped it.
	frMu sync.Mutex
	fr   frameReader
	buf  []byte
	oob  []byte // control data of one recvmsg
	// skipped counts the attach messages of unknown, ignorable types
	// Recv has read past (server.md §2.8).
	skipped int
}

// NewConn wraps f, one end of a pair Pair makes or an attach socket
// connection, as self's connection to peer. f should be non-blocking
// (Pair's and Wrap's are), so reads can have deadlines. It makes no
// syscall a sandboxed role is denied.
func NewConn(f *os.File, self, peer Peer) (*Conn, error) {
	raw, err := f.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("ipc: wrapping %s: %w", f.Name(), err)
	}
	return &Conn{
		f: f, raw: raw, self: self, peer: peer,
		recvmsg: self == Spawner || (self == Proto && peer == Spawner),
		framed:  framedIPC,
		// One more than the largest message, so one that fills the buffer
		// is known to be too long rather than cut.
		buf: make([]byte, MaxMessage+1),
		oob: make([]byte, controlSpace),
	}, nil
}

// controlSpace is the room for the control data of one recvmsg. It holds
// every fd one sendmsg can carry: 254 on darwin, where 255 gets EINVAL
// [M: dan-mac, 2026-11-27], and SCM_MAX_FD, 253, on Linux [kernel ABI].
// It must: darwin puts every fd of a message into the reader's fd table
// even when the buffer is too small for them, and returns only the
// numbers that fit, so the rest could never be closed (server.md §10
// [M]). darwin keeps a message's control data in one 2048-byte mbuf
// cluster, 8 bytes for each fd [derived: 254 fds is the most that fits],
// and gives the reader 4 bytes for each, so 4096 bytes is room for them
// in any number of control messages.
const controlSpace = 4096

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

// CheckSocket says whether fd is a socket of the type this platform's IPC
// uses: SOCK_SEQPACKET on Linux, SOCK_STREAM on darwin. Roles call it on
// the fd they were started with, before their sandbox, which denies
// getsockopt.
func CheckSocket(fd int) error {
	t, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil {
		return fmt.Errorf("ipc: fd %d is not a socket: %w", fd, err)
	}
	if t != sockType {
		return fmt.Errorf("ipc: fd %d is a socket of type %d, not %d", fd, t, sockType)
	}
	return nil
}

// WriteRecord sends b as one record that is not an IPC message: the
// attach socket's greeting (server.md §2.6). On Linux it is one seqpacket
// message; on darwin it is framed as a message is.
func WriteRecord(f *os.File, b []byte) error { return writeRecord(f, b, framedIPC) }

func writeRecord(f *os.File, b []byte, framed bool) error {
	if framed {
		b = appendFrame(make([]byte, 0, frameHeader+len(b)), b)
	}
	_, err := f.Write(b)
	return err
}

// ReadRecord reads one record that WriteRecord sent, of at most max
// bytes. A longer one is refused with an error that wraps ErrMalformed. It
// reads no byte past the record, so a Conn can take over f after it.
func ReadRecord(f *os.File, max int) ([]byte, error) { return readRecord(f, max, framedIPC) }

func readRecord(f *os.File, max int, framed bool) ([]byte, error) {
	if !framed {
		// One seqpacket message, read whole: a buffer one byte over the
		// bound tells a long one from one that fits.
		buf := make([]byte, max+1)
		n, err := f.Read(buf)
		if err != nil {
			return nil, err
		}
		if n > max {
			return nil, malformed("a record over %d bytes", max)
		}
		return buf[:n], nil
	}
	// recvmsg, not read: darwin's read(2) would put any fds that came
	// into this process's fd table, unseen (server.md §3.1). None may
	// come with a record.
	raw, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}
	oob := make([]byte, controlSpace)
	readFull := func(p []byte, start bool) error {
		for len(p) > 0 {
			n, fds, err := recvmsgRaw(raw, p, oob, "the record's sender")
			if err != nil {
				return err
			}
			if len(fds) > 0 {
				closeFDs(fds)
				return malformed("a record came with %d fds", len(fds))
			}
			if n == 0 {
				if start {
					return io.EOF
				}
				return io.ErrUnexpectedEOF
			}
			p, start = p[n:], false
		}
		return nil
	}
	var hdr [frameHeader]byte
	if err := readFull(hdr[:], true); err != nil {
		return nil, err
	}
	// Bounded before the allocation: the length is the peer's word.
	l := binary.BigEndian.Uint32(hdr[:])
	if l == 0 || l > uint32(max) {
		return nil, malformed("a framed record of %d bytes is not in 1..%d", l, max)
	}
	buf := make([]byte, l)
	if err := readFull(buf, false); err != nil {
		return nil, err
	}
	return buf, nil
}

// Send sends m, with its fds attached if it carries any. Only the spawner
// sends fds, and with sendmsg; everything else is one write(2), which is
// all proto's and emu's policies allow.
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
	if c.framed {
		framed := appendFrame(make([]byte, 0, frameHeader+len(b)), b)
		defer clear(framed)
		b = framed
	}
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
	var n int
	err = c.raw.Write(func(fd uintptr) bool {
		n, serr = unix.SendmsgN(int(fd), b, rights, nil, 0)
		return serr != unix.EAGAIN
	})
	// The files must stay open, and so their fds valid, until sendmsg has
	// copied them into the message.
	runtime.KeepAlive(fs)
	if err != nil {
		return err
	}
	if serr != nil {
		return serr
	}
	if n < len(b) {
		// Only a stream socket sends part of a message. The fds went
		// with its first bytes, where the receiver looks for them
		// (frame.go); the rest follows as plain bytes.
		_, err = c.f.Write(b[n:])
	}
	return err
}

// Recv receives the next message from the peer. io.EOF means the peer has
// closed its end. A message that fails to parse, comes from the wrong
// direction, or carries the wrong number of fds is refused with an error
// wrapping ErrMalformed, and every fd that came with it is closed. An
// attach message of a type this build does not know, whose type says it
// may be ignored, is read past, with its fds closed, at most MaxSkipped
// times on one connection (server.md §2.8). On a framed Conn, a refused
// length is final: the stream has lost its place, so every later Recv
// refuses too.
func (c *Conn) Recv() (Message, error) {
	for {
		m, err := c.recv()
		if !errors.Is(err, ErrSkipped) {
			return m, err
		}
		if c.skipped++; c.skipped > MaxSkipped {
			return nil, malformed("more than %d attach messages this build does not know", MaxSkipped)
		}
	}
}

// RecvUntil is Recv bounded twice: by deadline, the time a slow or hung
// peer is given, and by ctx, which cmd/mosey cancels on SIGTERM. Whichever
// comes first ends the wait, and a cancelled ctx returns its cause, so a
// process told to stop never sits out a timeout meant for its peer
// (server.md §2.4, "Every wait gives way to SIGTERM"). The deadline is
// cleared on return, unless ctx was cancelled: the wake can then land at
// any moment, so the deadline is left in the past rather than cleared
// under it. A message received as ctx was cancelled is dropped, fds and
// all. Waking a read is only a deadline, so this makes no syscall a
// sandboxed role is denied.
func (c *Conn) RecvUntil(ctx context.Context, deadline time.Time) (Message, error) {
	if err := c.f.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { c.f.SetReadDeadline(time.Unix(1, 0)) })
	m, err := c.Recv()
	if !stop() {
		if m != nil {
			CloseFiles(m)
		}
		return nil, context.Cause(ctx)
	}
	c.f.SetReadDeadline(time.Time{})
	return m, err
}

func (c *Conn) recv() (Message, error) {
	n, fds, err := c.read()
	if err != nil {
		return nil, err
	}
	if n > MaxMessage {
		closeFDs(fds)
		return nil, malformed("over %d bytes", MaxMessage)
	}
	m, err := Parse(c.peer, c.self, c.buf[:n])
	want := routes[c.buf[0]].fds
	// Parse copies what it keeps; the buffer may have held the credential
	// line, which is wiped as soon as it is read (threat-model.md §4.10).
	clear(c.buf[:n])
	if err != nil {
		closeFDs(fds)
		return nil, err
	}
	if len(fds) != want {
		closeFDs(fds)
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
			closeFDs(fds[i:])
			return nil, err
		}
		fs[i] = f
	}
	return withFiles(m, fs), nil
}

// CloseFiles closes every fd m carries. Recv hands the fds of a message
// it accepts to the caller, so a caller that refuses a well-formed message
// because it is not the one the protocol expects next closes them with
// this, as server.md §3.1 says every receiver does: otherwise a peer could
// fill the receiver's fd table one unexpected message at a time.
func CloseFiles(m Message) {
	for _, f := range files(m) {
		if f != nil {
			f.Close()
		}
	}
}

// closeFDs closes fds that were received and not handed on.
func closeFDs(fds []int) {
	for _, fd := range fds {
		unix.Close(fd)
	}
}

// read reads one message into c.buf, with any fds that came with it.
func (c *Conn) read() (n int, fds []int, err error) {
	if c.framed {
		return c.readFramed()
	}
	if !c.recvmsg {
		n, err = c.f.Read(c.buf)
		return n, nil, err
	}
	n, fds, err = c.recvmsgInto(c.buf)
	if err != nil {
		return 0, nil, err
	}
	if n == 0 && len(fds) == 0 {
		// recvmsg cannot tell an empty message from a closed peer, and an
		// empty message is never valid, so both end the conversation.
		return 0, nil, io.EOF
	}
	return n, fds, nil
}

// readFramed reads one framed message into c.buf, in as many reads as the
// stream needs, each within the message (frame.go). A deadline may stop
// it part-way; the next call goes on from there, and Close closes the
// fds of the part read.
func (c *Conn) readFramed() (int, []int, error) {
	c.frMu.Lock()
	defer c.frMu.Unlock()
	if c.fr.err != nil {
		return 0, nil, c.fr.err
	}
	for {
		// Always recvmsg, even where no fds are allowed in: darwin's
		// read(2) puts any fds that came into this process's fd table,
		// where nothing would ever close them (server.md §10 [M]).
		// recvmsg hands them over, and recv closes them.
		n, fds, err := c.recvmsgInto(c.fr.next(c.buf))
		if errors.Is(err, ErrMalformed) {
			// The bytes of this read are gone with its fds: the stream
			// has lost its place.
			c.fr.err = err
			closeFDs(c.fr.take())
			return 0, nil, err
		}
		if err != nil {
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				// The connection is gone (closed here, or reset), so
				// the rest of the message will not come: close the fds
				// of its part that did. Only a deadline is resumed.
				c.fr.err = err
				closeFDs(c.fr.take())
			}
			return 0, nil, err
		}
		size, mfds, done, err := c.fr.add(n, fds)
		if err != nil {
			closeFDs(mfds)
			return 0, nil, err
		}
		if done {
			return size, mfds, nil
		}
	}
}

// recvmsgInto reads into p with recvmsg, and returns the fds that came,
// close-on-exec. A read flagged truncated is refused and its fds closed.
func (c *Conn) recvmsgInto(p []byte) (n int, fds []int, err error) {
	return recvmsgRaw(c.raw, p, c.oob, c.peer.String())
}

// recvmsgRaw is recvmsgInto on any socket, with oob for the control data
// and from naming the peer in errors.
func recvmsgRaw(raw syscall.RawConn, p, oob []byte, from string) (n int, fds []int, err error) {
	var oobn, flags int
	var rerr error
	err = raw.Read(func(fd uintptr) bool {
		if !recvCloexec {
			// No MSG_CMSG_CLOEXEC: the fds are made close-on-exec under
			// ForkLock, as the net package does for accept, so no child
			// forked meanwhile inherits one.
			syscall.ForkLock.RLock()
			defer syscall.ForkLock.RUnlock()
		}
		n, oobn, flags, _, rerr = unix.Recvmsg(int(fd), p, oob, recvFlags)
		if !recvCloexec && rerr == nil && oobn > 0 {
			cloexecRights(oob[:oobn])
		}
		return rerr != unix.EAGAIN
	})
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		// RawConn.Read fails on its own only for a deadline or a file
		// closed under it, and reports the second as the poller's "use of
		// closed file", which os.File.Read would have called os.ErrClosed.
		// It is os.ErrClosed here too, so a reader whose Conn is closed
		// by its own process sees IsEOF, not a fault.
		return 0, nil, fmt.Errorf("ipc: receiving from %s: %w (%v)", from, os.ErrClosed, err)
	}
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
		closeFDs(fds)
		return 0, nil, malformed("truncated (flags %#x)", flags)
	}
	return n, fds, nil
}

// cloexecRights sets close-on-exec on every fd in the control messages of
// oob.
func cloexecRights(oob []byte) {
	cmsgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return
	}
	for _, cm := range cmsgs {
		if fds, err := unix.ParseUnixRights(&cm); err == nil {
			for _, fd := range fds {
				unix.CloseOnExec(fd)
			}
		}
	}
}

// Pending says whether a message is waiting, without taking it: proto
// asks before each emu request, because emu never speaks unasked and a
// message while idle is a violation (server.md §3.5). It peeks with
// recvmsg, which proto's policy has. Ask it between Recvs, from the
// goroutine that calls Recv: on a framed Conn it waits for a Recv in
// progress to end.
func (c *Conn) Pending() bool {
	if c.framed {
		c.frMu.Lock()
		started := c.fr.started()
		c.frMu.Unlock()
		if started {
			return true // part of a message is read already
		}
	}
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

// Close closes the socket, and the fds of a message that a deadline
// stopped part-way. A Recv blocked on it returns an error, and closes
// the fds of its part itself.
func (c *Conn) Close() error {
	// The socket first: that wakes a blocked Recv, which then lets go of
	// frMu.
	err := c.f.Close()
	c.frMu.Lock()
	closeFDs(c.fr.take())
	c.frMu.Unlock()
	return err
}

// IsEOF says whether err means the peer is gone rather than misbehaving.
func IsEOF(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, unix.ECONNRESET) || errors.Is(err, os.ErrClosed)
}
