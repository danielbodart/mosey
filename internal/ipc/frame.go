package ipc

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Framing for a stream socket (server.md §3.1, §10). macOS has no AF_UNIX
// SOCK_SEQPACKET, so there each message goes on a SOCK_STREAM socket with a
// 4-byte big-endian length before it. The message after the length is the
// same bytes a seqpacket message would be: the layouts of §3.3 do not
// change. The framing is portable code, so its tests and its fuzz target
// run on Linux too; only the darwin build uses it on the wire.

// frameHeader is the size of the length before each framed message.
const frameHeader = 4

// appendFrame appends b, with its length before it, to dst.
func appendFrame(dst, b []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(b)))
	return append(dst, b...)
}

// frameReader takes one framed message at a time off a stream. It never
// asks for a byte past the end of the message it is reading, so every
// read holds bytes of one message only. The fds a read brings belong to
// that message: the sender attaches them to the first byte of their
// message, and a read that stops at the message's end cannot take the
// next message's fds. That keeps each message's fds with it even when the
// kernel gives the message in short reads.
//
// A length of 0 or over MaxMessage is refused before the body is read or
// anything allocated. The stream has then lost its place, so the refusal
// is final: every later call returns it, and nothing more is read.
type frameReader struct {
	hdr   [frameHeader]byte
	nhdr  int   // bytes of hdr read
	size  int   // the body's length, once hdr is whole
	nbody int   // bytes of the body read
	fds   []int // fds that came with this message so far
	err   error // the final refusal, if there was one
}

// next is where the next read goes: the rest of the length, or the rest
// of the body in buf. buf must hold MaxMessage bytes.
func (r *frameReader) next(buf []byte) []byte {
	if r.nhdr < frameHeader {
		return r.hdr[r.nhdr:]
	}
	return buf[r.nbody:r.size]
}

// started says whether any part of a message has been read.
func (r *frameReader) started() bool { return r.nhdr > 0 || len(r.fds) > 0 }

// add records a read of n bytes into next's slice, and the fds that came
// with it. Once the message is whole, it returns the body's length and
// its fds, and starts on the next message. A read of 0 bytes is the end
// of the stream: io.EOF between messages, and within one, an error that
// wraps io.EOF too (the peer is gone, not misbehaving). On any error the
// caller closes the fds returned.
func (r *frameReader) add(n int, fds []int) (size int, msgFDs []int, done bool, err error) {
	r.fds = append(r.fds, fds...)
	if n == 0 {
		fds := r.take()
		if r.err == nil {
			r.err = io.EOF
			if len(fds) > 0 || r.nhdr > 0 {
				r.err = fmt.Errorf("ipc: the stream ended within a message: %w", io.EOF)
			}
		}
		return 0, fds, false, r.err
	}
	if r.nhdr < frameHeader {
		r.nhdr += n
		if r.nhdr < frameHeader {
			return 0, nil, false, nil
		}
		// Bounded before any use: the length is the peer's word.
		l := binary.BigEndian.Uint32(r.hdr[:])
		if l == 0 || l > MaxMessage {
			r.err = malformed("a framed length of %d is not in 1..%d", l, MaxMessage)
			return 0, r.take(), false, r.err
		}
		r.size = int(l)
		return 0, nil, false, nil
	}
	r.nbody += n
	if r.nbody < r.size {
		return 0, nil, false, nil
	}
	size = r.size
	r.nhdr, r.size, r.nbody = 0, 0, 0
	return size, r.take(), true, nil
}

// take hands over the fds held, for the caller to keep or close.
func (r *frameReader) take() []int {
	fds := r.fds
	r.fds = nil
	return fds
}
