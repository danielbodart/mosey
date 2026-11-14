// Package ipc is how the server's three roles talk (D22): messages on
// SOCK_SEQPACKET socketpairs, so the kernel keeps message boundaries and
// there are no length fields to parse, and file descriptors passed with
// SCM_RIGHTS.
//
//	spawner -> proto   Start, with the UDP socket and the pty master
//	proto -> spawner   Credential (for stdout), Exit
//	proto -> emu       Output, Resize
//	emu -> proto       Update, Replies
//
// Every parser here faces a process that may be compromised: emu's
// messages are the ones the sandbox exists for, and the spawner's grammar
// is the only thing an unsandboxed process parses from proto. Each message
// type has a fixed layout, and Parse refuses anything else. Each parser has
// a fuzz target.
package ipc

import "os"

// Conn is one end of a seqpacket socketpair.
type Conn struct{}

// NewConn wraps f, which must be a SOCK_SEQPACKET socket.
func NewConn(f *os.File) (*Conn, error) {
	panic("TODO slice 1")
}

// Pair makes a connected socketpair, one end for this process and one to
// pass to a child.
func Pair() (local *Conn, child *os.File, err error) {
	panic("TODO slice 1")
}

// Send sends m, with fds attached if m carries any.
func (c *Conn) Send(m Message) error {
	panic("TODO slice 1")
}

// Recv receives the next message. Received fds are attached to it; a
// message that may not carry fds but arrives with some is refused, and the
// fds closed.
func (c *Conn) Recv() (Message, error) {
	panic("TODO slice 1")
}

func (c *Conn) Close() error { panic("TODO slice 1") }
