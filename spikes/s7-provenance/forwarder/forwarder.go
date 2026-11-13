// Package forwarder is mosey's server side of agent forwarding with
// provenance, as spike S7 proposes it: the server listens where the
// session's SSH_AUTH_SOCK points, and for each connection either hands it
// to the host's attester, if the host has one, or pumps it straight into
// the agent channel, exactly as ssh -A would.
//
// It fails closed. Only a host with no attester at all (no hand-off socket,
// and Required not set) gets plain forwarding. On a host that has one, a
// hand-off that fails for any reason (the attester down, out of fds, over
// its per-user limit, or hanging up) refuses the client: its connection is
// closed and nothing reaches the agent channel. A failed attester costs
// signing, never attestation.
//
// mosey-server is the user's own binary (D7), so this is what an honest
// server does, not a guarantee against a hostile one: a program that can
// replace the server, or run its own, can skip the hand-off. The local
// agent's ssh.attestedHosts is what notices that.
//
// mosey neither builds nor parses a provenance statement and imports
// nothing of quoin (D17): the attester reads the client's chain from the
// kernel through the handed-off connection, adds its statement to the
// stream, and the statement rides the agent channel as one more agent
// message. The hand-off is the only interface: one byte 'H' and two file
// descriptors over SCM_RIGHTS, the client's connection and the attester's
// end of a socketpair whose other end is pumped into the channel.
package forwarder

import (
	"errors"
	"fmt"
	"io/fs"
	"io"
	"net"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// DefaultAttester is where a host's attester listens for hand-offs. It is
// fixed, not taken from the environment: a path the user's programs could
// set would let them point the next session at a hand-off of their own.
const DefaultAttester = "/run/agent-attest/handoff.sock"

// ErrRefused is Forward's answer when the host has an attester and the
// hand-off to it failed: the client was refused, not forwarded plainly.
var ErrRefused = errors.New("the attester did not take the connection; refused")

// Forwarder hands connections to the attester at Attester, over one
// connection it keeps, or pumps them plainly when the host has none.
type Forwarder struct {
	Attester string
	// Required refuses every client when there is no attester either, for
	// a host that is meant to have one.
	Required bool
	mu       sync.Mutex
	via      *net.UnixConn
}

// Forward serves one client connection into channel, the agent channel's
// stream for this connection. It reports whether the attester took it, and
// ErrRefused when there is an attester and it did not. It returns once both
// directions are done.
func (f *Forwarder) Forward(client *net.UnixConn, channel io.ReadWriteCloser) (attested bool, err error) {
	defer client.Close()
	defer channel.Close()
	ours, theirs, err := socketpair()
	if err != nil {
		return false, err
	}
	defer ours.Close()
	absent, err := f.hand(client, theirs)
	theirs.Close()
	switch {
	case err == nil:
		client.Close()
		pump(ours, channel)
		return true, nil
	case absent && !f.Required:
		pump(client, channel)
		return false, nil
	default:
		return false, fmt.Errorf("%w: %v", ErrRefused, err)
	}
}

// hand passes client and upstream to the attester. absent is whether the
// host has no attester at all: nothing at the hand-off path.
func (f *Forwarder) hand(client *net.UnixConn, upstream *os.File) (absent bool, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.via == nil {
		c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: f.Attester, Net: "unix"})
		if err != nil {
			_, serr := os.Lstat(f.Attester)
			return errors.Is(serr, fs.ErrNotExist), err
		}
		f.via = c
	}
	cf, err := client.File()
	if err != nil {
		return false, err
	}
	defer cf.Close()
	_, _, err = f.via.WriteMsgUnix([]byte{'H'}, unix.UnixRights(int(cf.Fd()), int(upstream.Fd())), nil)
	if err != nil {
		f.via.Close()
		f.via = nil
		return false, err
	}
	return false, nil
}

// pump copies both ways until either side is done with writing, then
// closes both.
func pump(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
	a.Close()
	b.Close()
	<-done
}

func socketpair() (*net.UnixConn, *os.File, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	of := os.NewFile(uintptr(fds[0]), "ours")
	defer of.Close()
	c, err := net.FileConn(of)
	if err != nil {
		unix.Close(fds[1])
		return nil, nil, err
	}
	uc, ok := c.(*net.UnixConn)
	if !ok {
		c.Close()
		unix.Close(fds[1])
		return nil, nil, errors.New("not a unix socket")
	}
	return uc, os.NewFile(uintptr(fds[1]), "theirs"), nil
}
