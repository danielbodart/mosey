// Package forwarder is mosey's server side of agent forwarding with
// provenance, as spike S7 proposes it: the server listens where the
// session's SSH_AUTH_SOCK points, and for each connection either hands it
// to the host's attester, if one listens on the well-known hand-off socket,
// or pumps it straight into the agent channel, exactly as ssh -A would.
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
	"io"
	"net"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// DefaultAttester is where a host's attester listens for hand-offs.
const DefaultAttester = "/run/agent-attest/handoff.sock"

// Forwarder hands connections to the attester at Attester, over one
// connection it keeps, or pumps them plainly when there is none.
type Forwarder struct {
	Attester string
	mu       sync.Mutex
	via      *net.UnixConn
}

// Forward serves one client connection into channel, the agent channel's
// stream for this connection. It reports whether the attester took it.
// Either way it returns once both directions are done.
func (f *Forwarder) Forward(client *net.UnixConn, channel io.ReadWriteCloser) (attested bool, err error) {
	defer client.Close()
	defer channel.Close()
	ours, theirs, err := socketpair()
	if err != nil {
		return false, err
	}
	defer ours.Close()
	if f.hand(client, theirs) {
		theirs.Close()
		client.Close()
		pump(ours, channel)
		return true, nil
	}
	theirs.Close()
	pump(client, channel)
	return false, nil
}

func (f *Forwarder) hand(client *net.UnixConn, upstream *os.File) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.via == nil {
		c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: f.Attester, Net: "unix"})
		if err != nil {
			return false
		}
		f.via = c
	}
	cf, err := client.File()
	if err != nil {
		return false
	}
	defer cf.Close()
	_, _, err = f.via.WriteMsgUnix([]byte{'H'}, unix.UnixRights(int(cf.Fd()), int(upstream.Fd())), nil)
	if err != nil {
		f.via.Close()
		f.via = nil
		return false
	}
	return true
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
