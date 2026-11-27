//go:build linux || darwin

package server

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// agentListener is the spawner's agent socket (server.md §2.7).
type agentListener struct {
	f      *os.File
	path   string
	closed atomic.Bool
}

// listenAgent listens on dir/agent.sock: SOCK_STREAM, as agents are,
// bound under a temporary name and renamed once it listens, mode 0600, in
// a directory the caller made and checked private.
func listenAgent(dir string) (*agentListener, error) {
	if err := checkPrivateDir(dir); err != nil {
		return nil, err
	}
	l := &agentListener{path: filepath.Join(dir, agentName)}
	fd, err := socket(unix.AF_UNIX, unix.SOCK_STREAM, true)
	if err != nil {
		return nil, fmt.Errorf("making the agent socket: %w", err)
	}
	tmp := l.path + ".tmp"
	err = unix.Bind(fd, &unix.SockaddrUnix{Name: tmp})
	if err == nil {
		err = unix.Listen(fd, agentBacklog)
	}
	if err == nil {
		err = os.Chmod(tmp, 0o600)
	}
	if err == nil {
		err = os.Rename(tmp, l.path)
	}
	if err != nil {
		unix.Close(fd)
		os.Remove(tmp)
		return nil, fmt.Errorf("listening on the agent socket: %w", err)
	}
	l.f = os.NewFile(uintptr(fd), l.path)
	return l, nil
}

// agentPeers are the uids whose processes may use the agent socket: this
// user's, and root's (agent.md §4.1). sshd's forwarded socket is guarded
// by its file mode alone, which root passes, so `sudo -E ssh-add -l`
// works under ssh -A; root can reach this user's processes and files
// anyway, so refusing it would protect nothing. The attach socket stays
// this user's alone (samePeer): a resume is not something root does on
// the user's behalf.
func agentPeers() []int { return []int{os.Getuid(), 0} }

// Accept returns the next connection from a process of this user or root, in
// non-blocking mode so proto can wrap it inside its sandbox (ipc.AgentConn).
// One from any other uid is closed unanswered and reported as
// errForeignPeer. Once closed it returns an error that is os.ErrClosed.
func (l *agentListener) Accept() (*os.File, error) {
	raw, err := l.f.SyscallConn()
	if err != nil {
		return nil, err
	}
	var nfd int
	var aerr error
	err = raw.Read(func(fd uintptr) bool {
		nfd, aerr = accept(int(fd))
		return aerr != unix.EAGAIN
	})
	if err == nil {
		err = aerr
	}
	if err != nil {
		if l.closed.Load() {
			return nil, fmt.Errorf("the agent socket: %w", os.ErrClosed)
		}
		return nil, err
	}
	if err := peerIs(nfd, agentPeers()...); err != nil {
		unix.Close(nfd)
		return nil, err
	}
	return os.NewFile(uintptr(nfd), "agent"), nil
}

// Close stops accepting and removes the socket.
func (l *agentListener) Close() error {
	l.closed.Store(true)
	os.Remove(l.path)
	return l.f.Close()
}
