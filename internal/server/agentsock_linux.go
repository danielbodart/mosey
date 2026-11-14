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
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
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

// Accept returns the next connection from a process of this user, in
// non-blocking mode so proto can wrap it inside its sandbox (ipc.AgentConn).
// One from another uid is closed unanswered and reported as
// errForeignPeer. Once closed it returns an error that is os.ErrClosed.
func (l *agentListener) Accept() (*os.File, error) {
	raw, err := l.f.SyscallConn()
	if err != nil {
		return nil, err
	}
	var nfd int
	var aerr error
	err = raw.Read(func(fd uintptr) bool {
		nfd, _, aerr = unix.Accept4(int(fd), unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK)
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
	if err := samePeer(nfd); err != nil {
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
