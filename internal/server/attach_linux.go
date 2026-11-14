package server

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"

	"github.com/danielbodart/mosey/internal/bootstrap"
	"github.com/danielbodart/mosey/internal/ipc"
)

// attachListener is a spawner's attach socket (server.md §2.6).
type attachListener struct {
	f         *os.File
	dir, path string
}

// listenAttach makes base (if absent) and the session's directory under
// it, both checked private, and listens on a SOCK_SEQPACKET socket there.
// The socket is bound under a temporary name and renamed once it listens,
// so a socket at the final name always accepts: a lister never mistakes a
// session starting up for one that has gone.
func listenAttach(base string, sid [16]byte) (*attachListener, error) {
	if err := makePrivateDir(base); err != nil {
		return nil, fmt.Errorf("the sessions directory: %w", err)
	}
	dir := sessionDir(base, sid)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, fmt.Errorf("the session's directory: %w", err)
	}
	l := &attachListener{dir: dir, path: filepath.Join(dir, attachName)}
	if err := checkPrivateDir(dir); err != nil {
		os.Remove(dir)
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		os.Remove(dir)
		return nil, fmt.Errorf("making the attach socket: %w", err)
	}
	tmp := l.path + ".tmp"
	err = unix.Bind(fd, &unix.SockaddrUnix{Name: tmp})
	if err == nil {
		err = unix.Listen(fd, MaxAttachConns)
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
		os.Remove(dir)
		return nil, fmt.Errorf("listening on the attach socket: %w", err)
	}
	// Non-blocking, so os.NewFile registers it with the poller and Close
	// wakes an Accept blocked on it.
	l.f = os.NewFile(uintptr(fd), l.path)
	return l, nil
}

// errForeignPeer is a connection from a process of another user.
var errForeignPeer = errors.New("a process of another user")

// Accept returns the next connection from a process of this user, wrapped
// for IPC. A connection from any other uid is closed unanswered, and
// reported as errForeignPeer so the caller can log it and carry on.
func (l *attachListener) Accept() (*os.File, error) {
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
		return nil, err
	}
	if err := samePeer(nfd); err != nil {
		unix.Close(nfd)
		return nil, err
	}
	f, err := ipc.Wrap(nfd, "attach")
	if err != nil {
		unix.Close(nfd)
		return nil, err
	}
	return f, nil
}

// Close stops accepting and removes the socket and its directory, so a
// resume never reaches a session that is ending.
func (l *attachListener) Close() error {
	os.Remove(l.path)
	os.Remove(l.dir)
	return l.f.Close()
}

// samePeer checks with SO_PEERCRED that the process at the other end of fd
// runs as this user [S1 resume.go].
func samePeer(fd int) error {
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return fmt.Errorf("reading the peer's credentials: %w", err)
	}
	if int(cred.Uid) != os.Getuid() {
		return fmt.Errorf("%w (uid %d)", errForeignPeer, cred.Uid)
	}
	return nil
}

// dialAttach connects to a session's attach socket in dir, after checking
// dir is private, and checks the listener runs as this user too. It
// returns the connection and the greeting the spawner sent first.
func dialAttach(dir string) (*os.File, []byte, error) {
	if err := checkPrivateDir(dir); err != nil {
		return nil, nil, err
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	if err := unix.Connect(fd, &unix.SockaddrUnix{Name: filepath.Join(dir, attachName)}); err != nil {
		unix.Close(fd)
		return nil, nil, err
	}
	if err := samePeer(fd); err != nil {
		unix.Close(fd)
		return nil, nil, err
	}
	f, err := ipc.Wrap(fd, "attach")
	if err != nil {
		unix.Close(fd)
		return nil, nil, err
	}
	// The greeting is one seqpacket message, read whole: a buffer one byte
	// over the bound tells a long one from one that fits.
	f.SetReadDeadline(time.Now().Add(GreetingTimeout))
	buf := make([]byte, bootstrap.MaxSessionLine+1)
	n, err := f.Read(buf)
	f.SetReadDeadline(time.Time{})
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("reading the session's greeting: %w", err)
	}
	if n > bootstrap.MaxSessionLine {
		f.Close()
		return nil, nil, fmt.Errorf("%w: a greeting over %d bytes", bootstrap.ErrBadLine, bootstrap.MaxSessionLine)
	}
	return f, buf[:n], nil
}
