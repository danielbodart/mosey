package server

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/danielbodart/mosey/internal/bootstrap"
	"github.com/danielbodart/mosey/internal/ipc"
)

// The attach socket (server.md §2.6): where a session's spawner listens for
// a resume (D8), and how a launcher or a lister finds it. Only processes of
// the user can reach it: it lives in a 0700 directory of theirs, checked
// by both sides, and the spawner checks the peer's uid as well.
const (
	// attachName is the socket's name in its session's directory.
	attachName = "attach.sock"
	// MaxAttachConns is how many attach-socket connections a spawner
	// serves at once: a resume takes milliseconds, so more are closed
	// unanswered [choice].
	MaxAttachConns = 4
	// GreetingTimeout bounds how long a launcher or lister waits for a
	// session's greeting: the spawner answers at once, so a hung one is
	// skipped rather than waited on [choice] (bootstrap.md §11).
	GreetingTimeout = 2 * time.Second
)

// sessionsDir is R/mosey (server.md §2.6): under $XDG_RUNTIME_DIR when it
// is set and absolute, else under the temporary directory with the uid in
// its name, so users of a shared /tmp do not collide.
func sessionsDir(getenv func(string) string) string {
	if r := getenv("XDG_RUNTIME_DIR"); filepath.IsAbs(r) {
		return filepath.Join(r, "mosey")
	}
	tmp := getenv("TMPDIR")
	if !filepath.IsAbs(tmp) {
		tmp = "/tmp"
	}
	return filepath.Join(tmp, "mosey-"+strconv.Itoa(os.Getuid()))
}

// sessionDir is a session's directory under base, named by its id in hex.
func sessionDir(base string, sid [16]byte) string {
	return filepath.Join(base, fmt.Sprintf("%x", sid))
}

// isSessionDirName says whether name could be a session's directory: 32
// lower-case hex digits, as sessionDir writes them.
func isSessionDirName(name string) bool {
	if len(name) != 32 {
		return false
	}
	for i := 0; i < len(name); i++ {
		if c := name[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// errNotPrivate is a directory that is not one only the user can use.
var errNotPrivate = errors.New("not a private directory of this user")

// checkPrivateDir says whether path is a directory, not a symlink, owned
// by this user with no group or other permission bits: one no other user
// can have put a socket in, or swapped for a link to theirs.
func checkPrivateDir(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.IsDir(), fi.Mode()&os.ModeSymlink != 0:
		return fmt.Errorf("%s: %w (not a directory)", path, errNotPrivate)
	case !ok || int(st.Uid) != os.Getuid():
		return fmt.Errorf("%s: %w (owned by someone else)", path, errNotPrivate)
	case fi.Mode().Perm()&0o077 != 0:
		return fmt.Errorf("%s: %w (mode %#o)", path, errNotPrivate, fi.Mode().Perm())
	}
	return nil
}

// makePrivateDir makes path with mode 0700 unless it exists, and checks it
// either way.
func makePrivateDir(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return checkPrivateDir(path)
}

// attachListener is a spawner's attach socket (server.md §2.6).
type attachListener struct {
	f         *os.File
	dir, path string
	closed    atomic.Bool
}

// listenAttach makes base (if absent) and the session's directory under
// it, both checked private, and listens on an IPC socket there: a
// SOCK_SEQPACKET socket on Linux, a framed SOCK_STREAM socket on darwin
// (ipc.Socket, server.md §10). The socket is bound under a temporary name
// and renamed once it listens, so a socket at the final name always
// accepts: a lister never mistakes a session starting up for one that has
// gone.
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
	fd, err := ipc.Socket()
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
// reported as errForeignPeer so the caller can log it and carry on. Once
// the listener is closed it returns an error that is os.ErrClosed, and
// only then: the poller's own word for a closed file is not that error.
func (l *attachListener) Accept() (*os.File, error) {
	f, err := l.accept()
	if err != nil && l.closed.Load() {
		return nil, fmt.Errorf("the attach socket: %w", os.ErrClosed)
	}
	return f, err
}

func (l *attachListener) accept() (*os.File, error) {
	raw, err := l.f.SyscallConn()
	if err != nil {
		return nil, err
	}
	var nfd int
	var aerr error
	err = raw.Read(func(fd uintptr) bool {
		nfd, aerr = ipc.Accept(int(fd))
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
	l.closed.Store(true)
	os.Remove(l.path)
	os.Remove(l.dir)
	return l.f.Close()
}

// samePeer checks that the process at the other end of fd runs as this
// user: SO_PEERCRED on Linux, LOCAL_PEERCRED on darwin [S1 resume.go].
func samePeer(fd int) error { return peerIs(fd, os.Getuid()) }

// peerIs is samePeer for a given set of uids, so a test can play another
// user.
func peerIs(fd int, uids ...int) error {
	uid, err := ipc.PeerUID(fd)
	if err != nil {
		return fmt.Errorf("reading the peer's credentials: %w", err)
	}
	for _, u := range uids {
		if uid == u {
			return nil
		}
	}
	return fmt.Errorf("%w (uid %d)", errForeignPeer, uid)
}

// connectRetry is how often dialAttach tries again to connect to a
// session whose backlog is full [choice].
const connectRetry = 20 * time.Millisecond

// dialAttach connects to a session's attach socket in dir, after checking
// dir is private, and checks the listener runs as this user too. It
// returns the connection and the greeting the spawner sent first.
func dialAttach(dir string) (*os.File, []byte, error) {
	if err := checkPrivateDir(dir); err != nil {
		return nil, nil, err
	}
	// The connect and the greeting share one deadline, so a spawner that
	// is stopped or wedged with its backlog full is skipped, not waited
	// on (bootstrap.md §11). A blocking connect to a full backlog sleeps
	// until there is room; a non-blocking one says EAGAIN on Linux and is
	// not left in progress, so it is simply tried again. (darwin refuses
	// it at once, and the session is skipped.)
	deadline := time.Now().Add(GreetingTimeout)
	fd, err := ipc.Socket()
	if err != nil {
		return nil, nil, err
	}
	sa := &unix.SockaddrUnix{Name: filepath.Join(dir, attachName)}
	for {
		err = unix.Connect(fd, sa)
		if err != unix.EAGAIN && err != unix.EINTR {
			break
		}
		if time.Now().After(deadline) {
			err = fmt.Errorf("the session is not accepting: %w", err)
			break
		}
		time.Sleep(connectRetry)
	}
	if err != nil {
		unix.Close(fd)
		return nil, nil, fmt.Errorf("connecting to the session: %w", err)
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
	f.SetReadDeadline(deadline)
	greeting, err := ipc.ReadRecord(f, bootstrap.MaxSessionLine)
	f.SetReadDeadline(time.Time{})
	if errors.Is(err, ipc.ErrMalformed) {
		f.Close()
		return nil, nil, fmt.Errorf("%w: a greeting over %d bytes", bootstrap.ErrBadLine, bootstrap.MaxSessionLine)
	}
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("reading the session's greeting: %w", err)
	}
	return f, greeting, nil
}
