package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// CaptureDeadline is how long the capture's one connection may take from
// its accept to its EOF [S3].
const CaptureDeadline = 10 * time.Second

// NoBindError is why no bind was captured: the agent is then off, and the
// client says so (agent.md §2.4).
type NoBindError struct{ Reason string }

func (e *NoBindError) Error() string { return e.Reason }

func noBind(format string, a ...any) error { return &NoBindError{Reason: fmt.Sprintf(format, a...)} }

// capture is the state machine of agent.md §2.2 on the one connection,
// once its peer has been checked: ssh's own bind, the trigger, then EOF.
// Anything else is no bind at all, because everything after frame 1
// comes from the far host, which can mint a valid bind for any host it
// reaches [S3 E11]. It writes the replies ssh and the trigger expect.
func capture(rw io.ReadWriter) (Bind, error) {
	f, err := readFrame(rw, MaxCaptureFrame)
	if err != nil {
		return Bind{}, noBind("ssh sent no session-bind: %v", err)
	}
	b, err := ParseBind(f)
	if err != nil {
		return Bind{}, noBind("ssh's first agent message is not a session-bind for forwarding: %v", err)
	}
	if _, err := rw.Write(frame(msgSuccess)); err != nil {
		return Bind{}, noBind("answering the session-bind: %v", err)
	}
	f, err = readFrame(rw, MaxCaptureFrame)
	if err != nil {
		return Bind{}, noBind("the server did not ask for identities after the bind: %v", err)
	}
	if len(f) != 5 || f[4] != msgRequestIdentities {
		rw.Write(frame(msgFailure))
		return Bind{}, noBind("protocol error: message %d after the session-bind, not the identities request", f[4])
	}
	if _, err := rw.Write(frame(msgIdentitiesAnswer, 0, 0, 0, 0)); err != nil {
		return Bind{}, noBind("answering the identities request: %v", err)
	}
	var one [1]byte
	switch n, err := rw.Read(one[:]); {
	case n > 0:
		return Bind{}, noBind("protocol error: more after the identities answer")
	case errors.Is(err, io.EOF):
		return b, nil
	case isTimeout(err):
		return Bind{}, noBind("the server held the agent channel open")
	default:
		return Bind{}, noBind("reading after the identities answer: %v", err)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// Capture is the throwaway agent the bootstrap ssh is pointed at with
// ForwardAgent (bootstrap.md §8). It holds no keys; it exists so ssh sends
// it the bootstrap connection's session-bind.
type Capture struct {
	// Path is the socket, for ssh -o ForwardAgent=Path.
	Path string

	ln      *net.UnixListener
	expect  chan int
	expectO sync.Once
	mu      sync.Mutex
	took    bool
	done    chan struct{}
	once    sync.Once
	bind    Bind
	err     error
}

// CaptureDir is where the capture socket lives (bootstrap.md §8 step 1):
// $XDG_RUNTIME_DIR/mosey when that is set and absolute, else the
// temporary directory's mosey-UID, as the server's sessions directory is
// (server.md §2.6).
func CaptureDir(getenv func(string) string) string {
	if r := getenv("XDG_RUNTIME_DIR"); filepath.IsAbs(r) {
		return filepath.Join(r, "mosey")
	}
	tmp := getenv("TMPDIR")
	if !filepath.IsAbs(tmp) {
		tmp = "/tmp"
	}
	return filepath.Join(tmp, "mosey-"+strconv.Itoa(os.Getuid()))
}

// ListenCapture makes dir if it is absent, checks it is a private
// directory of this user's (0700, owned, not a link), and listens on a
// fresh cap-HEX.sock in it, mode 0600, unlinked on Close.
func ListenCapture(dir string) (*Capture, error) {
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("making %s: %w", dir, err)
	}
	if err := checkPrivateDir(dir); err != nil {
		return nil, err
	}
	var r [16]byte
	rand.Read(r[:])
	path := filepath.Join(dir, "cap-"+hex.EncodeToString(r[:])+".sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("listening on the capture socket: %w", err)
	}
	ln.SetUnlinkOnClose(true)
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	c := &Capture{Path: path, ln: ln, expect: make(chan int, 1), done: make(chan struct{})}
	go c.serve()
	return c, nil
}

// checkPrivateDir says whether path is a directory, not a symlink, owned
// by this user, with no group or other permission bits.
func checkPrivateDir(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.IsDir():
		return fmt.Errorf("%s is not a directory", path)
	case !ok || int(st.Uid) != os.Getuid():
		return fmt.Errorf("%s is owned by someone else", path)
	case fi.Mode().Perm()&0o077 != 0:
		return fmt.Errorf("%s has mode %#o, not private", path, fi.Mode().Perm())
	}
	return nil
}

// Expect names the bootstrap ssh, once started: the only process whose
// connection is taken. A connection that comes first waits for it.
func (c *Capture) Expect(pid int) {
	c.expectO.Do(func() { c.expect <- pid })
}

func (c *Capture) finish(b Bind, err error) {
	c.once.Do(func() {
		c.bind, c.err = b, err
		close(c.done)
	})
}

func (c *Capture) serve() {
	conn, err := c.ln.AcceptUnix()
	// One connection only: a second agent channel from the server cannot
	// reach the capture (agent.md §2.2).
	c.ln.Close()
	if err != nil {
		c.finish(Bind{}, noBind("the server did not open the agent channel (is AllowAgentForwarding off there?)"))
		return
	}
	c.mu.Lock()
	c.took = true
	c.mu.Unlock()
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(CaptureDeadline))
	pid, uid, err := peerCred(conn)
	if err != nil {
		c.finish(Bind{}, noBind("reading the capture peer's credentials: %v", err))
		return
	}
	var want int
	select {
	case want = <-c.expect:
	case <-time.After(CaptureDeadline):
		c.finish(Bind{}, noBind("the capture was never told which ssh to expect"))
		return
	}
	if pid != want || uid != os.Getuid() {
		c.finish(Bind{}, noBind("the capture was reached by pid %d uid %d, not our ssh (pid %d)", pid, uid, want))
		return
	}
	c.finish(capture(conn))
}

// Result waits for the capture's final state (agent.md §2.2): the one
// connection's EOF or failure, or, if nothing has connected by the time
// sshExited closes, no bind. ctx bounds the wait.
func (c *Capture) Result(ctx context.Context, sshExited <-chan struct{}) (Bind, error) {
	select {
	case <-c.done:
	case <-sshExited:
		c.mu.Lock()
		took := c.took
		c.mu.Unlock()
		if !took {
			c.ln.Close() // serve's Accept fails, and says why
		}
		select {
		case <-c.done:
		case <-ctx.Done():
			return Bind{}, noBind("waiting for the session-bind: %v", ctx.Err())
		}
	case <-ctx.Done():
		return Bind{}, noBind("waiting for the session-bind: %v", ctx.Err())
	}
	return c.bind, c.err
}

// Close stops listening and removes the socket. A capture that took no
// connection ends with no bind.
func (c *Capture) Close() error {
	return c.ln.Close()
}
