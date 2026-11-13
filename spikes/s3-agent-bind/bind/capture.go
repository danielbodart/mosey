package bind

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Captured is a session-bind ssh sent to the capture socket, with the pid
// of the process that sent it (SO_PEERCRED).
type Captured struct {
	Bind    *Bind
	PeerPID int32
	PeerUID uint32
	// Msgs are the agent message numbers seen on that connection, in order.
	Msgs []byte
	// Err is why the bind was not taken; Bind is nil whenever Err is set.
	Err error
}

// Capture is a throwaway agent that holds no keys. The bootstrap ssh is run
// with -o ForwardAgent=<its path>; when the server side opens the agent
// channel, ssh connects here and, before relaying anything, sends
// session-bind@openssh.com with is_forwarding=1 for the session it is
// running.
//
// Everything after that first frame comes from the server, which may be
// hostile and can mint a valid session-bind for any host it can reach (the
// host key's signature over the session id is made before authentication).
// So Capture is a strict state machine (review response, critical #1):
//
//   - exactly one connection is accepted; the listener closes on accept, so
//     a second agent channel from the server fails to open;
//   - that connection must come from the expected pid and uid (our own ssh
//     child, SO_PEERCRED), or nothing is taken;
//   - frame 1 must be a valid session-bind with is_forwarding=1 (ssh's own);
//   - frame 2 must be REQUEST_IDENTITIES, answered with no keys;
//   - then EOF. Any further frame, or any other order, is a protocol error
//     and no bind is taken at all.
//
// Legacy (the first prototype, kept only so the harness can show the attack
// it allowed) takes the last valid bind on the connection from anyone.
type Capture struct {
	Path   string
	Legacy bool

	ln       *net.UnixListener
	once     sync.Once
	done     chan struct{}
	result   Captured
	accepted bool
	mu       sync.Mutex
	wantPID  int
	wantUID  int
	expected chan struct{}
}

const captureDeadline = 10 * time.Second

func NewCapture(dir string) (*Capture, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	var r [8]byte
	rand.Read(r[:])
	p := filepath.Join(dir, "cap-"+hex.EncodeToString(r[:])+".sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: p, Net: "unix"})
	if err != nil {
		return nil, err
	}
	os.Chmod(p, 0o600)
	ln.SetUnlinkOnClose(true)
	c := &Capture{Path: p, ln: ln, done: make(chan struct{}), expected: make(chan struct{})}
	go c.serve()
	return c, nil
}

// Expect names the only process whose connection is taken: the bootstrap
// ssh, once it has been started. Connections wait for it.
func (c *Capture) Expect(pid, uid int) {
	c.mu.Lock()
	c.wantPID, c.wantUID = pid, uid
	c.mu.Unlock()
	close(c.expected)
}

// Close stops listening. If no connection was ever accepted, the result is
// "no bind" (the server never opened the agent channel).
func (c *Capture) Close() error {
	err := c.ln.Close()
	c.mu.Lock()
	acc := c.accepted
	c.mu.Unlock()
	if !acc {
		c.finish(Captured{Err: errors.New("ssh never connected: the server did not open the agent channel, or refused agent forwarding")})
	}
	return err
}

// Result waits for the one connection to end (it ends when ssh exits, at
// the latest) and returns what was taken.
func (c *Capture) Result() Captured {
	<-c.done
	return c.result
}

func (c *Capture) finish(r Captured) {
	c.once.Do(func() {
		c.result = r
		close(c.done)
	})
}

func (c *Capture) serve() {
	conn, err := c.ln.AcceptUnix()
	if err != nil {
		return
	}
	c.mu.Lock()
	c.accepted = true
	c.mu.Unlock()
	// One connection only: a second agent channel from the server cannot
	// reach us.
	c.ln.Close()
	c.finish(c.handle(conn))
}

func (c *Capture) handle(conn *net.UnixConn) (got Captured) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(captureDeadline))
	var cred *unix.Ucred
	if raw, err := conn.SyscallConn(); err == nil {
		raw.Control(func(fd uintptr) {
			cred, _ = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		})
	}
	if cred == nil {
		return Captured{Err: errors.New("capture: no peer credentials")}
	}
	got.PeerPID, got.PeerUID = cred.Pid, cred.Uid
	select {
	case <-c.expected:
	case <-time.After(captureDeadline):
		return Captured{PeerPID: got.PeerPID, PeerUID: got.PeerUID, Err: errors.New("capture: no expected pid set")}
	}
	c.mu.Lock()
	wantPID, wantUID := c.wantPID, c.wantUID
	c.mu.Unlock()
	if !c.Legacy && (int(cred.Pid) != wantPID || int(cred.Uid) != wantUID) {
		got.Err = fmt.Errorf("capture: connection from pid %d uid %d, not our ssh (pid %d uid %d)", cred.Pid, cred.Uid, wantPID, wantUID)
		return got
	}
	if c.Legacy {
		return c.legacy(conn, got)
	}
	fail := func(err error) Captured {
		got.Bind = nil
		got.Err = err
		return got
	}
	// Frame 1: ssh's own session-bind.
	msg, err := ReadFrame(conn)
	if err != nil {
		return fail(fmt.Errorf("capture: no first frame: %w", err))
	}
	got.Msgs = append(got.Msgs, msg[0])
	b, err := parseBindFrame(msg)
	if err != nil {
		return fail(fmt.Errorf("capture: first frame: %w", err))
	}
	if !b.Fwd {
		return fail(errors.New("capture: first bind is not is_forwarding"))
	}
	conn.Write(Frame([]byte{AgentSuccess}))
	// Frame 2: the server's trigger, one REQUEST_IDENTITIES.
	msg, err = ReadFrame(conn)
	if err != nil {
		return fail(fmt.Errorf("capture: no identities request after the bind: %w", err))
	}
	got.Msgs = append(got.Msgs, msg[0])
	if msg[0] != AgentcRequestIDs || len(msg) != 1 {
		conn.Write(Frame([]byte{AgentFailure}))
		return fail(fmt.Errorf("capture: protocol error: frame 2 is message %d, not REQUEST_IDENTITIES", msg[0]))
	}
	conn.Write(Frame([]byte{AgentIdentitiesAnswer, 0, 0, 0, 0}))
	// Then EOF: anything else the server sends is refused, and so is the bind.
	msg, err = ReadFrame(conn)
	if err == nil {
		got.Msgs = append(got.Msgs, msg[0])
		conn.Write(Frame([]byte{AgentFailure}))
		return fail(fmt.Errorf("capture: protocol error: message %d after the identities answer", msg[0]))
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return fail(errors.New("capture: the server held the agent channel open"))
	}
	got.Bind = b
	return got
}

func parseBindFrame(msg []byte) (*Bind, error) {
	if msg[0] != AgentcExtension {
		return nil, fmt.Errorf("message %d, not session-bind", msg[0])
	}
	name, rest, ok := sshString(msg[1:])
	if !ok || string(name) != SessionBindExt {
		return nil, errors.New("not session-bind")
	}
	return ParseContents(rest)
}

// legacy is the first prototype's handler: every valid bind on the
// connection overwrites the last, from any sender. Kept to reproduce the
// review's attack; never use.
func (c *Capture) legacy(conn *net.UnixConn, got Captured) Captured {
	for {
		msg, err := ReadFrame(conn)
		if err != nil {
			if got.Bind == nil {
				got.Err = errors.New("capture(legacy): no bind")
			}
			return got
		}
		got.Msgs = append(got.Msgs, msg[0])
		switch msg[0] {
		case AgentcExtension:
			b, err := parseBindFrame(msg)
			if err != nil {
				conn.Write(Frame([]byte{AgentFailure}))
				continue
			}
			got.Bind = b
			conn.Write(Frame([]byte{AgentSuccess}))
		case AgentcRequestIDs:
			conn.Write(Frame([]byte{AgentIdentitiesAnswer, 0, 0, 0, 0}))
		default:
			conn.Write(Frame([]byte{AgentFailure}))
		}
	}
}

func sshString(b []byte) (s, rest []byte, ok bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(n) > uint64(len(b)-4) {
		return nil, nil, false
	}
	return b[4 : 4+n], b[4+n:], true
}
