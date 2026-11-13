package bind

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

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
}

// Capture is a throwaway agent that holds no keys. The bootstrap ssh is run
// with -o ForwardAgent=<its path>; when the server side opens the agent
// channel, ssh connects here and, before relaying anything, sends
// session-bind@openssh.com with is_forwarding=1 for the session it is
// running. Capture verifies it and keeps it. It answers an identity request
// with no keys and refuses everything else, so nothing is ever signed and
// the user's real agent (quoin-signer, galley) is never contacted.
type Capture struct {
	Path string
	ln   *net.UnixListener
	C    chan Captured
	mu   sync.Mutex
	errs []error
}

func NewCapture(dir string) (*Capture, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	p := filepath.Join(dir, "capture.sock")
	_ = os.Remove(p)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: p, Net: "unix"})
	if err != nil {
		return nil, err
	}
	c := &Capture{Path: p, ln: ln, C: make(chan Captured, 8)}
	go c.serve()
	return c, nil
}

func (c *Capture) Close() error { return c.ln.Close() }

func (c *Capture) Errors() []error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]error(nil), c.errs...)
}

func (c *Capture) serve() {
	for {
		conn, err := c.ln.AcceptUnix()
		if err != nil {
			return
		}
		go c.handle(conn)
	}
}

func (c *Capture) fail(err error) {
	c.mu.Lock()
	c.errs = append(c.errs, err)
	c.mu.Unlock()
}

func (c *Capture) handle(conn *net.UnixConn) {
	defer conn.Close()
	var cred *unix.Ucred
	if raw, err := conn.SyscallConn(); err == nil {
		raw.Control(func(fd uintptr) {
			cred, _ = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		})
	}
	got := Captured{}
	if cred != nil {
		got.PeerPID, got.PeerUID = cred.Pid, cred.Uid
	}
	defer func() {
		if got.Bind != nil {
			c.C <- got
		}
	}()
	for {
		msg, err := ReadFrame(conn)
		if err != nil {
			return
		}
		got.Msgs = append(got.Msgs, msg[0])
		switch msg[0] {
		case AgentcExtension:
			name, rest, ok := sshString(msg[1:])
			if !ok || string(name) != SessionBindExt {
				conn.Write(Frame([]byte{AgentExtensionFailure}))
				continue
			}
			b, err := ParseContents(rest)
			if err != nil {
				c.fail(fmt.Errorf("capture: %w", err))
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
