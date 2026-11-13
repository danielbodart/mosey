//go:build linux

package hs

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

// RESUME (D8). A new client -- possibly on a new device, after a reboot --
// cannot reuse anything from the old one: nothing transport- or
// crypto-related is ever written to disk. Instead:
//
//  1. The new client SSHes to the host as usual (D6). SSH authenticates the
//     user (authorized_keys) and the host (known_hosts).
//  2. Over SSH it runs `mosey-server attach <name>`. That helper is a fresh
//     process running as the user. It connects to the running session's
//     network process over a unix socket in a 0700 directory under
//     $XDG_RUNTIME_DIR, and the network process checks SO_PEERCRED
//     (uid must equal its own). This is the "authenticated local channel".
//  3. The network process mints brand-new single-use BCredentials (new
//     session id, new PSK, new X-Wing key) for this attach and returns them;
//     the helper prints them to SSH stdout; the client reads them.
//  4. The client runs an ordinary variant-B handshake with them. The new
//     transport is attached to the existing terminal session. Old clients'
//     transports are independent (each has its own keys and indices).
//
// So "resume" is just "a new handshake whose credentials were vouched for by
// a new SSH login", and the only thing that persists is the session itself
// (pty + emulator state), which lives in the session process (O4).

const resumeMagic = "mosey-attach-v1\n"

// ResumeServer hands out fresh credentials to same-uid local peers.
type ResumeServer struct {
	ln      *net.UnixListener
	Path    string
	Mint    func() (BCredentials, error)
	wantUID uint32
	// PeerUID is overridable in tests to simulate a foreign uid.
	PeerUID func(*net.UnixConn) (uint32, error)
}

func ListenResume(dir string, mint func() (BCredentials, error)) (*ResumeServer, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	st := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || fi.Mode().Perm() != 0o700 || st.Uid != uint32(os.Getuid()) {
		return nil, fmt.Errorf("resume dir %s must be a 0700 directory owned by us", dir)
	}
	p := filepath.Join(dir, "session.sock")
	os.Remove(p)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: p, Net: "unix"})
	if err != nil {
		return nil, err
	}
	return &ResumeServer{ln: ln, Path: p, Mint: mint, wantUID: uint32(os.Getuid()), PeerUID: peerUID}, nil
}

func peerUID(c *net.UnixConn) (uint32, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *syscall.Ucred
	var serr error
	if err := rc.Control(func(fd uintptr) {
		cred, serr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if serr != nil {
		return 0, serr
	}
	return cred.Uid, nil
}

var ErrForeignPeer = errors.New("hs: resume peer has a different uid")

// ServeOne accepts one attach request.
func (r *ResumeServer) ServeOne() error {
	c, err := r.ln.AcceptUnix()
	if err != nil {
		return err
	}
	defer c.Close()
	uid, err := r.PeerUID(c)
	if err != nil {
		return err
	}
	if uid != r.wantUID {
		return ErrForeignPeer
	}
	buf := make([]byte, len(resumeMagic))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != resumeMagic {
		return ErrMalformed
	}
	cred, err := r.Mint()
	if err != nil {
		return err
	}
	_, err = c.Write(cred.Marshal())
	return err
}

func (r *ResumeServer) Close() error { return r.ln.Close() }

// RequestCredentials is what `mosey-server attach` does.
func RequestCredentials(path string) (BCredentials, error) {
	c, err := net.Dial("unix", path)
	if err != nil {
		return BCredentials{}, err
	}
	defer c.Close()
	if _, err := c.Write([]byte(resumeMagic)); err != nil {
		return BCredentials{}, err
	}
	b, err := io.ReadAll(io.LimitReader(c, 4096))
	if err != nil {
		return BCredentials{}, err
	}
	return ParseBCredentials(b)
}
