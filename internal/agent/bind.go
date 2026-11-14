package agent

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"
)

// Agent protocol message numbers (PROTOCOL.agent, draft-miller-ssh-agent).
const (
	msgFailure           = 5
	msgSuccess           = 6
	msgRequestIdentities = 11
	msgIdentitiesAnswer  = 12
	msgExtension         = 27
)

// SessionBindExtension is OpenSSH's session-bind extension's name.
const SessionBindExtension = "session-bind@openssh.com"

// Bounds on the frames this package reads (agent.md §2.2, §3, §6).
const (
	// MaxCaptureFrame bounds a frame in the capture: a real bind is under
	// 5 KiB even with an RSA-16384 host key [derived].
	MaxCaptureFrame = 16 << 10
	// MaxBindReply bounds the agent's reply to a replayed bind; the
	// defined replies are one byte [choice].
	MaxBindReply = 4 << 10
	// MaxTriggerReply bounds the identities answer the launcher's trigger
	// reads (bootstrap.md §8) [choice].
	MaxTriggerReply = 256 << 10
)

// Bind is a session-bind@openssh.com that ssh sent, with is_forwarding set:
// the frame exactly as it arrived, and the fields the pin needs.
type Bind struct {
	frame     []byte
	HostKey   ssh.PublicKey
	SessionID []byte
}

// Frame is the bind's agent frame, length prefix included, byte for byte
// as ssh sent it: what is replayed (agent.md §3).
func (b Bind) Frame() []byte { return b.frame }

// IsZero says whether b is no bind at all.
func (b Bind) IsZero() bool { return b.frame == nil }

var errMalformed = errors.New("a malformed agent message")

// ParseBind reads a session-bind frame (length prefix included) strictly:
// an extension message named session-bind@openssh.com whose contents are
// exactly a host key, a session id, a signature and is_forwarding = 1 with
// nothing after them, and whose signature by the host key over the session
// id verifies (agent.md §2.1). It is what the capture takes as frame 1.
func ParseBind(frame []byte) (Bind, error) {
	if len(frame) < 5 || int(binary.BigEndian.Uint32(frame)) != len(frame)-4 {
		return Bind{}, errMalformed
	}
	body := frame[4:]
	if body[0] != msgExtension {
		return Bind{}, fmt.Errorf("message %d, not a session-bind", body[0])
	}
	name, rest, ok := sshString(body[1:])
	if !ok || string(name) != SessionBindExtension {
		return Bind{}, errors.New("an extension other than session-bind")
	}
	keyBlob, rest, ok1 := sshString(rest)
	sid, rest, ok2 := sshString(rest)
	sigBlob, rest, ok3 := sshString(rest)
	if !ok1 || !ok2 || !ok3 || len(rest) != 1 || len(sid) == 0 {
		return Bind{}, fmt.Errorf("session-bind: %w", errMalformed)
	}
	switch rest[0] {
	case 1:
	case 0:
		return Bind{}, errors.New("a session-bind that is not for forwarding")
	default:
		return Bind{}, fmt.Errorf("session-bind: %w (is_forwarding %d)", errMalformed, rest[0])
	}
	key, err := ssh.ParsePublicKey(keyBlob)
	if err != nil {
		return Bind{}, fmt.Errorf("session-bind: the host key: %w", err)
	}
	var sig struct {
		Format string
		Blob   []byte
		Rest   []byte `ssh:"rest"`
	}
	if err := ssh.Unmarshal(sigBlob, &sig); err != nil || len(sig.Rest) != 0 {
		return Bind{}, fmt.Errorf("session-bind: the signature: %w", errMalformed)
	}
	if err := key.Verify(sid, &ssh.Signature{Format: sig.Format, Blob: sig.Blob}); err != nil {
		return Bind{}, fmt.Errorf("session-bind: the signature does not verify: %w", err)
	}
	return Bind{frame: append([]byte(nil), frame...), HostKey: key, SessionID: append([]byte(nil), sid...)}, nil
}

// sshString splits an RFC 4251 string off the front of b.
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

// readFrame reads one agent frame, length prefix included, refusing a
// length of 0 or over max before reading the body.
func readFrame(r io.Reader, max int) ([]byte, error) {
	var l [4]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(l[:])
	if n == 0 || uint64(n) > uint64(max) {
		return nil, fmt.Errorf("an agent message of %d bytes", n)
	}
	f := make([]byte, 4+n)
	copy(f, l[:])
	if _, err := io.ReadFull(r, f[4:]); err != nil {
		return nil, err
	}
	return f, nil
}

// frame is an agent message with its length prefix.
func frame(body ...byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(body))), body...)
}
