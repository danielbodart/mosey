// Package bind is the S3 spike's record of how a mosey client can hold an
// OpenSSH session-bind@openssh.com triple (host key, session id, the host
// key's signature over the session id) and replay it on every local agent
// connection it opens for a forwarded mosey agent channel.
//
// Wire format of session-bind@openssh.com is from OpenSSH's PROTOCOL.agent
// (public spec, BSD-licensed project; not Mosh-derived):
//
//	string  hostkey
//	string  session identifier
//	string  signature
//	bool    is_forwarding
package bind

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"
)

const SessionBindExt = "session-bind@openssh.com"

// Agent protocol message numbers (draft-miller-ssh-agent).
const (
	AgentFailure          = 5
	AgentSuccess          = 6
	AgentcRequestIDs      = 11
	AgentIdentitiesAnswer = 12
	AgentcSignRequest     = 13
	AgentSignResponse     = 14
	AgentcExtension       = 27
	AgentExtensionFailure = 28
	MaxAgentMsg           = 256 << 10
)

// Bind is one session-bind. Sig is the marshalled ssh.Signature blob.
type Bind struct {
	HostKey ssh.PublicKey
	SID     []byte
	Sig     []byte
	Fwd     bool
}

func (b *Bind) String() string {
	return fmt.Sprintf("bind{host %s, sid %s…(%d bytes), fwd %v}",
		ssh.FingerprintSHA256(b.HostKey), hex.EncodeToString(b.SID[:min(8, len(b.SID))]), len(b.SID), b.Fwd)
}

// Verify checks the host key's signature over the session id, as quoin's
// parseBind and OpenSSH's ssh-agent both do.
func (b *Bind) Verify() error {
	var sig ssh.Signature
	if err := ssh.Unmarshal(b.Sig, &sig); err != nil {
		return err
	}
	return b.HostKey.Verify(b.SID, &sig)
}

// Contents is the extension's body (after the extension name).
func (b *Bind) Contents() []byte {
	return ssh.Marshal(struct {
		Key, SID, Sig []byte
		Fwd           bool
	}{b.HostKey.Marshal(), b.SID, b.Sig, b.Fwd})
}

// WithFwd returns a copy with is_forwarding set as given. The signature is
// over the session id only, so the flag is the client's statement about
// how the agent connection is being used, exactly as in OpenSSH.
func (b Bind) WithFwd(fwd bool) *Bind { b.Fwd = fwd; return &b }

func ParseContents(c []byte) (*Bind, error) {
	var w struct {
		Key, SID, Sig []byte
		Fwd           bool
	}
	if err := ssh.Unmarshal(c, &w); err != nil {
		return nil, err
	}
	k, err := ssh.ParsePublicKey(w.Key)
	if err != nil {
		return nil, err
	}
	b := &Bind{HostKey: k, SID: w.SID, Sig: w.Sig, Fwd: w.Fwd}
	if err := b.Verify(); err != nil {
		return nil, fmt.Errorf("session-bind signature: %w", err)
	}
	return b, nil
}

// Frame is an agent message with its u32 length prefix.
func Frame(body []byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(body))), body...)
}

// ExtensionFrame is SSH_AGENTC_EXTENSION(name, contents) framed.
func ExtensionFrame(name string, contents []byte) []byte {
	b := []byte{AgentcExtension}
	b = binary.BigEndian.AppendUint32(b, uint32(len(name)))
	b = append(b, name...)
	return Frame(append(b, contents...))
}

// ReadFrame reads one framed agent message body.
func ReadFrame(r io.Reader) ([]byte, error) {
	var l [4]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(l[:])
	if n == 0 || n > MaxAgentMsg {
		return nil, errors.New("agent frame length out of range")
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}
