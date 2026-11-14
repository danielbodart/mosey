package bootstrap

import (
	"io"
	"net/netip"
)

// Version is the bootstrap protocol's version. A server that sees another
// says so on stderr and exits, and D7's copy-over brings it in line.
const Version = 1

// ClientLine is what the client writes to ssh's stdin.
type ClientLine struct {
	// Public is the client's one-shot X-Wing public key (D20).
	Public     []byte
	Cols, Rows int
	// Env is TERM, COLORTERM and the locale variables, for the shell.
	Env map[string]string
}

// CredentialLine is what `mosey --serve` prints on stdout.
type CredentialLine struct {
	// Addr is the server's address as SSH reached it (from SSH_CONNECTION),
	// so the client sends UDP where its SSH config resolved, through any
	// ProxyJump. The client may override it.
	Addr         netip.Addr
	Port         uint16
	CredentialID [8]byte
	SessionID    [16]byte
	PSK          [32]byte
	// Public is the server's one-shot X-Wing public key.
	Public []byte
}

// MarshalClientLine is c as one line, with its newline.
func MarshalClientLine(c ClientLine) []byte { panic("TODO slice 1") }

// ParseClientLine reads a ClientLine, refusing anything not canonical.
func ParseClientLine(line []byte) (ClientLine, error) { panic("TODO slice 1") }

// MarshalCredentialLine is c as one line, with its newline.
func MarshalCredentialLine(c CredentialLine) []byte { panic("TODO slice 1") }

// ParseCredentialLine reads a CredentialLine, refusing anything not
// canonical.
func ParseCredentialLine(line []byte) (CredentialLine, error) { panic("TODO slice 1") }

// ReadCredential reads ssh's stdout up to the credential line, skipping
// other lines, and gives up after a bounded number of bytes.
func ReadCredential(r io.Reader) (CredentialLine, error) { panic("TODO slice 1") }
