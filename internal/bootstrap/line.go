package bootstrap

import (
	"errors"
	"io"
	"net/netip"
)

// The line types are bootstrap.md §10.1's, so the server can be written
// against them; the bodies are bootstrap-client's to fill in.

const (
	// Version is the bootstrap protocol's version. A server that sees another
	// says so on stderr and exits, and D7's copy-over brings it in line.
	Version           = 1
	MaxClientLine     = 4096
	MaxCredentialLine = 2048
	MaxErrorLine      = 128 // frozen with the ErrorLine grammar
	MaxPreamble       = 64 << 10
)

// ClientLine is what the client writes to ssh's stdin (bootstrap.md §6.2).
type ClientLine struct {
	SoftwareVersion string   // swver
	Resume          bool     // attach: false = "new"
	SessionID       [16]byte // attach = resume:SID, when Resume
	Agent           bool     // agent
	Cols, Rows      uint16   // 1..65535
	// Env is TERM, COLORTERM and the locale variables, for the shell.
	Env map[string]string
	// Public is the client's one-shot X-Wing public key (D20).
	Public []byte
}

// CredentialLine is what `mosey --serve` prints on stdout (§6.3).
type CredentialLine struct {
	SoftwareVersion string
	// Addr is the server's address as SSH reached it (from SSH_CONNECTION),
	// so the client sends UDP where its SSH config resolved, through any
	// ProxyJump; the zero Addr is "-".
	Addr         netip.Addr
	Port         uint16
	CredentialID [8]byte
	SessionID    [16]byte
	PSK          [32]byte
	// Public is the server's one-shot X-Wing public key.
	Public []byte
}

// ErrorLine is a server's refusal on stdout (§6.4); Detail "" is "-".
type ErrorLine struct {
	Proto  int
	Code   string
	Detail string
}

const (
	CodeLine        = "line"
	CodeVersion     = "version"
	CodeUnsupported = "unsupported"
	CodeSession     = "session"
	CodeInternal    = "internal"
)

var (
	ErrBadLine = errors.New("bootstrap: malformed mosey line")
	ErrNoLine  = errors.New("bootstrap: no mosey line")
)

// VersionError is a line whose proto is not Version; errors.Is(err,
// ErrBadLine) is true.
type VersionError struct{ Got int }

func (e *VersionError) Error() string { panic("TODO slice 1") }

// MarshalClientLine is c as one line, with its newline.
func MarshalClientLine(c ClientLine) []byte { panic("TODO slice 1") }

// ParseClientLine reads a ClientLine, refusing anything not canonical.
func ParseClientLine(line []byte) (ClientLine, error) { panic("TODO slice 1") }

// MarshalCredentialLine is c as one line, with its newline.
func MarshalCredentialLine(c CredentialLine) []byte { panic("TODO slice 1") }

// ParseCredentialLine reads a CredentialLine, refusing anything not
// canonical.
func ParseCredentialLine(line []byte) (CredentialLine, error) { panic("TODO slice 1") }

// MarshalErrorLine is e as one line, with its newline.
func MarshalErrorLine(e ErrorLine) []byte { panic("TODO slice 1") }

// ParseErrorLine reads an ErrorLine of any protocol version.
func ParseErrorLine(line []byte) (ErrorLine, error) { panic("TODO slice 1") }

// ReadCredential reads ssh's stdout up to the credential line, skipping
// other lines, and gives up after a bounded number of bytes.
func ReadCredential(r io.Reader) (CredentialLine, error) { panic("TODO slice 1") }
