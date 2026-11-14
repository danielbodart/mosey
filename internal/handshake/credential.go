package handshake

import (
	"log/slog"
	"time"
)

// Credential is what the server hands the client over SSH stdout: enough
// to start one handshake. Its fields travel in a bootstrap.CredentialLine.
type Credential struct {
	// ID names the credential in msg1's clear header, so the server finds it
	// with one map lookup before any MAC or KEM work. Random and single-use,
	// so it links nothing beyond this one handshake.
	ID [8]byte
	// SessionID names the terminal session, for resume (D8) and logs.
	SessionID [16]byte
	// PSK is defence in depth and the key of msg1's mac1 DoS filter. It is
	// not what authenticates either side; the one-shot keys are.
	PSK [32]byte
	// ServerPublic is the server's one-shot X-Wing public key.
	ServerPublic []byte
}

// Credentials is the server's store of credentials it has minted and the
// client has not yet confirmed (D20): each lives CredentialTTL, at most
// MaxUnused may be outstanding per session, and the oldest is evicted, and
// logged, when a new one would exceed that.
//
// A credential is consumed only when the client confirms it with the first
// authentic transport packet, never on msg1, so msg1s forged with a leaked
// PSK cannot lock the genuine client out.
type Credentials struct{}

const (
	// CredentialTTL is how long a minted credential waits for its
	// handshake: SSH stdout to UDP plus retransmissions (S1, our choice).
	CredentialTTL = 30 * time.Second
	// MaxUnused is how many unconfirmed credentials a session may hold (S1).
	MaxUnused = 2
)

// NewCredentials is an empty store that logs evictions to log.
func NewCredentials(log *slog.Logger) *Credentials {
	panic("TODO slice 1")
}

// Mint makes a credential for the client whose one-shot public key arrived
// over SSH stdin, bound to session.
func (c *Credentials) Mint(session [16]byte, clientPublic []byte) (Credential, error) {
	panic("TODO slice 1")
}
