package bootstrap

import (
	"context"
	"os/exec"
)

// SSH is how the client runs the system ssh for a bootstrap.
type SSH struct {
	// Program is ssh's path; "ssh" looks it up on PATH.
	Program string
	// Destination is what the user typed: a host, user@host, or an alias
	// from their ssh config.
	Destination string
	// Args are extra ssh options from the command line, passed before the
	// destination.
	Args []string
	// Server is the remote mosey binary, run as `Server server`: mosey on
	// PATH, or --server's path. D7's copy-over replaces this in a later
	// slice.
	Server string
	// AgentCapture is the capture socket for D25's bind capture, a later
	// slice. Empty means ForwardAgent=no.
	AgentCapture string
}

// Command is the ssh command line: always a fresh connection
// (ControlMaster=no, ControlPath=none), since a multiplexed session has no
// key exchange of its own and so no session-bind to capture (S3), and
// never a pty (-T), since the bootstrap is two lines of protocol.
func (s SSH) Command(ctx context.Context) *exec.Cmd {
	panic("TODO slice 1")
}
