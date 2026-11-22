package bootstrap

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// LocalDestination is the DESTINATION that is this machine, with no ssh
// (§2.2): the one word every user already reads as this machine, asked
// for by name so that a bare mosey starts nothing (Dan, 2026-11-16).
const LocalDestination = "localhost"

// Local says whether this is mosey localhost: a session on this machine,
// started with no ssh (§2.2). Only the word itself counts, in any case;
// 127.0.0.1, ::1 and me@localhost go through ssh like any other host, so
// the ssh path can still be run against this machine.
func (s SSH) Local() bool { return strings.EqualFold(s.Destination, LocalDestination) }

// checkLocal is Check for the local launcher (§2.2). The server path is
// run with no shell between, so it needs none of ValidServer's quoting
// rules; ssh's own options have no ssh to go to.
func (s SSH) checkLocal() error {
	if len(s.Options.Args) > 0 {
		return &UsageError{"mosey: ssh options have no use with " + LocalDestination + ", which runs without ssh"}
	}
	return s.checkRole()
}

// localHost is where a local client sends UDP when the server names no
// address (§2.2, §7.2): a spawner started with no SSH_CONNECTION binds the
// wildcard and advertises nothing, and loopback reaches the wildcard.
const localHost = "127.0.0.1"

// LocalConfig stands in for ssh -G's output when there is no ssh (§2.2):
// only hostname, for §7.2's fallback, so ChooseAddr takes a loopback
// address the server names and otherwise uses localHost.
func LocalConfig() Config { return Config{"hostname": {localHost}} }

// localEnvDrop is what the local launcher does not inherit from the client
// (§2.2): the marks of an ssh login, which this is not. A client that runs
// inside an ssh session would otherwise have the spawner bind only the
// address that login came in on (SSH_CONNECTION, server.md §2.2), so a
// later client on another network could not reach the session; and the
// launcher would open the client's agent as if sshd had forwarded it
// (§8's trigger), when a local session has no ssh bind to capture.
var localEnvDrop = map[string]bool{
	"SSH_CONNECTION": true,
	"SSH_CLIENT":     true,
	"SSH_TTY":        true,
	"SSH_AUTH_SOCK":  true,
}

// localCommand is the local launcher (§2.2): Server, or this very binary,
// run as the launcher or a role, with the client's environment less
// localEnvDrop. The session it starts is one of this user's sessions on
// this machine like any other: the same spawner and attach sockets, so
// -list shows it and a client over ssh from elsewhere can take it.
func (s SSH) localCommand(ctx context.Context) *exec.Cmd {
	path, err := s.Server, error(nil)
	if path == "" {
		path = s.Self.Path
	}
	if path == "" {
		path, err = os.Executable()
	}
	cmd := exec.CommandContext(ctx, path, strings.Fields(s.flag())...)
	if err != nil {
		// Start returns it: there is no binary to run.
		cmd.Err = fmt.Errorf("finding this mosey's own file: %w", err)
	}
	s.Self.Prepare(cmd)
	cmd.WaitDelay = time.Second
	cmd.Env = localEnv(os.Environ())
	return cmd
}

// localEnv is environ less localEnvDrop.
func localEnv(environ []string) []string {
	env := []string{}
	for _, kv := range environ {
		if name, _, _ := strings.Cut(kv, "="); !localEnvDrop[name] {
			env = append(env, kv)
		}
	}
	return env
}
