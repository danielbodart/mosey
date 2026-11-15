package bootstrap

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

// SSH is how the client runs the system ssh for a bootstrap (D6): the
// user's own ssh, config, keys and known_hosts, with the few options the
// bootstrap needs placed first so nothing in the user's config undoes them.
type SSH struct {
	// Program is ssh; "ssh" looks it up on PATH.
	Program string
	// Destination is what the user typed: host, user@host, an alias from
	// their ssh config, or ssh://user@host:port. Passed to ssh unchanged,
	// after --.
	Destination string
	// Options are the user's own ssh options, filtered (§2.1).
	Options SSHOptions
	// Server is the remote mosey binary, run as `Server --serve`: -remote's
	// path. Empty is D7's probe (§4.7.2), which runs mosey on the remote
	// PATH, of whatever version, or else ~/.cache/mosey/mosey if it
	// answers Protocol, and otherwise says what the host is.
	Server string
	// Protocol is what the probe needs the cached copy's --serve=protocol
	// to say: ProtocolAnswer, this client's protocol numbers. Only the
	// probe uses it.
	Protocol string
	// AgentCapture is the capture socket for D25's bind capture (§8):
	// when set, the bootstrap runs with ForwardAgent=AgentCapture. Empty
	// is ForwardAgent=no.
	AgentCapture string
	// Role is the server role to run: "" for the bootstrap's own
	// `--serve`, RoleList for `--serve=list` (§9.4), which reads no line
	// and prints the user's sessions, or RoleKill for `--serve=kill
	// RoleArg` (§9.5), which ends the session called RoleArg.
	Role    string
	RoleArg string
	// Batch runs ssh with BatchMode=yes: R3's background reconnect, which
	// must never ask the user anything (§9.2.2).
	Batch bool
}

// The server roles the client runs (§9.4, §9.5).
const (
	RoleList = "list"
	RoleKill = "kill"
)

// Bounds on what the user may name (§2, §4.1).
const (
	maxDestination = 1024
	maxServer      = 256
)

// ResolveTimeout bounds ssh -G, which makes no connection but may run the
// config's Match exec commands (§3).
const ResolveTimeout = 10 * time.Second

// Check says whether Destination and Server can be passed on safely (§2,
// §4.1). Its errors are *UsageError.
func (s SSH) Check() error {
	d := s.Destination
	if d == "" || len(d) > maxDestination || d[0] == '-' {
		return &UsageError{fmt.Sprintf("mosey: %q is not a destination", d)}
	}
	for i := 0; i < len(d); i++ {
		// ssh would read a space as the start of the remote command.
		if d[i] < 0x21 || d[i] == 0x7f {
			return &UsageError{fmt.Sprintf("mosey: %q is not a destination", d)}
		}
	}
	switch {
	case s.Role != "" && s.Role != RoleList && s.Role != RoleKill:
		return &UsageError{fmt.Sprintf("mosey: no server role %q", s.Role)}
	case s.Role == RoleKill && !ValidSessionName(s.RoleArg):
		return &UsageError{fmt.Sprintf("mosey: %q is not a session name: 1 to 32 letters, digits, '-', '_' and '.', starting with a letter or digit", s.RoleArg)}
	case s.Role != RoleKill && s.RoleArg != "":
		return &UsageError{"mosey: only --serve=kill takes a session name"}
	}
	if s.Server != "" && !ValidServer(s.Server) {
		return &UsageError{fmt.Sprintf("mosey: -remote %q: a remote path may hold only letters, digits and ._/+- (and start with ~/)", s.Server)}
	}
	return nil
}

// ValidServer says whether path may be the remote mosey (§4.1):
//
//	server   = [ "~/" ] 1*pathchar    ; at most 256 bytes, not starting with -
//	pathchar = ALPHA / DIGIT / "." / "_" / "/" / "+" / "-"
//
// Nothing in it needs quoting in any login shell or in /bin/sh, so the
// remote command can be written without quoting it, and a leading ~/ is
// left for the remote /bin/sh to expand, as D7's ~/.cache/mosey/mosey needs.
func ValidServer(path string) bool {
	if len(path) > maxServer {
		return false
	}
	if rest, ok := cutHome(path); ok {
		path = rest
	}
	if path == "" || path[0] == '-' {
		return false
	}
	for i := 0; i < len(path); i++ {
		c := path[i]
		if !isAlnum(c) && c != '.' && c != '_' && c != '/' && c != '+' && c != '-' {
			return false
		}
	}
	return true
}

func cutHome(path string) (string, bool) {
	if len(path) >= 2 && path[:2] == "~/" {
		return path[2:], true
	}
	return path, false
}

// ResolveError is ssh -G failing: a typo in ~/.ssh/config or a bad -o
// shows up here, and ssh's stderr says which. Stderr is ssh's, unfiltered
// and bounded; whoever shows it passes it through Sanitize.
type ResolveError struct {
	Stderr []byte
	Err    error
}

func (e *ResolveError) Error() string { return fmt.Sprintf("ssh -G: %v", e.Err) }
func (e *ResolveError) Unwrap() error { return e.Err }

// Resolve runs `ssh -G` to learn what the user's config says for this
// destination (§3), with the user's options and agent flag, no stdin, and
// a deadline.
func (s SSH) Resolve(ctx context.Context) (Config, error) {
	ctx, cancel := context.WithTimeout(ctx, ResolveTimeout)
	defer cancel()
	args := []string{"-G"}
	args = append(args, s.Options.Args...)
	if s.Options.Agent != 0 {
		args = append(args, "-"+string(s.Options.Agent))
	}
	args = append(args, "--", s.Destination)
	cmd := exec.CommandContext(ctx, s.program(), args...)
	var stdout, stderr limitedBuffer
	stdout.max, stderr.max = MaxConfig+1, 64<<10
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			err = fmt.Errorf("%w (after %v)", ctx.Err(), ResolveTimeout)
		}
		return nil, &ResolveError{Stderr: stderr.Bytes(), Err: err}
	}
	c, err := ParseConfig(stdout.Bytes())
	if err != nil {
		return nil, &ResolveError{Stderr: stderr.Bytes(), Err: err}
	}
	return c, nil
}

func (s SSH) program() string {
	if s.Program == "" {
		return "ssh"
	}
	return s.Program
}

// RemoteCommand is the one argument ssh hands to the remote login shell
// (§4.1). The /bin/sh wrapper is there for its exit status: a missing
// server exits 127 and one that will not run 126 under it, whatever the
// login shell (tcsh and nushell would say 1), which is how the client
// tells "no mosey there" from other failures (§4.2). The outer exec keeps
// the login shell out of the process tree and the inner one makes the
// launcher the process sshd waits for.
func (s SSH) RemoteCommand() string {
	if s.Server == "" {
		return probeCommand(s.Protocol, s.flag())
	}
	return wrap("exec " + s.Server + " " + s.flag())
}

// flag is --serve with the role, if any, and kill's session name. Check
// has made sure the role is one of ours and the name an sname, so neither
// needs quoting (§9.5).
func (s SSH) flag() string {
	switch s.Role {
	case "":
		return "--serve"
	case RoleKill:
		return "--serve=" + s.Role + " " + s.RoleArg
	}
	return "--serve=" + s.Role
}

// Probes reports whether RemoteCommand is §4.7.2's probe, which may answer
// with a ProbeLine. Only a new session's is answered with an upload: R3,
// -list and -kill copy nothing (§4.7.1).
func (s SSH) Probes() bool { return s.Server == "" }

// wrap is §4.1's wrapper: script, run by /bin/sh whatever the login shell.
// script must hold no ' (it ends the quoting), no \ (fish reads \' and \\
// inside single quotes), no ! and no newline (csh), so every login shell
// hands it to /bin/sh unchanged.
func wrap(script string) string {
	return "exec /bin/sh -c '" + script + "'"
}

// probeCommand is §4.7.2's probe. protocol is this client's
// ProtocolAnswer, digits and one space, so it needs no quoting; anything
// else is never put in the script, and no cached copy is run.
//
// mosey on the remote PATH comes first and is exec'd as it is, whatever
// its version (Dan, 2026-11-15: whatever mosey the host has): if it
// speaks another protocol, the bootstrap line or the handshake says so.
// Otherwise the cached copy, ~/.cache/mosey/mosey, is a candidate only if
// neither ~/.cache/mosey nor the file is a symlink and both, and
// ~/.cache, are the user's: the installer's own rules (§4.7.7), so the
// probe never runs a file from a place it would refuse to write. It is
// asked --serve=protocol with stdin on /dev/null (the ClientLine waiting
// there is the launcher's) and stderr dropped, and exec'd as flag (the
// launcher's --serve, or a role's) only if it says exactly protocol.
// Otherwise one MOSEY-PROBE line saying what the host is, and exit 0, so
// 126 and 127 keep their slice-1 meaning. (The script may hold no !, so
// "not a symlink" is the empty then-branch.)
func probeCommand(protocol, flag string) string {
	if !validProtocolAnswer(protocol) {
		protocol = "-"
	}
	return wrap(`if command -v mosey >/dev/null 2>&1; then exec mosey ` + flag + `; fi; ` +
		`c="$HOME/.cache/mosey"; f="$c/mosey"; ` +
		`if test -h "$c" || test -h "$f"; then :; ` +
		`elif test -O "$HOME/.cache" && test -O "$c" && test -O "$f" && ` +
		`[ "$("$f" --serve=protocol </dev/null 2>/dev/null)" = "` + protocol + `" ]; then exec "$f" ` + flag + `; fi; ` +
		`s=$(uname -s 2>/dev/null); a=$(uname -m 2>/dev/null); ` +
		`echo "` + probeMagic + ` ` + strconv.Itoa(Version) + ` ${s:-unknown} ${a:-unknown}"`)
}

// uploadCommand is §4.7.6's: the binary arrives on stdin, goes to a
// mktemp file in ~/.cache/mosey (not /tmp, which is often noexec, and on
// the filesystem it is renamed within), and then runs as
// --serve=install, which checks it and moves it into place as
// ~/.cache/mosey/mosey (§4.7.7). The temporary name is removed whatever
// happened; after a success it is already gone.
func uploadCommand(hash [32]byte, size int64) string {
	return wrap(`umask 077; d="$HOME/.cache/mosey"; mkdir -p "$d" || exit 1; ` +
		`t=$(mktemp "$d/.upload.XXXXXXXX") || exit 1; ` +
		`cat >"$t" && chmod 700 "$t" && "$t" --serve=install ` + hex.EncodeToString(hash[:]) + " " + strconv.FormatInt(size, 10) + ` "$t"; ` +
		`s=$?; rm -f "$t"; exit $s`)
}

// Command is the bootstrap ssh (§4.1). c is what Resolve found, which says
// whether this ssh knows SessionType, StdinNull and ForkAfterAuthentication.
//
// The options come first because ssh uses the first value it obtains for
// each, and reads the command line before any config file, so neither the
// user's -o nor their config can undo them; the flags that would beat a -o
// (-A, -t) never get here (§2.1).
func (s SSH) Command(ctx context.Context, c Config) *exec.Cmd {
	return s.command(ctx, c, s.RemoteCommand())
}

// UploadCommand is §4.7.6's ssh: the bootstrap's own options, so nothing
// is forwarded and the user's config cannot undo them, running the upload
// script, which reads a binary of size bytes and SHA-256 hash on stdin
// and installs it as ~/.cache/mosey/mosey.
func (s SSH) UploadCommand(ctx context.Context, c Config, hash [32]byte, size int64) *exec.Cmd {
	return s.command(ctx, c, uploadCommand(hash, size))
}

func (s SSH) command(ctx context.Context, c Config, remote string) *exec.Cmd {
	forwardAgent := "no"
	if s.AgentCapture != "" {
		forwardAgent = s.AgentCapture
	}
	args := []string{
		// No pty: the bootstrap is two lines of protocol, and a pty would
		// echo stdin and turn LF into CRLF.
		"-T",
		// Always a fresh connection: a multiplexed one has no key exchange
		// of its own, so no session-bind to capture, and its agent would be
		// the master's (S3 E12, E12b).
		"-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ControlPersist=no",
		"-o", "ForwardAgent=" + forwardAgent,
		// No forwarding of any kind (threat-model §4.9): the bootstrap
		// needs none, and a config's X11 or port forwards would give the
		// far host a way back in, or collide with the user's own ssh.
		"-o", "ForwardX11=no", "-o", "ClearAllForwardings=yes", "-o", "Tunnel=no",
		// A config LocalCommand must not run, nor escapes act on a pipe.
		"-o", "PermitLocalCommand=no", "-o", "EscapeChar=none",
		// A config RemoteCommand and a command on the line is an error.
		"-o", "RemoteCommand=none",
	}
	if s.Batch {
		// R3's reconnect runs while the screen is up: no question may be
		// put, so a login that would need one fails instead (§9.2.2).
		args = append(args, "-o", "BatchMode=yes")
	}
	// A config SessionType none or StdinNull yes would break the
	// bootstrap, but an ssh older than 8.7 refuses the keywords, so they
	// are forced only where ssh -G shows they exist.
	for _, kw := range []struct{ keyword, option string }{
		{"sessiontype", "SessionType=default"},
		{"stdinnull", "StdinNull=no"},
		{"forkafterauthentication", "ForkAfterAuthentication=no"},
	} {
		if c.Has(kw.keyword) {
			args = append(args, "-o", kw.option)
		}
	}
	args = append(args, s.Options.Args...)
	args = append(args, "--", s.Destination, remote)
	cmd := exec.CommandContext(ctx, s.program(), args...)
	cmd.WaitDelay = time.Second
	if s.Batch {
		// BatchMode stops ssh's own questions but not those of what ssh
		// starts: a ProxyCommand, a ProxyJump's inner ssh (which does not
		// inherit -o BatchMode) or a KnownHostsCommand could open
		// /dev/tty and draw over the screen or read keystrokes (§9.2.2).
		// In a session of its own ssh has no controlling terminal, so
		// nothing it starts can find one; and SSH_ASKPASS_REQUIRE=never
		// (ssh(1)) stops any of them asking through a graphical askpass
		// instead.
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		cmd.Env = append(os.Environ(), "SSH_ASKPASS_REQUIRE=never")
	}
	return cmd
}

// limitedBuffer keeps the first max bytes written to it and drops the
// rest, so a runaway child cannot fill memory.
type limitedBuffer struct {
	bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.Len(); room > 0 {
		b.Buffer.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

var _ io.Writer = (*limitedBuffer)(nil)

// ExitStatus is ssh's exit status from err as cmd.Wait returned it, or -1
// if ssh did not exit normally.
func ExitStatus(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}
