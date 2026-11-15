package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/danielbodart/mosey/internal/agent"
	"github.com/danielbodart/mosey/internal/bootstrap"
)

// Timings of the bootstrap ssh after its line (bootstrap.md §4.3).
const (
	// sshExitWait is how long ssh has to exit once the line is out: the
	// launcher has exited by then, so it should take a round trip. It is
	// S3's capture deadline, which the agent slice will need it to be.
	sshExitWait = 10 * time.Second
	// sshKillWait is how long a SIGTERMed ssh has before SIGKILL.
	sshKillWait = time.Second
	// maxDrain bounds what is read from ssh's stdout after the line.
	maxDrain = 64 << 10
)

// spawn is the bootstrap: ssh -G, then the bootstrap ssh, the ClientLine
// up its stdin and the CredentialLine back (bootstrap.md §3–§6). It
// returns the line and the config, and leaves ssh to be reaped in the
// background. Everything it prints goes to stderr through the §6.5
// filter, while the terminal is still cooked.
type spawn struct {
	ssh    bootstrap.SSH
	line   bootstrap.ClientLine
	stderr io.Writer
	log    *slog.Logger
	getenv func(string) string
	// cfg is what ssh -G said, once run has asked it.
	cfg bootstrap.Config
	// forward is the agent forwarding the bootstrap set up, or nil for
	// none (bootstrap.md §5, §8); saidAgentOff is whether the user has
	// been told why not, which run, tried again after a D7 copy, says
	// only once.
	forward      *agent.Forwarder
	saidAgentOff bool
}

func (b *spawn) run(ctx context.Context) (bootstrap.CredentialLine, bootstrap.Config, error) {
	dest := b.ssh.Destination
	cfg, err := b.ssh.Resolve(ctx)
	if err != nil {
		var re *bootstrap.ResolveError
		if errors.As(err, &re) {
			b.show(re.Stderr)
		}
		if ctx.Err() != nil {
			return bootstrap.CredentialLine{}, nil, ctx.Err()
		}
		return bootstrap.CredentialLine{}, nil, fail(err, "ssh -G %s failed", dest)
	}
	b.cfg = cfg
	// D25: forward the agent exactly when ssh would (bootstrap.md §5),
	// through a capture socket that takes ssh's own session-bind (§8).
	capt, sock := b.startCapture(cfg)
	if capt != nil {
		defer capt.Close()
	}

	cmd := b.ssh.Command(ctx, cfg)
	p, err := startPiped(cmd)
	if err != nil {
		return bootstrap.CredentialLine{}, nil, fail(err, "running %s: %v", cmd.Path, err)
	}
	b.log.Info("bootstrap ssh started", "pid", cmd.Process.Pid, "destination", dest, "server", b.ssh.Server)
	if capt != nil {
		// The only connection the capture takes is our ssh's.
		capt.Expect(cmd.Process.Pid)
	}

	// ssh's stderr goes to the user until the line, and then only to the
	// log, both through the filter: it carries the far side's stderr, and
	// D9 says no remote escape sequence reaches the local terminal.
	sink := &switchWriter{w: b.stderr}
	copied := make(chan struct{})
	go func() {
		defer close(copied)
		w := bootstrap.Sanitize(sink)
		io.Copy(w, p.stderr)
		w.Close()
		p.stderr.Close()
	}()

	// One write, before authentication: at most 4 KiB into a 64 KiB pipe,
	// so it cannot block, and ssh delivers it and then EOF.
	if _, err := p.stdin.Write(bootstrap.MarshalClientLine(b.line)); err != nil {
		b.log.Warn("writing the client line", "err", err)
	}
	p.stdin.Close()

	cred, err := bootstrap.ReadCredential(p.stdout)
	if err != nil {
		var nl *bootstrap.NoLineError
		var ns *bootstrap.NoServerError
		if !errors.As(err, &ns) && (!errors.As(err, &nl) || nl.Overflow) {
			// ssh may be running on: nothing more it says is wanted.
			cmd.Process.Kill()
		}
		p.stdout.Close()
		status := reap(cmd, b.log)
		waitFor(copied, sshKillWait)
		if ctx.Err() != nil {
			return bootstrap.CredentialLine{}, nil, ctx.Err()
		}
		return bootstrap.CredentialLine{}, nil, b.explain(err, status)
	}
	sink.set(&logLines{log: b.log})
	go drain(p.stdout)
	exited := make(chan struct{})
	go func() { reap(cmd, b.log); close(exited) }()
	b.log.Info("credential line read", "server", cred.SoftwareVersion, "addr", cred.Addr, "port", cred.Port)
	if capt != nil {
		b.finishCapture(ctx, capt, cfg, sock, exited)
	}
	return cred, cfg, nil
}

// startCapture decides whether to forward the agent (bootstrap.md §5) and,
// if so, listens on a capture socket, points the bootstrap ssh's
// ForwardAgent at it, and says agent=yes in the line (§8 steps 1–2). It
// returns the capture and the agent socket to forward, or nil.
func (b *spawn) startCapture(cfg bootstrap.Config) (*agent.Capture, string) {
	sock, on := bootstrap.AgentSocket(cfg, b.getenv)
	fa := cfg.Get("forwardagent")
	b.log.Info("agent forwarding", "config", fa, "wanted", on, "socket", sock)
	if !on {
		if fa != "" && fa != "no" {
			name := "SSH_AUTH_SOCK"
			if strings.HasPrefix(fa, "$") {
				name = fa[1:]
			}
			b.agentOff(name + " is not set")
		}
		return nil, ""
	}
	capt, err := agent.ListenCapture(agent.CaptureDir(b.getenv))
	if err != nil {
		b.agentOff(err.Error())
		return nil, ""
	}
	b.ssh.AgentCapture = capt.Path
	b.line.Agent = true
	return capt, sock
}

// finishCapture waits for the capture's final state, pins the bind to
// known_hosts, and, if both hold, sets up forwarding (bootstrap.md §8
// steps 4–7). Anything else leaves the agent off, said once on stderr.
func (b *spawn) finishCapture(ctx context.Context, capt *agent.Capture, cfg bootstrap.Config, sock string, exited <-chan struct{}) {
	// The bind normally came before the line did; the bound is for a
	// far side that holds the channel, and the time ssh may take to exit.
	ctx, cancel := context.WithTimeout(ctx, agent.CaptureDeadline+sshExitWait)
	defer cancel()
	bind, err := capt.Result(ctx, exited)
	if err != nil {
		b.agentOff(err.Error())
		return
	}
	host, port := cfg.Get("hostkeyalias"), 22
	if host == "" || host == "none" {
		host = cfg.Get("hostname")
		if p, err := strconv.Atoi(cfg.Get("port")); err == nil {
			port = p
		}
	}
	// An alias is looked up bare, whatever the port, as ssh itself looks
	// it up [ssh: a HostKeyAlias entry with no port is accepted on any].
	files := append(strings.Fields(cfg.Get("userknownhostsfile")), strings.Fields(cfg.Get("globalknownhostsfile"))...)
	if err := agent.Pin(bind.HostKey, host, port, files); err != nil {
		b.agentOff(err.Error())
		return
	}
	b.log.Info("agent forwarding on", "socket", sock, "host key", ssh.FingerprintSHA256(bind.HostKey))
	b.forward = &agent.Forwarder{Dial: agent.DialUnix(sock), Bind: bind, Log: b.log}
}

// agentOff says once, before the screen is up, why the agent is not
// forwarded (agent.md §2.4); the session goes on without it.
func (b *spawn) agentOff(why string) {
	b.log.Warn("not forwarding the agent", "why", why)
	if b.saidAgentOff {
		return
	}
	b.saidAgentOff = true
	w := bootstrap.Sanitize(b.stderr)
	fmt.Fprintf(w, "mosey: not forwarding the agent: %s\n", why)
	w.Close()
}

// explain turns a bootstrap failure into what the user reads
// (bootstrap.md §6.4, §10), showing first anything the far side said.
func (b *spawn) explain(err error, status int) error {
	dest := b.ssh.Destination
	var (
		remote *bootstrap.RemoteError
		nl     *bootstrap.NoLineError
		ver    *bootstrap.VersionError
		ns     *bootstrap.NoServerError
	)
	switch {
	case errors.As(err, &ns):
		// The probe's answer (§4.7.2): Run copies mosey over.
		return fail(err, "no mosey %s on %s", b.line.SoftwareVersion, dest)
	case errors.As(err, &remote):
		return b.refused(remote)
	case errors.As(err, &ver):
		return fail(err, "%s sent a mosey line of protocol %d; this mosey speaks %d: install %s there or pass -remote", dest, ver.Got, bootstrap.Version, b.line.SoftwareVersion)
	case errors.Is(err, bootstrap.ErrBadLine):
		return fail(err, "%s sent a malformed mosey line", dest)
	case errors.As(err, &nl):
		b.show(nl.Tail)
		switch {
		case nl.Overflow:
			return fail(err, "%s printed over %d bytes and no mosey line", dest, bootstrap.MaxPreamble)
		case status == 255:
			// ssh has said why on stderr already.
			return fail(err, "ssh to %s failed", dest)
		case status == 126 || status == 127:
			return fail(fmt.Errorf("%w: %w", bootstrap.ErrNoServer, err),
				"no mosey at %s on %s: install it there or pass -remote", b.ssh.Server, dest)
		case status < 0:
			return fail(err, "ssh to %s was killed", dest)
		}
		return fail(err, "the remote mosey exited with status %d", status)
	}
	return fail(err, "reading from ssh: %v", err)
}

// refused is the user's message for a server's ErrorLine (bootstrap.md
// §6.4).
func (b *spawn) refused(e *bootstrap.RemoteError) error {
	switch e.Code {
	case bootstrap.CodeLine:
		return fail(e, "the server could not read this client's request: a bug, please report it")
	case bootstrap.CodeVersion:
		if e.Proto == bootstrap.Version {
			// The line versions agree, so what was refused is this
			// client's software version: only a server from before the
			// stable protocol does that (D8 V1), which serves only its
			// own release.
			return fail(e, "the remote mosey %s predates the stable protocol and serves only clients of its own version: install %s there or pass -remote",
				e.Detail, b.line.SoftwareVersion)
		}
		// A line version the server cannot read: with one line version
		// there is none older to send again at (§6.1).
		return fail(e, "the remote mosey %s cannot read this client's request (bootstrap protocol %d, it speaks %d)",
			e.Detail, bootstrap.Version, e.Proto)
	case bootstrap.CodeUnsupported:
		return fail(e, "the remote mosey can't do %s yet", e.Detail)
	case bootstrap.CodeSession:
		return fail(e, "no such session on %s", b.ssh.Destination)
	case bootstrap.CodeTaken:
		return fail(e, "the session on %s is held by another client", b.ssh.Destination)
	case bootstrap.CodeInternal:
		return fail(e, "the server failed to start (see above)")
	}
	return fail(e, "the server refused: %s (see above)", e.Code)
}

// show writes what the far side said to stderr, filtered.
func (b *spawn) show(p []byte) {
	if len(p) == 0 {
		return
	}
	w := bootstrap.Sanitize(b.stderr)
	w.Write(p)
	w.Close()
	if p[len(p)-1] != '\n' {
		b.stderr.Write([]byte("\n"))
	}
}

// piped is the parent's ends of a child's stdio pipes.
type piped struct {
	stdin          *os.File
	stdout, stderr *os.File
}

// startPiped starts cmd with its stdio on pipes the parent holds. The
// pipes are *os.Files rather than exec's own, so cmd.Wait never waits on
// a copying goroutine and the parent decides when each end closes.
func startPiped(cmd *exec.Cmd) (*piped, error) {
	inR, inW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		inR.Close()
		inW.Close()
		return nil, err
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		inR.Close()
		inW.Close()
		outR.Close()
		outW.Close()
		return nil, err
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = inR, outW, errW
	err = cmd.Start()
	inR.Close()
	outW.Close()
	errW.Close()
	if err != nil {
		inW.Close()
		outR.Close()
		errR.Close()
		return nil, err
	}
	return &piped{stdin: inW, stdout: outR, stderr: errR}, nil
}

// drain reads what ssh's stdout still says after the line, up to a bound,
// so ssh is never blocked writing it, then closes it.
func drain(r io.ReadCloser) {
	io.Copy(io.Discard, io.LimitReader(r, maxDrain))
	r.Close()
}

// reap waits for the bootstrap ssh to exit, which after its stdout has
// ended it should within a round trip, and makes sure it does
// (bootstrap.md §4.3): SIGTERM after sshExitWait, SIGKILL sshKillWait
// later. It returns ssh's exit status. After a good line it runs in the
// background, and a non-zero exit is logged, not fatal: the session no
// longer depends on SSH.
func reap(cmd *exec.Cmd, log *slog.Logger) int {
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var err error
	select {
	case err = <-done:
	case <-time.After(sshExitWait):
		log.Warn("bootstrap ssh still running; terminating it")
		cmd.Process.Signal(syscall.SIGTERM)
		select {
		case err = <-done:
		case <-time.After(sshKillWait):
			cmd.Process.Kill()
			err = <-done
		}
	}
	status := bootstrap.ExitStatus(err)
	log.Info("bootstrap ssh exited", "status", status)
	return status
}

func waitFor(c <-chan struct{}, d time.Duration) {
	select {
	case <-c:
	case <-time.After(d):
	}
}

// switchWriter is a writer whose destination can change while it is
// being written to: ssh's stderr moves from the user to the log when the
// line arrives.
type switchWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *switchWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.w.Write(p)
	return len(p), nil
}

func (s *switchWriter) set(w io.Writer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.w = w
}

// logLines logs each line written to it, already filtered, as one record.
type logLines struct {
	log  *slog.Logger
	part []byte
}

func (l *logLines) Write(p []byte) (int, error) {
	l.part = append(l.part, p...)
	for {
		i := bytes.IndexByte(l.part, '\n')
		if i < 0 {
			break
		}
		if line := strings.TrimSpace(string(l.part[:i])); line != "" {
			l.log.Info("ssh stderr", "line", line)
		}
		l.part = l.part[i+1:]
	}
	if len(l.part) > bootstrap.MaxSanitizedLine*4 {
		l.log.Info("ssh stderr", "line", string(l.part))
		l.part = nil
	}
	return len(p), nil
}
