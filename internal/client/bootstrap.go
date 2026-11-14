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
	"strings"
	"sync"
	"syscall"
	"time"

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
	// D25: slice 1 always bootstraps with ForwardAgent=no, but works out
	// what the user's config asks for, for the log and the agent slice.
	sock, on := bootstrap.AgentSocket(cfg, b.getenv)
	b.log.Debug("agent forwarding", "config", cfg.Get("forwardagent"), "wanted", on, "socket", sock, "forwarded", false)

	// AGENT SLICE HOOK (bootstrap.md §8, S3 option a'). When `on`, the
	// agent slice, here and nowhere else:
	//   1. listens on a capture socket in a fresh 0700 directory and sets
	//      b.ssh.AgentCapture to its path, so Command passes
	//      ForwardAgent=<capture socket> instead of no;
	//   2. sends agent=yes in b.line;
	//   3. after startPiped, tells the capture its only acceptable peer:
	//      cmd.Process.Pid and our uid;
	//   4. reads the capture's result only after reap has seen ssh exit
	//      (so the far side controls no timer), pins the bind to
	//      known_hosts, and on NoBind carries on with the agent off.
	// Until then AgentCapture stays "" and the line says agent=no.

	cmd := b.ssh.Command(ctx, cfg)
	p, err := startPiped(cmd)
	if err != nil {
		return bootstrap.CredentialLine{}, nil, fail(err, "running %s: %v", cmd.Path, err)
	}
	b.log.Info("bootstrap ssh started", "pid", cmd.Process.Pid, "destination", dest, "server", b.ssh.Server)

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
	go reap(cmd, b.log)
	b.log.Info("credential line read", "server", cred.SoftwareVersion, "addr", cred.Addr, "port", cred.Port)
	return cred, cfg, nil
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
// §6.4). The D7 slice answers a version refusal with an upload instead.
func (b *spawn) refused(e *bootstrap.RemoteError) error {
	switch e.Code {
	case bootstrap.CodeLine:
		return fail(e, "the server could not read this client's request: a bug, please report it")
	case bootstrap.CodeVersion:
		if b.line.Resume {
			// An upgrade ends resumability (bootstrap.md §9.2 step 5): no
			// upload, which would install this version, not the session's.
			return fail(e, "the session runs version %s; this is %s: resume it with mosey %s, or end it from a new session", e.Detail, b.line.SoftwareVersion, e.Detail)
		}
		theirs := e.Detail
		if e.Proto != bootstrap.Version {
			theirs = fmt.Sprintf("%s (bootstrap protocol %d; this is %d)", theirs, e.Proto, bootstrap.Version)
		}
		return fail(e, "the remote mosey is version %s, this is %s: install %s there or pass -remote", theirs, b.line.SoftwareVersion, b.line.SoftwareVersion)
	case bootstrap.CodeUnsupported:
		return fail(e, "the remote mosey can't do %s yet", e.Detail)
	case bootstrap.CodeSession:
		return fail(e, "no session to resume on %s", b.ssh.Destination)
	case bootstrap.CodeAmbiguous:
		return fail(e, "%s sessions on %s: name one with -r=SESSION (mosey -list %s shows them)", e.Detail, b.ssh.Destination, b.ssh.Destination)
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
