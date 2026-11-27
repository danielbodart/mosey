package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/danielbodart/mosey/internal/agent"
	"github.com/danielbodart/mosey/internal/bootstrap"
	"github.com/danielbodart/mosey/internal/ipc"
	"github.com/danielbodart/mosey/internal/startup"
)

// Launcher timeouts (server.md §8).
const (
	// T1 bounds reading the ClientLine: the client writes it before ssh
	// authenticates, so it is there when the command starts; this is
	// handshake.CredentialTTL (bootstrap.md §4.4).
	T1 = 30 * time.Second
	// T2 bounds the wait for the spawner's Ready [derived].
	T2 = 15 * time.Second
)

// Launcher is `mosey --serve`, the process ssh starts (server.md §1.1): it
// reads the client's line, starts the spawner in a session of its own,
// relays the credential line, and exits, so ssh can exit while the session
// lives on. It cannot simply detach: sshd made it a session leader, so
// setsid would fail, and Go cannot fork without exec, so the fork is an
// exec of the spawner.
type Launcher struct {
	// Stdin, Stdout and Stderr are ssh's.
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	// Self is this mosey, started again as `--serve=spawner`.
	Self startup.Process
	// Env is the spawner's environment: the launcher's own, unchanged.
	Env []string
	// Trigger opens sshd's forwarded agent to make the client's ssh send
	// its bind (bootstrap.md §8): agent.Trigger, unless a test sets it.
	Trigger func(ctx context.Context, sock string) error
	// sessions overrides the sessions directory, which on macOS is always
	// /tmp/mosey-UID (server.md §10); a test hook, as the spawner's is.
	sessions string
}

// LaunchError is a bootstrap failure the client is told about with an
// ErrorLine, and the user with Text on stderr.
type LaunchError struct {
	Code, Detail string
	Text         string
}

func (e *LaunchError) Error() string { return e.Text }

// Run does the launcher's part. Any failure has already been reported on
// stdout and stderr when it returns, and has left nothing running.
func (l *Launcher) Run(ctx context.Context) error {
	err := l.run(ctx)
	var silent *silentError
	if err != nil && !errors.As(err, &silent) {
		var le *LaunchError
		if !errors.As(err, &le) {
			le = &LaunchError{Code: bootstrap.CodeInternal, Text: err.Error()}
		}
		fmt.Fprintf(l.Stderr, "mosey --serve: %s\n", le.Text)
		l.Stdout.Write(bootstrap.MarshalErrorLine(bootstrap.ErrorLine{
			Proto: bootstrap.Version, Code: le.Code, Detail: le.Detail,
		}))
	}
	return err
}

func (l *Launcher) run(ctx context.Context) error {
	if !serverRuns {
		return &LaunchError{Code: bootstrap.CodeUnsupported, Text: "the server runs on Linux only for now"}
	}
	// Before the credential line passes through, as in the spawner
	// (threat-model.md §4.10).
	if err := setNotDumpable(); err != nil {
		return err
	}
	line, err := readClientLine(ctx, l.Stdin)
	if err != nil {
		return err
	}
	cl, err := parseClientLine(line)
	if err != nil {
		return err
	}

	// Choosing and starting are one step (bootstrap.md §9.2 "The lock"):
	// the lock is held until the spawner has answered.
	base := l.sessionsDir()
	lock, err := lockSessions(base, T2)
	if err != nil {
		return err
	}
	defer lock.Close()
	var sessions []bootstrap.SessionLine
	var conns []liveSession
	for _, s := range liveSessions(base) {
		// Every session whose greeting parses, of any attach protocol,
		// and every one whose greeting has a critical field this build
		// does not know, which ParseSessionLine still names: choose
		// passes over those for auto, and names them for name:NAME and
		// resume:SID (bootstrap.md §9.2 step 5).
		g, err := bootstrap.ParseSessionLine(s.greeting)
		if err != nil && g.Unknown == "" {
			s.f.Close()
			continue
		}
		sessions, conns = append(sessions, g), append(conns, s)
	}
	c := choose(cl, sessions, GenerateName)
	for i, s := range conns {
		if c.start || c.err != nil || i != c.take {
			s.f.Close()
		}
	}
	switch {
	case c.err != nil:
		return c.err
	case c.start:
		// -dir is checked here, before anything starts, so a missing one
		// is the user's clear error and no session (bootstrap.md §9.2.3).
		// The spawner resolves it again to start the shell there.
		if cl.Dir != "" {
			_, home := shellAndHome(l.getenv, passwdFile)
			if _, err := startDir(home, cl.Dir); err != nil {
				return &LaunchError{Code: bootstrap.CodeDir, Text: fmt.Sprintf("the directory %q is not one: %v", cl.Dir, err)}
			}
		}
		cl.Attach, cl.Name, cl.HasHolder = bootstrap.AttachNew, c.name, false
		return l.start(ctx, bootstrap.MarshalClientLine(cl), cl)
	}
	taken := conns[c.take]
	defer taken.f.Close()
	// A reconnect keeps its holder (resume:SID:CREDID): the spawner holds
	// the session for that client while the new credential is out, so the
	// same client's next try still finds it its own (bootstrap.md §9.2.2).
	// -dir, -type and a command are for a session being created: an
	// existing one ignores them, so they are not passed on (bootstrap.md
	// §9.2.3).
	to := cl
	to.Attach, to.SessionID, to.Name = bootstrap.AttachResume, sessions[c.take].SessionID, ""
	to.Dir, to.Type, to.Command = "", "", ""
	return l.resume(ctx, taken.f, bootstrap.MarshalClientLine(to), cl, notRun(cl, sessions[c.take]))
}

// start is a new session: the spawner, started in a session of its own,
// gets the line, which names the session (new:NAME), and answers with the
// credential line (server.md §2.1).
func (l *Launcher) start(ctx context.Context, line []byte, cl bootstrap.ClientLine) error {
	ours, theirs, err := ipc.Pair()
	if err != nil {
		return err
	}
	conn, err := ipc.NewConn(ours, ipc.Launcher, ipc.Spawner)
	if err != nil {
		return err
	}
	defer conn.Close()
	cmd := selfCommand(l.Self, "--serve=spawner")
	cmd.Env = l.Env
	// No copy of ssh's pipes, or ssh would wait for the spawner: stdio is
	// /dev/null, and the spawner opens its own log.
	cmd.ExtraFiles = []*os.File{theirs}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		theirs.Close()
		return fmt.Errorf("starting the spawner: %w", err)
	}
	theirs.Close()
	go cmd.Wait()
	abandon := func() { cmd.Process.Kill() }

	if err := conn.Send(ipc.ClientLine{Line: line}); err != nil {
		abandon()
		return fmt.Errorf("the server did not start: %w", err)
	}
	m, err := conn.RecvUntil(ctx, time.Now().Add(T2))
	if err != nil {
		abandon()
		return fmt.Errorf("the server did not start")
	}
	switch m := m.(type) {
	case ipc.Ready:
		l.trigger(ctx, cl)
		// One write: the client reads a whole line. Then the line is
		// wiped: harmless to leak by D20, but no reason to keep it
		// (threat-model.md §4.10).
		_, err := l.Stdout.Write(m.Line)
		clear(m.Line)
		if err != nil {
			// ssh has gone; the spawner tears the session down.
			cmd.Process.Signal(syscall.SIGTERM)
			return &silentError{fmt.Errorf("writing the credential line: %w", err)}
		}
		return nil
	case ipc.Failed:
		abandon()
		return errors.New(m.Text)
	}
	abandon()
	return fmt.Errorf("the server did not start")
}

// attachable says whether this launcher can attach a session whose
// greeting is g: the one attach protocol each speaks must be the same
// (D8 V1, bootstrap.md §9.2 step 5, server.md §2.8), and the greeting
// must have no critical field this launcher does not know, since such a
// field restricts or selects in a way it cannot judge (versioning.md §3).
func attachable(g bootstrap.SessionLine) bool {
	return g.AttachProtocol == bootstrap.AttachProtocol && g.Unknown == ""
}

// attachMismatch is the refusal of a session this launcher cannot attach:
// both numbers on the line, the session's then this launcher's, so the
// client's own message can name both even where it shows none of the
// launcher's stderr (R3's reconnect logs it), and both on stderr
// (bootstrap.md §6.4). A greeting with a critical field this launcher
// does not know is refused as unsupported, naming the field.
func attachMismatch(g bootstrap.SessionLine) *LaunchError {
	if g.AttachProtocol == bootstrap.AttachProtocol && g.Unknown != "" {
		return &LaunchError{
			Code:   bootstrap.CodeUnsupported,
			Detail: g.Unknown,
			Text:   fmt.Sprintf("session %s needs %s, which this mosey does not know", g.Name, g.Unknown),
		}
	}
	return &LaunchError{
		Code:   bootstrap.CodeAttach,
		Detail: strconv.Itoa(g.AttachProtocol) + "-" + strconv.Itoa(bootstrap.AttachProtocol),
		Text:   fmt.Sprintf("session %s speaks attach protocol %d; this mosey speaks %d", g.Name, g.AttachProtocol, bootstrap.AttachProtocol),
	}
}

// resume is the launcher's part of taking a session (bootstrap.md §9.2
// steps 2 and 5): hand the session's spawner the line (resume:SID), and
// print the credential line it answers with, marked existing when
// notRun (the client's command is not the one the session runs). The
// session may be of any mosey version that speaks this attach protocol
// (D8 V1).
func (l *Launcher) resume(ctx context.Context, f *os.File, line []byte, cl bootstrap.ClientLine, notRun bool) error {
	conn, err := ipc.NewConn(f, ipc.Launcher, ipc.Spawner)
	if err != nil {
		return err
	}
	if err := conn.Send(ipc.ClientLine{Line: line}); err != nil {
		return fmt.Errorf("the session did not answer: %w", err)
	}
	f.SetReadDeadline(time.Now().Add(T2))
	m, err := conn.Recv()
	if err != nil {
		return fmt.Errorf("the session did not answer: %w", err)
	}
	switch m := m.(type) {
	case ipc.Ready:
		l.trigger(ctx, cl)
		line := m.Line
		if notRun {
			// The command was not run, and the client says so; only a
			// client that sent one is told, so no older one sees the word
			// (bootstrap.md §6.3, §9.2.3).
			marked, err := markExisting(m.Line)
			clear(m.Line)
			if err != nil {
				return err
			}
			line = marked
		}
		_, err := l.Stdout.Write(line)
		clear(line)
		if err != nil {
			return &silentError{fmt.Errorf("writing the credential line: %w", err)}
		}
		return nil
	case ipc.Failed:
		return errors.New(m.Text)
	}
	return errors.New("the session did not answer")
}

// markExisting is the session's credential line with existing added
// (bootstrap.md §6.3). The line is parsed and written again rather than
// edited, so what goes out is a line the client will read; the copies of
// the PSK are wiped.
func markExisting(line []byte) ([]byte, error) {
	c, err := bootstrap.ParseCredentialLine(line)
	if err != nil {
		return nil, fmt.Errorf("the session's credential line: %w", err)
	}
	defer clear(c.PSK[:])
	c.Existing = true
	return bootstrap.MarshalCredentialLine(c), nil
}

// trigger makes the client's ssh send its session-bind to the client's
// capture socket, before the line goes out (bootstrap.md §8, "Server"), by
// opening the agent sshd forwarded for this login. With none (the host
// has AllowAgentForwarding no) there is nothing to do, and the client
// carries on without the agent. A failure is not the session's: the
// client then sees no bind, and says so.
func (l *Launcher) trigger(ctx context.Context, cl bootstrap.ClientLine) {
	sock := l.getenv("SSH_AUTH_SOCK")
	if !cl.Agent || sock == "" {
		return
	}
	trigger := l.Trigger
	if trigger == nil {
		trigger = agent.Trigger
	}
	// Its failure is the capture's to explain: the client says why it
	// has no bind, so nothing is printed here too.
	_ = trigger(ctx, sock)
}

// sessionsDir is where the user's sessions are (server.md §2.6).
func (l *Launcher) sessionsDir() string {
	if l.sessions != "" {
		return l.sessions
	}
	return sessionsDir(l.getenv)
}

func (l *Launcher) getenv(name string) string {
	for i := len(l.Env) - 1; i >= 0; i-- {
		if k, v, ok := strings.Cut(l.Env[i], "="); ok && k == name {
			return v
		}
	}
	return ""
}

// liveSession is a session whose spawner answered with a greeting.
type liveSession struct {
	f        *os.File
	greeting []byte
}

// liveSessions connects to every session under base that answers. A
// directory that is not a session's, or whose spawner has gone, is
// skipped.
func liveSessions(base string) []liveSession {
	if checkPrivateDir(base) != nil {
		return nil
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil
	}
	var live []liveSession
	for _, e := range entries {
		if !isSessionDirName(e.Name()) {
			continue
		}
		f, greeting, err := dialAttach(filepath.Join(base, e.Name()))
		if err != nil {
			continue
		}
		live = append(live, liveSession{f, greeting})
	}
	return live
}

// silentError is a failure there is no one left to tell.
type silentError struct{ error }

// readClientLine reads stdin to EOF within T1, at most MaxClientLine
// bytes: exactly one line, its newline last (bootstrap.md §4.4).
func readClientLine(ctx context.Context, r io.Reader) ([]byte, error) {
	type result struct {
		b   []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		b, err := io.ReadAll(io.LimitReader(r, bootstrap.MaxClientLine+1))
		done <- result{b, err}
	}()
	bad := &LaunchError{Code: bootstrap.CodeLine, Text: "the client's line is malformed"}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(T1):
		return nil, &LaunchError{Code: bootstrap.CodeLine, Text: "no line from the client"}
	case res := <-done:
		if res.err != nil {
			return nil, fmt.Errorf("reading the client's line: %w", res.err)
		}
		b := res.b
		if len(b) == 0 || len(b) > bootstrap.MaxClientLine || b[len(b)-1] != '\n' || bytes.IndexByte(b, '\n') != len(b)-1 {
			return nil, bad
		}
		return b, nil
	}
}

// parseClientLine is what the launcher checks of the client's line before
// it chooses: that it parses, which checks its line number (bootstrap.md
// §6.2, §6.4). No software version is on it (D8 V1): any release's client
// of this line number is served. A field it does not know is ignored,
// unless it is critical: then the client asked for something this server
// cannot do, and is told which field (versioning.md §3).
func parseClientLine(line []byte) (bootstrap.ClientLine, error) {
	cl, err := bootstrap.ParseClientLine(line)
	if err != nil {
		var ve *bootstrap.VersionError
		var ce *bootstrap.CriticalError
		switch {
		case errors.As(err, &ve):
			return cl, &LaunchError{Code: bootstrap.CodeVersion,
				Text: fmt.Sprintf("the client speaks protocol %d; this mosey speaks %d", ve.Got, bootstrap.Version)}
		case errors.As(err, &ce):
			return cl, &LaunchError{Code: bootstrap.CodeUnsupported, Detail: ce.Key,
				Text: fmt.Sprintf("the client asked for %s, which this mosey does not know", ce.Key)}
		}
		return cl, &LaunchError{Code: bootstrap.CodeLine, Text: "the client's line is malformed"}
	}
	return cl, nil
}

// checkClientLine is what a new session's spawner checks of the line its
// launcher sends: as the launcher did, and that it starts a session with
// a name the launcher chose (new:NAME, bootstrap.md §9.2 step 2).
func checkClientLine(line []byte) error {
	cl, err := parseClientLine(line)
	if err != nil {
		return err
	}
	if cl.Attach != bootstrap.AttachNew || cl.Name == "" {
		// A spawner started for a session never takes another, and every
		// session it starts has a name.
		return &LaunchError{Code: bootstrap.CodeLine, Text: "not a new session with a name"}
	}
	return nil
}
