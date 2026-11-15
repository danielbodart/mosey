package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/danielbodart/mosey/internal/agent"
	"github.com/danielbodart/mosey/internal/bootstrap"
	"github.com/danielbodart/mosey/internal/ipc"
	"github.com/danielbodart/mosey/internal/nocore"
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
	// Self is this binary, started as `Self --serve=spawner`.
	Self string
	// Version is this binary's, which an error line names. The client's
	// is never compared with it (D8 V1).
	Version string
	// Env is the spawner's environment: the launcher's own, unchanged.
	Env []string
	// Trigger opens sshd's forwarded agent to make the client's ssh send
	// its bind (bootstrap.md §8): agent.Trigger, unless a test sets it.
	Trigger func(ctx context.Context, sock string) error
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
	// Before the credential line passes through, as in the spawner
	// (threat-model.md §4.10). The server runs on Linux only for now.
	if err := nocore.NotDumpable(); errors.Is(err, errors.ErrUnsupported) {
		return &LaunchError{Code: bootstrap.CodeUnsupported, Text: "the server runs on Linux only for now"}
	} else if err != nil {
		return err
	}
	line, err := readClientLine(ctx, l.Stdin)
	if err != nil {
		return err
	}
	cl, err := parseClientLine(line, l.Version)
	if err != nil {
		return err
	}

	// Choosing and starting are one step (bootstrap.md §9.2 "The lock"):
	// the lock is held until the spawner has answered.
	base := sessionsDir(l.getenv)
	lock, err := lockSessions(base, T2)
	if err != nil {
		return err
	}
	defer lock.Close()
	var sessions []bootstrap.SessionLine
	var conns []liveSession
	for _, s := range liveSessions(base) {
		g, ok := attachable(s.greeting)
		if !ok {
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
		cl.Attach, cl.Name, cl.HasHolder = bootstrap.AttachNew, c.name, false
		return l.start(ctx, bootstrap.MarshalClientLine(cl), cl)
	}
	taken := conns[c.take]
	defer taken.f.Close()
	// A reconnect keeps its holder (resume:SID:CREDID): the spawner holds
	// the session for that client while the new credential is out, so the
	// same client's next try still finds it its own (bootstrap.md §9.2.2).
	to := cl
	to.Attach, to.SessionID, to.Name = bootstrap.AttachResume, sessions[c.take].SessionID, ""
	return l.resume(ctx, taken.f, taken.greeting, bootstrap.MarshalClientLine(to), cl)
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
	cmd := &exec.Cmd{
		Path: l.Self,
		Args: []string{l.Self, "--serve=spawner"},
		Env:  l.Env,
		// No copy of ssh's pipes, or ssh would wait for the spawner: stdio
		// is /dev/null, and the spawner opens its own log.
		ExtraFiles:  []*os.File{theirs},
		SysProcAttr: &syscall.SysProcAttr{Setsid: true},
	}
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
	conn.File().SetReadDeadline(time.Now().Add(T2))
	m, err := conn.Recv()
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

// attachable is a session's greeting if this launcher can attach it: one
// that parses (bootstrap.md §9.2.1) and whose attach protocol range meets
// this build's (§9.2 step 5).
func attachable(greeting []byte) (bootstrap.SessionLine, bool) {
	g, err := bootstrap.ParseSessionLine(greeting)
	if err != nil {
		return g, false
	}
	_, ok := bootstrap.AttachVersion(g)
	return g, ok
}

// resume is the launcher's part of taking a session (bootstrap.md §9.2
// steps 2 and 5): hand the session's spawner the line (resume:SID), and
// print the credential line it answers with. The session may be of any
// version (D8 V1).
func (l *Launcher) resume(ctx context.Context, f *os.File, greeting, line []byte, cl bootstrap.ClientLine) error {
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
		_, err := l.Stdout.Write(m.Line)
		clear(m.Line)
		if err != nil {
			return &silentError{fmt.Errorf("writing the credential line: %w", err)}
		}
		return nil
	case ipc.Failed:
		return errors.New(m.Text)
	}
	return errors.New("the session did not answer")
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
// it chooses: that it parses, which checks its line version (bootstrap.md
// §6.2, §6.4). Its software version is never compared with this one's
// (D8 V1): any release's client is served. version, this launcher's, is
// only what a refusal says the server is.
func parseClientLine(line []byte, version string) (bootstrap.ClientLine, error) {
	cl, err := bootstrap.ParseClientLine(line)
	if err != nil {
		var ve *bootstrap.VersionError
		if errors.As(err, &ve) {
			return cl, &LaunchError{Code: bootstrap.CodeVersion, Detail: version,
				Text: fmt.Sprintf("the client speaks bootstrap protocol %d, this server %d", ve.Got, bootstrap.Version)}
		}
		return cl, &LaunchError{Code: bootstrap.CodeLine, Text: "the client's line is malformed"}
	}
	return cl, nil
}

// checkClientLine is what a new session's spawner checks of the line its
// launcher sends: as the launcher did, and that it starts a session with
// a name the launcher chose (new:NAME, bootstrap.md §9.2 step 2).
func checkClientLine(line []byte, version string) error {
	cl, err := parseClientLine(line, version)
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
