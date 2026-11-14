package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"

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
	// Version is this binary's, which the client's must equal (D7).
	Version string
	// Env is the spawner's environment: the launcher's own, unchanged.
	Env []string
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
	if err := checkClientLine(line, l.Version); err != nil {
		return err
	}

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

// checkClientLine is what both the launcher and the spawner check of the
// client's line: that it parses, then its protocol version, its software
// version, and that it asks for nothing reserved (bootstrap.md §6.2, §6.4).
func checkClientLine(line []byte, version string) error {
	cl, err := bootstrap.ParseClientLine(line)
	if err != nil {
		var ve *bootstrap.VersionError
		if errors.As(err, &ve) {
			return &LaunchError{Code: bootstrap.CodeVersion, Detail: version,
				Text: fmt.Sprintf("the client speaks bootstrap protocol %d, this server %d", ve.Got, bootstrap.Version)}
		}
		return &LaunchError{Code: bootstrap.CodeLine, Text: "the client's line is malformed"}
	}
	if cl.SoftwareVersion != version {
		return &LaunchError{Code: bootstrap.CodeVersion, Detail: version,
			Text: fmt.Sprintf("the client is version %s, this server %s", printableASCII(cl.SoftwareVersion, 64), version)}
	}
	if cl.Resume {
		return &LaunchError{Code: bootstrap.CodeUnsupported, Detail: "attach", Text: "resuming a session is not supported yet"}
	}
	if cl.Agent {
		return &LaunchError{Code: bootstrap.CodeUnsupported, Detail: "agent", Text: "agent forwarding is not supported yet"}
	}
	return nil
}
