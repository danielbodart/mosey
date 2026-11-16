package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"text/tabwriter"

	"github.com/danielbodart/mosey/internal/bootstrap"
)

// maxList bounds what -list and -kill read from the server: far more than
// any list of sessions, so a runaway far side cannot fill memory.
const maxList = 256 << 10

// ListOptions is what List needs from cmd/mosey.
type ListOptions struct {
	// SSH is how to reach the host: with no -remote, the probe runs the
	// host's mosey, PATH's or ~/.local/bin/mosey (bootstrap.md §4.7.2), so
	// -list finds the copy D7 put there.
	SSH bootstrap.SSH
	// Stdout gets the table; Stderr ssh's own words, through the stderr
	// filter (bootstrap.md §6.5), and the hints.
	Stdout, Stderr io.Writer
	Log            *slog.Logger
}

// List is `mosey -list host` (bootstrap.md §9.4): it runs `mosey
// --serve=list` there over the user's ssh, parses the MOSEY-LIST lines it
// prints, and lays out the table itself: name, state, since when.
// Every field is from a grammar of printable ASCII, so no remote escape
// sequence reaches the terminal (D9). A host with no mosey is told so,
// and nothing is copied there: listing is not a reason to install
// anything.
func List(ctx context.Context, o ListOptions) error {
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	o.SSH.Role, o.SSH.RoleArg = bootstrap.RoleList, ""
	out, err := runRole(ctx, o.SSH, o.Stderr, o.Log)
	if err != nil {
		return err
	}
	rows, dropped := bootstrap.ReadList(out)
	if dropped > 0 {
		o.Log.Warn("list lines that did not parse", "count", dropped)
		fmt.Fprintf(o.Stderr, "mosey: %s sent %d list lines this mosey could not read\n", o.SSH.Destination, dropped)
	}
	if len(rows) == 0 {
		fmt.Fprintf(o.Stdout, "no sessions on %s\n", o.SSH.Destination)
		return nil
	}
	tw := tabwriter.NewWriter(o.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tSTATE\tSINCE")
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", r.Name, r.State, r.Since.Local().Format(takenOverTime))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(o.Stderr, "attach to one with: mosey -s NAME %s\n", o.SSH.Destination)
	return nil
}

// KillOptions is what Kill needs from cmd/mosey.
type KillOptions struct {
	SSH bootstrap.SSH
	// Name is the session to end.
	Name           string
	Stdout, Stderr io.Writer
	Log            *slog.Logger
}

// Kill is `mosey -kill NAME host` (bootstrap.md §9.5): it runs `mosey
// --serve=kill NAME` there, which hangs the session's shell up.
func Kill(ctx context.Context, o KillOptions) error {
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	o.SSH.Role, o.SSH.RoleArg = bootstrap.RoleKill, o.Name
	out, err := runRole(ctx, o.SSH, o.Stderr, o.Log)
	var remote *bootstrap.RemoteError
	if err != nil && errors.As(err, &remote) && remote.Code == bootstrap.CodeSession {
		return fail(err, "no session called %s on %s", o.Name, o.SSH.Destination)
	}
	if err != nil && errors.As(err, &remote) && remote.Code == bootstrap.CodeAttach {
		// Its spawner speaks another attach protocol, so this host's mosey
		// cannot ask it to end (bootstrap.md §9.2 step 5).
		return attachRefused(remote, "session "+o.Name, o.SSH.Destination)
	}
	if err != nil {
		return err
	}
	o.Log.Info("killed", "name", o.Name, "said", len(out))
	fmt.Fprintf(o.Stdout, "mosey: ended session %s on %s\n", o.Name, o.SSH.Destination)
	return nil
}

// runRole runs a server role over the user's ssh with stdin closed and
// returns what it printed (bootstrap.md §9.4, §9.5): ssh -G first, its
// stderr through the filter, the probe answered as §4.7.1 says, and a
// remote ErrorLine as a *bootstrap.RemoteError.
func runRole(ctx context.Context, ssh bootstrap.SSH, stderr io.Writer, log *slog.Logger) ([]byte, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	ssh.Protocol = probeProtocol
	if err := ssh.Check(); err != nil {
		return nil, err
	}
	b := &spawn{ssh: ssh, stderr: stderr, log: log}
	cfg, err := ssh.Resolve(ctx)
	if err != nil {
		var re *bootstrap.ResolveError
		if errors.As(err, &re) {
			b.show(re.Stderr)
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fail(err, "ssh -G %s failed", ssh.Destination)
	}
	cmd := ssh.Command(ctx, cfg)
	var out bytes.Buffer
	cmd.Stdout = &limitWriter{w: &out, n: maxList}
	errs := bootstrap.Sanitize(stderr)
	cmd.Stderr = errs
	err = cmd.Run()
	errs.Close()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	last := lastLine(out.Bytes())
	if ssh.Probes() && bootstrap.ExitStatus(err) == 0 {
		// The probe's answer is its last line, after anything a login
		// shell's rc file said.
		if p, perr := bootstrap.ParseProbeLine(last); perr == nil {
			ns := &bootstrap.NoServerError{Probe: p}
			return nil, fail(ns, "no mosey on %s, so no sessions: mosey %s starts one, copying mosey there", ssh.Destination, ssh.Destination)
		}
	}
	switch status := bootstrap.ExitStatus(err); {
	case status == 0:
	case status == 255:
		return nil, fail(err, "ssh to %s failed", ssh.Destination)
	case status == 126 || status == 127:
		server := ssh.Server
		if server == "" {
			server = "mosey"
		}
		return nil, fail(fmt.Errorf("%w: %w", bootstrap.ErrNoServer, err),
			"no mosey at %s on %s: install it there or pass -remote", server, ssh.Destination)
	default:
		if e, perr := bootstrap.ParseErrorLine(last); perr == nil {
			return nil, &bootstrap.RemoteError{ErrorLine: e}
		}
		return nil, fail(err, "the remote mosey exited with status %d", status)
	}
	return out.Bytes(), nil
}

// lastLine is b's last line, LF included, or all of b if it has one line.
func lastLine(b []byte) []byte {
	if i := bytes.LastIndexByte(bytes.TrimSuffix(b, []byte("\n")), '\n'); i >= 0 {
		return b[i+1:]
	}
	return b
}

// limitWriter keeps the first n bytes written to it and drops the rest,
// while telling the writer it took everything, so ssh is never blocked.
type limitWriter struct {
	w io.Writer
	n int
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if l.n > 0 {
		k := min(len(p), l.n)
		l.w.Write(p[:k])
		l.n -= k
	}
	return len(p), nil
}
