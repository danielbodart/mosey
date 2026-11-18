package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"slices"
	"strings"
	"text/tabwriter"
	"unicode"
	"unicode/utf8"

	"github.com/danielbodart/mosey/internal/bootstrap"
)

// maxList bounds what -list and -kill read from the server: MaxListed
// lines of MaxListLine bytes each (bootstrap.md §9.4), far more than any
// real list of sessions, so a runaway far side cannot fill memory.
const maxList = bootstrap.MaxListed * bootstrap.MaxListLine

// maxShownCommand is how many runes of a session's command -list shows
// (bootstrap.md §9.4) [choice: one terminal line beside the other
// columns].
const maxShownCommand = 60

// shownCommand is a session's command as -list shows it: every rune that
// is not printable (a tab, a format character such as a bidi override, a
// non-ASCII space) as ?, and cut to maxShownCommand runes with … after.
// The parser has already held it to cmdtext, with no control character
// but tab, but it is a far side's words, so the table is only ever given
// what is safe to print and cannot reorder the line it is on (D9).
func shownCommand(s string) string { return shown(s, maxShownCommand, false) }

// maxShownForeground and maxShownCwd are how many runes of a session's
// foreground program and directory -list shows (bootstrap.md §9.4)
// [choice: a program's name whole, and enough of a path's end to tell
// sessions apart, so a row stays one line].
const (
	maxShownForeground = 16
	maxShownCwd        = 32
)

// shown is s as -list shows any far-side text: every rune that is not
// printable as ?, and cut to max runes with … where it was cut, at the
// start when tail (a path's last parts tell it apart), else at the end.
func shown(s string, max int, tail bool) string {
	rs := []rune(s)
	for i, r := range rs {
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			rs[i] = '?'
		}
	}
	switch {
	case len(rs) <= max:
		return string(rs)
	case tail:
		return "…" + string(rs[len(rs)-max:])
	}
	return string(rs[:max]) + "…"
}

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

// List is `mosey -list [host]` (bootstrap.md §9.4): it runs `mosey
// --serve=list` there over the user's ssh (or here, with none, §2.2), parses the MOSEY-LIST lines it
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
		fmt.Fprintf(o.Stderr, "mosey: %s sent %d list lines this mosey could not read\n", where(o.SSH), dropped)
	}
	if len(rows) == 0 {
		fmt.Fprintf(o.Stdout, "no sessions on %s\n", where(o.SSH))
		return nil
	}
	// RUNNING, DIR and COMMAND are each there only when some session has
	// one, so an older server's list, which has none of the first two,
	// lays out as it did; COMMAND is last.
	has := func(f func(bootstrap.ListLine) string) bool {
		return slices.ContainsFunc(rows, func(r bootstrap.ListLine) bool { return f(r) != "" })
	}
	type column struct {
		head string
		show func(bootstrap.ListLine) string
	}
	columns := []column{
		{"NAME", func(r bootstrap.ListLine) string { return r.Name }},
		{"STATE", func(r bootstrap.ListLine) string { return r.State.String() }},
		{"SINCE", func(r bootstrap.ListLine) string { return r.Since.Local().Format(takenOverTime) }},
	}
	if has(func(r bootstrap.ListLine) string { return r.Foreground }) {
		columns = append(columns, column{"RUNNING", func(r bootstrap.ListLine) string { return shown(r.Foreground, maxShownForeground, false) }})
	}
	if has(func(r bootstrap.ListLine) string { return r.Cwd }) {
		columns = append(columns, column{"DIR", func(r bootstrap.ListLine) string { return shown(r.Cwd, maxShownCwd, true) }})
	}
	if has(func(r bootstrap.ListLine) string { return r.Command }) {
		columns = append(columns, column{"COMMAND", func(r bootstrap.ListLine) string { return shownCommand(r.Command) }})
	}
	var table bytes.Buffer
	tw := tabwriter.NewWriter(&table, 0, 0, 2, ' ', 0)
	cells := make([]string, len(columns))
	for i, c := range columns {
		cells[i] = c.head
	}
	fmt.Fprintln(tw, strings.Join(cells, "\t"))
	for _, r := range rows {
		for i, c := range columns {
			cells[i] = c.show(r)
		}
		fmt.Fprintln(tw, strings.Join(cells, "\t"))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	// A shell's row has an empty last cell, padded by tabwriter: no
	// trailing spaces on any line.
	for line := range strings.Lines(table.String()) {
		if _, err := fmt.Fprintln(o.Stdout, strings.TrimRight(line, " \n")); err != nil {
			return err
		}
	}
	fmt.Fprintf(o.Stderr, "attach to one with: mosey -s NAME%s\n", again(o.SSH))
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
		return fail(err, "no session called %s on %s", o.Name, where(o.SSH))
	}
	if err != nil && errors.As(err, &remote) && remote.Code == bootstrap.CodeAttach {
		// Its spawner speaks another attach protocol, so this host's mosey
		// cannot ask it to end (bootstrap.md §9.2 step 5).
		return attachRefused(remote, "session "+o.Name, where(o.SSH))
	}
	if err != nil {
		return err
	}
	o.Log.Info("killed", "name", o.Name, "said", len(out))
	fmt.Fprintf(o.Stdout, "mosey: ended session %s on %s\n", o.Name, where(o.SSH))
	return nil
}

// runRole runs a server role over the user's ssh, or on this machine with
// no ssh (bootstrap.md §2.2), with stdin closed and returns what it
// printed (§9.4, §9.5): ssh -G first, its stderr through the filter, the
// probe answered as §4.7.1 says, and a remote ErrorLine as a
// *bootstrap.RemoteError.
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
	var exited *exec.ExitError
	switch status := bootstrap.ExitStatus(err); {
	case status == 0:
	case !errors.As(err, &exited):
		// It never ran, or did not exit of itself.
		return nil, fail(err, "running %s: %v", cmd.Path, err)
	case ssh.Local():
		// No ssh and no probe: only the server's own words (§2.2).
		if e, perr := bootstrap.ParseErrorLine(last); perr == nil {
			return nil, &bootstrap.RemoteError{ErrorLine: e}
		}
		return nil, fail(err, "%s exited with status %d", localServer(ssh), status)
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
