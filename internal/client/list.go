package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/danielbodart/mosey/internal/bootstrap"
)

// maxList bounds what -list copies from the server: far more than any
// list of sessions, so a runaway far side cannot flood the terminal.
const maxList = 256 << 10

// ListOptions is what List needs from cmd/mosey.
type ListOptions struct {
	SSH bootstrap.SSH
	// Stdout gets the server's list and Stderr ssh's own words, both
	// through the stderr filter (bootstrap.md §6.5).
	Stdout, Stderr io.Writer
	Log            *slog.Logger
}

// List is `mosey -list host` (bootstrap.md §9.4): it runs `mosey
// --serve=list` there over the user's ssh and copies what it prints. The
// text is for people and the client never parses it; like everything else
// from the far side it passes the filter, so no remote escape sequence
// reaches the terminal (D9).
func List(ctx context.Context, o ListOptions) error {
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	o.SSH.Role = bootstrap.RoleList
	if err := o.SSH.Check(); err != nil {
		return err
	}
	b := &spawn{ssh: o.SSH, stderr: o.Stderr, log: o.Log}
	cfg, err := o.SSH.Resolve(ctx)
	if err != nil {
		var re *bootstrap.ResolveError
		if errors.As(err, &re) {
			b.show(re.Stderr)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fail(err, "ssh -G %s failed", o.SSH.Destination)
	}
	cmd := o.SSH.Command(ctx, cfg)
	var out bytes.Buffer
	cmd.Stdout = &limitWriter{w: &out, n: maxList}
	errs := bootstrap.Sanitize(o.Stderr)
	cmd.Stderr = errs
	err = cmd.Run()
	errs.Close()
	listed := bootstrap.Sanitize(o.Stdout)
	listed.Write(out.Bytes())
	listed.Close()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	switch status := bootstrap.ExitStatus(err); {
	case status == 0:
	case status == 255:
		return fail(err, "ssh to %s failed", o.SSH.Destination)
	case status == 126 || status == 127:
		return fail(fmt.Errorf("%w: %w", bootstrap.ErrNoServer, err),
			"no mosey at %s on %s: install it there or pass -remote", o.SSH.Server, o.SSH.Destination)
	default:
		return fail(err, "the remote mosey exited with status %d", status)
	}
	if out.Len() > 0 && !bytes.Equal(out.Bytes(), []byte("no sessions\n")) {
		fmt.Fprintf(o.Stderr, "resume one with: mosey -r=SESSION %s\n", o.SSH.Destination)
	}
	return nil
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
