package server

import (
	"fmt"
	"io"
	"slices"
	"text/tabwriter"
	"time"

	"github.com/danielbodart/mosey/internal/bootstrap"
)

// List is `mosey --serve=list` (bootstrap.md §9.4): it reads the greeting
// of every session of this user that answers and prints one line each,
// oldest first, for a person to read. The client copies it through its
// stderr filter and never parses it, so this text is free to change.
// getenv is the environment sshd gave, which says where the sessions are.
func List(w io.Writer, getenv func(string) string) error {
	type row struct {
		started time.Time
		cells   []string
	}
	var rows []row
	for _, s := range liveSessions(sessionsDir(getenv)) {
		// The lister only reads: closing after the greeting is a lister's
		// whole exchange, and the spawner does nothing about it.
		s.f.Close()
		g, err := bootstrap.ParseSessionLine(s.greeting)
		if err != nil {
			// Another version's session: its version is all that can be
			// read of it, and it can only be resumed by that version.
			v, verr := bootstrap.SessionLineVersion(s.greeting)
			if verr != nil {
				continue
			}
			rows = append(rows, row{cells: []string{"?", "?", "?", "?", v}})
			continue
		}
		peer := "-"
		if g.Peer.IsValid() {
			peer = g.Peer.String()
		}
		rows = append(rows, row{started: g.Started, cells: []string{
			fmt.Sprintf("%x", g.SessionID), g.State.String(),
			g.Since.UTC().Format(time.RFC3339), peer, g.SoftwareVersion,
		}})
	}
	if len(rows) == 0 {
		_, err := fmt.Fprintln(w, "no sessions")
		return err
	}
	slices.SortStableFunc(rows, func(a, b row) int { return a.started.Compare(b.started) })
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SESSION\tSTATE\tSINCE\tPEER\tVERSION")
	for _, r := range rows {
		for i, c := range r.cells {
			if i > 0 {
				fmt.Fprint(tw, "\t")
			}
			fmt.Fprint(tw, c)
		}
		fmt.Fprintln(tw)
	}
	return tw.Flush()
}
