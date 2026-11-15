package server

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"time"

	"github.com/danielbodart/mosey/internal/bootstrap"
	"github.com/danielbodart/mosey/internal/ipc"
)

// List is `mosey --serve=list` (bootstrap.md §9.4): it reads the greeting
// of every session of this user that answers and prints one MOSEY-LIST
// line each, oldest first. The client parses the lines and lays out the
// table itself, so nothing printed here reaches a terminal unchecked.
// getenv is the environment sshd gave, which says where the sessions are.
func List(w io.Writer, getenv func(string) string) error {
	type row struct {
		started time.Time
		line    bootstrap.ListLine
	}
	var rows []row
	for _, s := range liveSessions(sessionsDir(getenv)) {
		// The lister only reads: closing after the greeting is a lister's
		// whole exchange, and the spawner does nothing about it.
		s.f.Close()
		g, err := bootstrap.ParseSessionLine(s.greeting)
		if err != nil {
			continue
		}
		rows = append(rows, row{started: g.Started, line: bootstrap.ListLine{
			Name: g.Name, State: g.State, Since: g.Since,
		}})
	}
	slices.SortStableFunc(rows, func(a, b row) int { return a.started.Compare(b.started) })
	for _, r := range rows {
		if _, err := w.Write(bootstrap.MarshalListLine(r.line)); err != nil {
			return err
		}
	}
	return nil
}

// ErrNoSuchSession is Kill finding no session of the name.
var ErrNoSuchSession = errors.New("no session of that name")

// Kill is `mosey --serve=kill NAME` (bootstrap.md §9.5): it finds the
// session called name among those that answer and asks its spawner to
// hang the shell up. With none, it prints `MOSEY-ERROR 1 session -` on w
// for the client and returns ErrNoSuchSession.
func Kill(w io.Writer, getenv func(string) string, name string) error {
	if !bootstrap.ValidSessionName(name) {
		return fmt.Errorf("%q is not a session name", printableASCII(name, 64))
	}
	var found *liveSession
	var other *bootstrap.SessionLine
	for _, s := range liveSessions(sessionsDir(getenv)) {
		g, err := bootstrap.ParseSessionLine(s.greeting)
		if err != nil || g.Name != name || found != nil {
			s.f.Close()
			continue
		}
		if !attachable(g) {
			// Hangup is an attach protocol message: one of another
			// protocol cannot be sent it (bootstrap.md §9.2 step 5).
			s.f.Close()
			other = &g
			continue
		}
		found = &s
	}
	if found == nil && other != nil {
		le := attachMismatch(*other)
		w.Write(bootstrap.MarshalErrorLine(bootstrap.ErrorLine{Proto: bootstrap.Version, Code: le.Code, Detail: le.Detail}))
		return le
	}
	if found == nil {
		w.Write(bootstrap.MarshalErrorLine(bootstrap.ErrorLine{Proto: bootstrap.Version, Code: bootstrap.CodeSession}))
		return ErrNoSuchSession
	}
	defer found.f.Close()
	return hangUp(found.f)
}

// hangUp sends a session's spawner Hangup and waits, at most T2, for it to
// close the connection, which it does once it has passed the request on.
func hangUp(f *os.File) error {
	conn, err := ipc.NewConn(f, ipc.Launcher, ipc.Spawner)
	if err != nil {
		return err
	}
	if err := conn.Send(ipc.Hangup{}); err != nil {
		return fmt.Errorf("asking the session to end: %w", err)
	}
	f.SetReadDeadline(time.Now().Add(T2))
	if _, err := conn.Recv(); !ipc.IsEOF(err) {
		return fmt.Errorf("the session did not answer: %v", err)
	}
	return nil
}
