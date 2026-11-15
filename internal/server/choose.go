package server

import (
	"strconv"

	"github.com/danielbodart/mosey/internal/bootstrap"
)

// choice is what a launcher does with a client's line once it has read the
// greetings of the user's sessions (bootstrap.md §9.2): start a session
// called name, take session take (an index into what it was given), or
// refuse with err.
type choice struct {
	start bool
	name  string
	take  int
	err   *LaunchError
}

// choose is §9.2's table, a pure function so every row is tested without
// processes: sessions are the greetings this version could read, and
// generate makes a name none of them has.
func choose(cl bootstrap.ClientLine, sessions []bootstrap.SessionLine, generate func(taken map[string]bool) string) choice {
	fresh := func() choice {
		taken := map[string]bool{}
		for _, s := range sessions {
			taken[s.Name] = true
		}
		return choice{start: true, name: generate(taken)}
	}
	switch cl.Attach {
	case bootstrap.AttachAuto:
		// R1: the most recently detached session, never an attached one,
		// so a second terminal gets a session of its own.
		if i := newest(sessions, func(s bootstrap.SessionLine) bool { return s.State == bootstrap.SessionDetached }); i >= 0 {
			return choice{take: i}
		}
		return fresh()
	case bootstrap.AttachName:
		// R2: NAME whatever its state, a takeover if attached (D26), or a
		// new session of that name.
		if i := newest(sessions, func(s bootstrap.SessionLine) bool { return s.Name == cl.Name }); i >= 0 {
			return choice{take: i}
		}
		return choice{start: true, name: cl.Name}
	case bootstrap.AttachResume:
		i := newest(sessions, func(s bootstrap.SessionLine) bool { return s.SessionID == cl.SessionID })
		if i < 0 {
			return choice{err: &LaunchError{Code: bootstrap.CodeSession, Text: "no such session"}}
		}
		if cl.HasHolder {
			return reconnect(cl.Holder, sessions[i], i)
		}
		return choice{take: i}
	}
	if cl.Name != "" {
		// new:NAME is the launcher's word to its spawner, never a client's.
		return choice{err: &LaunchError{Code: bootstrap.CodeLine, Text: "a session name the client may not choose this way"}}
	}
	return fresh()
}

// reconnect is R3's rule (bootstrap.md §9.2.2): a client reconnecting in
// the background takes its session only if it is detached or still held
// by the credential the client last had; one any other credential holds
// was taken over, and the client is told when. Taking it back instead
// (PLAN O15, open for Dan) would be `return choice{take: i}` here.
func reconnect(mine [bootstrap.CredentialIDSize]byte, s bootstrap.SessionLine, i int) choice {
	if s.State == bootstrap.SessionDetached || s.HasHolder && s.Holder == mine {
		return choice{take: i}
	}
	since := strconv.FormatInt(s.Since.Unix(), 10)
	return choice{err: &LaunchError{Code: bootstrap.CodeTaken, Detail: since, Text: "the session is held by another client since " + since}}
}

// newest is the index of the session that matches with the latest Since,
// the most recent change, or -1 if none does.
func newest(sessions []bootstrap.SessionLine, match func(bootstrap.SessionLine) bool) int {
	best := -1
	for i, s := range sessions {
		if match(s) && (best < 0 || s.Since.After(sessions[best].Since)) {
			best = i
		}
	}
	return best
}
