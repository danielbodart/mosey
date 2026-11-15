package server

import (
	"strings"
	"testing"
	"time"

	"github.com/danielbodart/mosey/internal/bootstrap"
)

// The launcher's choice (bootstrap.md §9.2), row by row, on greetings
// alone: no processes, no clock.

func session(name string, id byte, st bootstrap.SessionState, since int64) bootstrap.SessionLine {
	return bootstrap.SessionLine{AttachProtocol: bootstrap.AttachProtocol, SessionID: [16]byte{id}, Name: name, State: st, Since: time.Unix(since, 0)}
}

func held(s bootstrap.SessionLine, cred byte) bootstrap.SessionLine {
	s.Holder, s.HasHolder = [8]byte{cred}, true
	return s
}

func fixedName(map[string]bool) string { return "made-up" }

func line(a bootstrap.Attach, name string) bootstrap.ClientLine {
	return bootstrap.ClientLine{Attach: a, Name: name}
}

// speaking is s as a spawner of attach protocol aproto would greet.
func speaking(aproto int, s bootstrap.SessionLine) bootstrap.SessionLine {
	s.AttachProtocol = aproto
	return s
}

// A plain mosey DEST takes the most recently detached session and never
// an attached or new one, so a second terminal gets its own (D8 R1).
func TestAPlainClientTakesTheNewestDetachedSessionAndNeverAnAttachedOne(t *testing.T) {
	sessions := []bootstrap.SessionLine{
		session("old", 1, bootstrap.SessionDetached, 100),
		held(session("busy", 2, bootstrap.SessionAttached, 900), 7),
		session("recent", 3, bootstrap.SessionDetached, 500),
		session("starting", 4, bootstrap.SessionNew, 950),
	}
	if c := choose(line(bootstrap.AttachAuto, ""), sessions, fixedName); c.start || c.err != nil || c.take != 2 {
		t.Errorf("took %+v, not the most recently detached", c)
	}
	attachedOnly := sessions[1:2]
	if c := choose(line(bootstrap.AttachAuto, ""), attachedOnly, fixedName); !c.start || c.name != "made-up" {
		t.Errorf("with only an attached session: %+v, not a new session", c)
	}
	if c := choose(line(bootstrap.AttachAuto, ""), nil, fixedName); !c.start || c.name != "made-up" {
		t.Errorf("with no session: %+v", c)
	}
}

// A session whose spawner speaks another attach protocol (D8 V1,
// bootstrap.md §9.2 step 5) is never taken by a plain mosey HOST, which
// takes an attachable one or starts its own; -s NAME and R3's resume
// naming it are refused with its number; and its name is never given to
// a new session.
func TestASessionOfAnotherAttachProtocolIsPassedOverOrRefused(t *testing.T) {
	elder := speaking(2, session("work", 1, bootstrap.SessionDetached, 900))
	ours := session("play", 2, bootstrap.SessionDetached, 100)
	if c := choose(line(bootstrap.AttachAuto, ""), []bootstrap.SessionLine{elder, ours}, fixedName); c.start || c.err != nil || c.take != 1 {
		t.Errorf("a plain client: %+v, not the attachable detached session", c)
	}
	var taken map[string]bool
	c := choose(line(bootstrap.AttachAuto, ""), []bootstrap.SessionLine{elder}, func(t map[string]bool) string { taken = t; return "fresh" })
	if !c.start || c.name != "fresh" || !taken["work"] {
		t.Errorf("a plain client with only an attach-2 session: %+v, avoiding %v; want a new session, not called work", c, taken)
	}
	byName := choose(line(bootstrap.AttachName, "work"), []bootstrap.SessionLine{elder}, fixedName)
	byID := choose(bootstrap.ClientLine{Attach: bootstrap.AttachResume, SessionID: [16]byte{1}, Holder: [8]byte{7}, HasHolder: true},
		[]bootstrap.SessionLine{elder}, fixedName)
	for name, c := range map[string]choice{"-s work": byName, "R3's resume": byID} {
		if c.err == nil || c.err.Code != bootstrap.CodeAttach || c.err.Detail != "2-1" ||
			!strings.Contains(c.err.Text, "speaks attach protocol 2; this mosey speaks 1") {
			t.Errorf("%s of an attach-2 session: %+v", name, c)
		}
	}
}

// -s NAME takes NAME whatever its state (a takeover, D26), and starts it
// when there is none; -new always starts, with a generated name that no
// session has (D8 R2).
func TestNamedAndNewSessionsAreChosenAsTheSpecSays(t *testing.T) {
	sessions := []bootstrap.SessionLine{
		held(session("work", 1, bootstrap.SessionAttached, 100), 7),
		session("play", 2, bootstrap.SessionDetached, 200),
	}
	if c := choose(line(bootstrap.AttachName, "work"), sessions, fixedName); c.start || c.err != nil || c.take != 0 {
		t.Errorf("-s work: %+v, not a takeover of the attached work", c)
	}
	if c := choose(line(bootstrap.AttachName, "home"), sessions, fixedName); !c.start || c.name != "home" {
		t.Errorf("-s home: %+v, not a new session called home", c)
	}
	var taken map[string]bool
	c := choose(line(bootstrap.AttachNew, ""), sessions, func(t map[string]bool) string { taken = t; return "fresh" })
	if !c.start || c.name != "fresh" || !taken["work"] || !taken["play"] {
		t.Errorf("-new: %+v, avoiding %v", c, taken)
	}
	// new:NAME is the launcher's word to its spawner, never a client's.
	if c := choose(line(bootstrap.AttachNew, "sneaky"), sessions, fixedName); c.err == nil || c.err.Code != bootstrap.CodeLine {
		t.Errorf("new:NAME from a client: %+v", c)
	}
}

// R3's reconnect takes its session only when it is detached or still held
// by the reconnecting client's own credential; one another credential
// holds is `taken`, with when; one that has gone is `session`
// (bootstrap.md §9.2.2; PLAN O15's placeholder, reconnectTakesBack).
func TestReconnectTakesItsOwnSessionAndNeverAnothers(t *testing.T) {
	mine := [8]byte{7}
	reconnecting := bootstrap.ClientLine{Attach: bootstrap.AttachResume, SessionID: [16]byte{1}, Holder: mine, HasHolder: true}
	for name, c := range map[string]struct {
		s    bootstrap.SessionLine
		want string
	}{
		"still mine":         {held(session("work", 1, bootstrap.SessionAttached, 100), 7), "take"},
		"detached":           {session("work", 1, bootstrap.SessionDetached, 100), "take"},
		"another's":          {held(session("work", 1, bootstrap.SessionAttached, 1794650000), 8), "taken 1794650000"},
		"a pending resume's": {held(session("work", 1, bootstrap.SessionAttached, 100), 9), "taken 100"},
		"never attached":     {session("work", 1, bootstrap.SessionNew, 100), "taken 100"},
	} {
		got := choose(reconnecting, []bootstrap.SessionLine{c.s}, fixedName)
		var says string
		switch {
		case got.err != nil:
			says = got.err.Code + " " + got.err.Detail
		case got.start:
			says = "start"
		default:
			says = "take"
		}
		if says != c.want {
			t.Errorf("%s: %s, want %s", name, says, c.want)
		}
	}
	// PLAN O15's other answer, which is Dan's to choose, is the one
	// switch: a try then takes back what another client holds.
	if c := reconnect(true, mine, held(session("work", 1, bootstrap.SessionAttached, 1), 8), 0); c.err != nil || c.start || c.take != 0 {
		t.Errorf("with reconnectTakesBack: %+v, not a takeover", c)
	}
	gone := choose(reconnecting, []bootstrap.SessionLine{session("other", 2, bootstrap.SessionDetached, 1)}, fixedName)
	if gone.err == nil || gone.err.Code != bootstrap.CodeSession {
		t.Errorf("a reconnect of a session that has gone: %+v", gone)
	}
	// Without a holder, resume:SID is the launcher's own word: a takeover.
	plain := choose(bootstrap.ClientLine{Attach: bootstrap.AttachResume, SessionID: [16]byte{1}},
		[]bootstrap.SessionLine{held(session("work", 1, bootstrap.SessionAttached, 1), 8)}, fixedName)
	if plain.err != nil || plain.start || plain.take != 0 {
		t.Errorf("resume:SID: %+v", plain)
	}
}

// Generated names are sname, ADJECTIVE-NOUN, and never one in use, even
// when every plain one is (bootstrap.md §9.2).
func TestGeneratedNamesAreValidAndNeverClash(t *testing.T) {
	for _, w := range append(adjectives[:], nouns[:]...) {
		if !bootstrap.ValidSessionName(w) || strings.ContainsAny(w, "-_.") {
			t.Errorf("word %q", w)
		}
	}
	seen := map[string]bool{}
	for _, w := range adjectives {
		if seen[w] {
			t.Errorf("adjective %q twice", w)
		}
		seen[w] = true
	}
	for _, w := range nouns {
		if seen["n:"+w] {
			t.Errorf("noun %q twice", w)
		}
		seen["n:"+w] = true
	}
	n := GenerateName(nil)
	if a, b, ok := strings.Cut(n, "-"); !ok || !bootstrap.ValidSessionName(n) || !seen[a] || !seen["n:"+b] {
		t.Errorf("generated %q", n)
	}
	all := map[string]bool{}
	for _, a := range adjectives {
		for _, b := range nouns {
			all[a+"-"+b] = true
		}
	}
	for range 20 {
		n := GenerateName(all)
		if all[n] || !bootstrap.ValidSessionName(n) {
			t.Fatalf("generated %q with every plain name taken", n)
		}
	}
}
