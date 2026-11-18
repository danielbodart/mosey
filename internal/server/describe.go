package server

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/danielbodart/mosey/internal/bootstrap"
	"github.com/danielbodart/mosey/internal/pty"
)

// describeProgram is what the greeting says of the program at a session's
// keyboard (bootstrap.md §9.2.1): its name, and its directory with home as
// ~, each made to fit its field's grammar. A name or directory is the
// user's own, but may be any bytes, so it is fitted here rather than
// leaving the greeting unmarshallable; the client filters it again (D9).
func describeProgram(p pty.Program, home string) (fg, cwd string) {
	return fitText(p.Name, bootstrap.MaxForeground, false),
		fitText(tildePath(p.Dir, home), bootstrap.MaxCwd, true)
}

// tildePath is dir with a leading home written ~, as a shell's prompt
// shows it.
func tildePath(dir, home string) string {
	home = strings.TrimSuffix(home, "/")
	switch {
	case home == "" || dir == "":
		return dir
	case dir == home:
		return "~"
	case strings.HasPrefix(dir, home+"/"):
		return "~" + dir[len(home):]
	}
	return dir
}

// fitText is s with every byte that is not valid UTF-8 and every control
// character as ?, cut to at most max bytes on a rune boundary with … where
// it was cut: at the start when tail, since a path's last parts are what
// tell sessions apart, else at the end.
func fitText(s string, max int, tail bool) string {
	var b strings.Builder
	for len(s) > 0 {
		r, n := utf8.DecodeRuneInString(s)
		if r == utf8.RuneError && n <= 1 || unicode.IsControl(r) {
			r = '?'
		}
		b.WriteRune(r)
		s = s[n:]
	}
	s = b.String()
	if len(s) <= max {
		return s
	}
	const ellipsis = "…"
	keep := max - len(ellipsis)
	if tail {
		i := len(s) - keep
		for !utf8.RuneStart(s[i]) {
			i++
		}
		return ellipsis + s[i:]
	}
	i := keep
	for !utf8.RuneStart(s[i]) {
		i--
	}
	return s[:i] + ellipsis
}
