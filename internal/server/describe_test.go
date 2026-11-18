package server

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/danielbodart/mosey/internal/bootstrap"
	"github.com/danielbodart/mosey/internal/pty"
)

// The directory is written as a prompt writes it, home as ~, and only a
// whole home: /home/dan2 is not ~2.
func TestTheHomeDirectoryIsWrittenAsTilde(t *testing.T) {
	for _, c := range []struct{ dir, home, want string }{
		{"/home/dan", "/home/dan", "~"},
		{"/home/dan/Projects/mosey", "/home/dan", "~/Projects/mosey"},
		{"/home/dan/x", "/home/dan/", "~/x"},
		{"/home/dan2", "/home/dan", "/home/dan2"},
		{"/srv", "/home/dan", "/srv"},
		{"/srv", "", "/srv"},
		{"/srv", "/", "/srv"},
		{"", "/home/dan", ""},
	} {
		if got := tildePath(c.dir, c.home); got != c.want {
			t.Errorf("tildePath(%q, %q) = %q, want %q", c.dir, c.home, got, c.want)
		}
	}
}

// What the greeting says of a program always fits its field: a path of
// any bytes is not a greeting the spawner cannot write, and a long one
// keeps its end, which is what tells sessions apart.
func TestADescriptionIsFittedToItsFields(t *testing.T) {
	fg, cwd := describeProgram(pty.Program{Name: "cla\x1bude", Dir: "/home/u/a\tb\xff"}, "/home/u")
	if fg != "cla?ude" || cwd != "~/a?b?" {
		t.Errorf("%q %q", fg, cwd)
	}
	long := "/home/u/" + strings.Repeat("ü", 200) + "/mosey"
	fg, cwd = describeProgram(pty.Program{Name: strings.Repeat("n", 100), Dir: long}, "/home/u")
	if !bootstrap.ValidForeground(fg) || !strings.HasSuffix(fg, "n…") || !bootstrap.ValidCwd(cwd) ||
		!strings.HasPrefix(cwd, "…") || !strings.HasSuffix(cwd, "ü/mosey") {
		t.Errorf("%q %q", fg, cwd)
	}
}

func FuzzFitText(f *testing.F) {
	f.Add("~/Projects/mosey", true)
	f.Add(strings.Repeat("é", 150)+"\x1b\xff\t", false)
	f.Fuzz(func(t *testing.T, s string, tail bool) {
		for _, max := range []int{bootstrap.MaxForeground, bootstrap.MaxCwd} {
			got := fitText(s, max, tail)
			if s == "" {
				if got != "" {
					t.Fatalf("%q fitted as %q", s, got)
				}
				continue
			}
			if !utf8.ValidString(got) || len(got) > max {
				t.Fatalf("%q fitted to %d as %q", s, max, got)
			}
			if !bootstrap.ValidCwd(got) {
				t.Fatalf("%q fitted as %q, which is not a cwdtext", s, got)
			}
			if max == bootstrap.MaxForeground && !bootstrap.ValidForeground(got) {
				t.Fatalf("%q fitted as %q, which is not an fgtext", s, got)
			}
			if bootstrap.ValidCwd(s) && len(s) <= max && got != s {
				t.Fatalf("valid %q changed to %q", s, got)
			}
		}
	})
}
