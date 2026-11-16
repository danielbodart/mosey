package main

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/danielbodart/mosey/internal/bootstrap"
	"github.com/danielbodart/mosey/internal/client"
	"github.com/danielbodart/mosey/internal/predict"
)

func TestTheClientCommandLine(t *testing.T) {
	for _, c := range []struct {
		args   []string
		dest   string
		server string
		ssh    []string
		agent  byte
	}{
		{[]string{"far"}, "far", "", nil, 0},
		{[]string{"server"}, "server", "", nil, 0}, // a host called server is a host
		{[]string{"-remote", "~/bin/mosey", "me@far"}, "me@far", "~/bin/mosey", nil, 0},
		{[]string{"-A", "--", "-p2222", "-v", "far"}, "far", "", []string{"-p", "2222", "-v"}, 'A'},
		{[]string{"-A", "-a", "far"}, "far", "", nil, 'a'},
		{[]string{"-a", "-A", "far"}, "far", "", nil, 'A'},
		{[]string{"-A", "--", "-a", "far"}, "far", "", nil, 'a'}, // ssh's options come last, so win
	} {
		got, err := parseArgs(c.args)
		if err != nil {
			t.Errorf("%q: %v", c.args, err)
			continue
		}
		s := got.ssh
		if s.Destination != c.dest || s.Server != c.server || !slices.Equal(s.Options.Args, c.ssh) || s.Options.Agent != c.agent {
			t.Errorf("%q: %+v", c.args, s)
		}
	}
}

func TestABadCommandLineIsAUsageError(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"-bogus", "far"},
		{"--", "-t", "far"},
		{"--", "far", "ls"},
		{"-remote", "mo sey", "far"},
		{"-remote", "-x", "far"},
		{"--", "-p", "1", "-oProxyCommand=x"}, // the last word is the destination
		{"-h"},
	} {
		_, err := parseArgs(args)
		var u *bootstrap.UsageError
		if !errors.As(err, &u) {
			t.Errorf("%q: %v", args, err)
		}
	}
}

// No -remote is D7's probe and copy-over; -upload says whether to copy.
func TestUploadIsAskByDefaultAndOtherwiseAsSaid(t *testing.T) {
	for args, want := range map[string]client.UploadMode{"": client.UploadAsk, "yes": client.UploadYes, "no": client.UploadNo, "ask": client.UploadAsk} {
		a := []string{"far"}
		if args != "" {
			a = []string{"-upload", args, "far"}
		}
		got, err := parseArgs(a)
		if err != nil || got.upload != want || got.ssh.Server != "" {
			t.Errorf("%q: %+v %v", a, got, err)
		}
	}
	var u *bootstrap.UsageError
	if _, err := parseArgs([]string{"-upload", "maybe", "far"}); !errors.As(err, &u) {
		t.Errorf("-upload maybe: %v", err)
	}
}

func TestVersionNeedsNoDestination(t *testing.T) {
	c, err := parseArgs([]string{"-version"})
	if err != nil || !c.showVersion {
		t.Errorf("%+v %v", c, err)
	}
}

// A plain mosey DEST resumes automatically, -s NAME names a session,
// -new starts one, -list and -kill NAME act on them; -r is gone and the
// four exclude each other (bootstrap.md §2, D8 R1, R2).
func TestSessionsOnTheCommandLine(t *testing.T) {
	for _, c := range []struct {
		args   []string
		attach bootstrap.Attach
		name   string
		list   bool
		kill   string
	}{
		{[]string{"far"}, bootstrap.AttachAuto, "", false, ""},
		{[]string{"-s", "work", "far"}, bootstrap.AttachName, "work", false, ""},
		{[]string{"-s=quiet-heron", "--", "-p", "2222", "far"}, bootstrap.AttachName, "quiet-heron", false, ""},
		{[]string{"-new", "far"}, bootstrap.AttachNew, "", false, ""},
		{[]string{"-list", "far"}, bootstrap.AttachAuto, "", true, ""},
		{[]string{"-kill", "work", "far"}, bootstrap.AttachAuto, "", false, "work"},
	} {
		got, err := parseArgs(c.args)
		if err != nil {
			t.Errorf("%q: %v", c.args, err)
			continue
		}
		if got.attach != c.attach || got.name != c.name || got.list != c.list || got.kill != c.kill || got.ssh.Destination != "far" {
			t.Errorf("%q: %+v", c.args, got)
		}
	}
	for _, args := range [][]string{
		{"-s", "work", "-list", "far"},
		{"-new", "-kill", "work", "far"},
		{"-s", "work", "-new", "far"},
		{"-s", "", "far"},
		{"-s", "-work", "far"},
		{"-s", "a b", "far"},
		{"-kill", "x;y", "far"},
		{"-s", "far"}, // no destination: far is the name
		{"-r", "far"},
	} {
		_, err := parseArgs(args)
		var u *bootstrap.UsageError
		if !errors.As(err, &u) {
			t.Errorf("%q: %v", args, err)
		}
	}
}

func TestPredictIsAdaptiveByDefaultAndTakesMoshsNames(t *testing.T) {
	for args, want := range map[string]predict.Mode{"": predict.Adaptive, "always": predict.Always, "never": predict.Never, "adaptive": predict.Adaptive} {
		a := []string{"far"}
		if args != "" {
			a = []string{"-predict", args, "far"}
		}
		got, err := parseArgs(a)
		if err != nil || got.predict != want {
			t.Errorf("%q: %+v %v", a, got, err)
		}
	}
	var u *bootstrap.UsageError
	if _, err := parseArgs([]string{"-predict", "experimental", "far"}); !errors.As(err, &u) {
		t.Errorf("-predict experimental: %v", err)
	}
}

// -dir and -type go with every command that may start a session, and are
// held to the line's grammar here, as a usage error (bootstrap.md §2).
func TestDirAndTypeOnTheCommandLine(t *testing.T) {
	for _, c := range []struct {
		args     []string
		dir, typ string
	}{
		{[]string{"-dir", "src/my project", "-type", "claude -w x", "far"}, "src/my project", "claude -w x"},
		{[]string{"-s", "work", "-dir", "/srv", "far"}, "/srv", ""},
		{[]string{"-new", "-type", "vim\tx", "far"}, "", "vim\tx"},
		{[]string{"-dir", "", "far"}, "", ""},
	} {
		got, err := parseArgs(c.args)
		if err != nil || got.dir != c.dir || got.typ != c.typ {
			t.Errorf("%q: dir %q, type %q, %v", c.args, got.dir, got.typ, err)
		}
	}
	for _, args := range [][]string{
		{"-list", "-dir", "src", "far"},
		{"-kill", "work", "-type", "ls", "far"},
		{"-type", "echo a\recho b", "far"},
		{"-type", "\x1b[A", "far"},
		{"-dir", "a\tb", "far"},
		{"-dir", strings.Repeat("d", bootstrap.MaxStartText+1), "far"},
	} {
		_, err := parseArgs(args)
		var u *bootstrap.UsageError
		if !errors.As(err, &u) {
			t.Errorf("%q: %v", args, err)
		}
	}
}
