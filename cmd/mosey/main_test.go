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
		{"-bogus", "far"},
		{"far", "echo\x1b[2J"},
		{"--", "-t", "far"},
		{"-remote", "mo sey", "far"},
		{"-remote", "-x", "far"},
		{"--", "-p", "1", "-oProxyCommand=x"}, // no destination: localhost refuses ssh options
		{"--", "-v", "--", "far"},
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

// localhost is this machine, with no ssh (bootstrap.md §2.2): every
// session command works, -A and -a still say whether the shell gets the
// agent, and -remote names the local binary, which needs no quoting.
func TestLocalhostIsThisMachine(t *testing.T) {
	for _, c := range []struct {
		args          []string
		attach        bootstrap.Attach
		name, kill    string
		list          bool
		dir, typ, bin string
		agent         byte
	}{
		{args: []string{"localhost"}, attach: bootstrap.AttachAuto},
		{args: []string{"LocalHost"}, attach: bootstrap.AttachAuto},
		{args: []string{"--", "localhost"}, attach: bootstrap.AttachAuto},
		{args: []string{"-s", "far", "localhost"}, attach: bootstrap.AttachName, name: "far"},
		{args: []string{"-new", "localhost"}, attach: bootstrap.AttachNew},
		{args: []string{"-list", "localhost"}, attach: bootstrap.AttachAuto, list: true},
		{args: []string{"-kill", "work", "localhost"}, attach: bootstrap.AttachAuto, kill: "work"},
		{args: []string{"-s", "work", "-dir", "Projects/x", "-type", "claude", "localhost"}, attach: bootstrap.AttachName, name: "work", dir: "Projects/x", typ: "claude"},
		{args: []string{"-remote", "/opt/my tools/mosey", "localhost"}, attach: bootstrap.AttachAuto, bin: "/opt/my tools/mosey"},
		{args: []string{"-a", "localhost"}, attach: bootstrap.AttachAuto, agent: 'a'},
		{args: []string{"-a", "-A", "localhost"}, attach: bootstrap.AttachAuto, agent: 'A'},
	} {
		got, err := parseArgs(c.args)
		if err != nil {
			t.Errorf("%q: %v", c.args, err)
			continue
		}
		s := got.ssh
		if !s.Local() || s.Program != "" || s.Server != c.bin || s.Options.Agent != c.agent || len(s.Options.Args) != 0 {
			t.Errorf("%q: %+v", c.args, s)
		}
		if got.attach != c.attach || got.name != c.name || got.list != c.list || got.kill != c.kill || got.dir != c.dir || got.typ != c.typ {
			t.Errorf("%q: %+v", c.args, got)
		}
	}
	// Only the word itself: an address or a user@ is a host for ssh, so
	// the ssh path can still be run against this machine.
	for _, dest := range []string{"127.0.0.1", "::1", "me@localhost", "localhost.", "localhost2"} {
		got, err := parseArgs([]string{dest})
		if err != nil || got.ssh.Local() || got.ssh.Destination != dest || got.ssh.Program != "ssh" {
			t.Errorf("%q: %+v %v", dest, got.ssh, err)
		}
	}
	// What only says how to use ssh, or what to copy to a host over it,
	// is refused, not ignored.
	for _, args := range [][]string{
		{"-upload", "yes", "localhost"},
		{"-upload=ask", "localhost"},
		{"-ssh", "/usr/bin/ssh", "localhost"},
		{"-list", "-ssh", "ssh", "localhost"},
		{"--", "-p", "22", "localhost"},
	} {
		_, err := parseArgs(args)
		var u *bootstrap.UsageError
		if !errors.As(err, &u) || !strings.Contains(u.Msg, "no use with localhost") {
			t.Errorf("%q: %v", args, err)
		}
	}
}

// No DESTINATION is this machine, the same as localhost, as tmux is (Dan,
// 2026-11-18; bootstrap.md §2.2); -h and -help are the usage.
func TestNoDestinationIsThisMachine(t *testing.T) {
	for _, args := range [][]string{{"-h"}, {"-help"}} {
		c, err := parseArgs(args)
		if err != nil || !c.help {
			t.Errorf("%q: %+v %v", args, c, err)
		}
	}
	for _, c := range []struct {
		args   []string
		attach bootstrap.Attach
		list   bool
		kill   string
		agent  byte
	}{
		{args: nil, attach: bootstrap.AttachAuto},
		{args: []string{"--"}, attach: bootstrap.AttachAuto},
		{args: []string{"-list"}, attach: bootstrap.AttachAuto, list: true},
		{args: []string{"-s", "work"}, attach: bootstrap.AttachName},
		{args: []string{"-new"}, attach: bootstrap.AttachNew},
		{args: []string{"-kill", "work"}, attach: bootstrap.AttachAuto, kill: "work"},
		{args: []string{"-a"}, attach: bootstrap.AttachAuto, agent: 'a'},
		{args: []string{"-dir", "src"}, attach: bootstrap.AttachAuto},
	} {
		got, err := parseArgs(c.args)
		if err != nil || got.help || !got.ssh.Local() || got.ssh.Program != "" || got.attach != c.attach || got.list != c.list || got.kill != c.kill || got.ssh.Options.Agent != c.agent {
			t.Errorf("%q: %+v %v", c.args, got, err)
		}
	}
	// Flags that need ssh are still refused, as with localhost.
	for _, args := range [][]string{{"-upload", "yes"}, {"-ssh", "ssh"}, {"--", "-p", "22"}} {
		_, err := parseArgs(args)
		var u *bootstrap.UsageError
		if !errors.As(err, &u) || !strings.Contains(u.Msg, "no use with localhost") {
			t.Errorf("%q: %v", args, err)
		}
	}
}

// The words after DESTINATION are a command, as ssh takes one
// (bootstrap.md §2, §9.2.3): joined with spaces, never read as mosey's or
// ssh's flags, with ssh's options before the destination after --. A
// plain mosey DEST COMMAND is auto with the command, so the launcher can
// return to a detached session of that command (PLAN D8, option C); -s
// and -new keep their meaning.
func TestTheWordsAfterTheDestinationAreACommand(t *testing.T) {
	for _, c := range []struct {
		args    []string
		dest    string
		ssh     []string
		command string
		attach  bootstrap.Attach
		name    string
		dir     string
	}{
		{args: []string{"far", "claude"}, dest: "far", command: "claude", attach: bootstrap.AttachAuto},
		{args: []string{"far", "ls", "-la", "--", "-s", "x"}, dest: "far", command: "ls -la -- -s x", attach: bootstrap.AttachAuto},
		{args: []string{"far", "sh", "-c", "echo $((6*7)); exit 3"}, dest: "far", command: "sh -c echo $((6*7)); exit 3", attach: bootstrap.AttachAuto},
		{args: []string{"-s", "work", "-dir", "src", "far", "claude"}, dest: "far", command: "claude", attach: bootstrap.AttachName, name: "work", dir: "src"},
		{args: []string{"-new", "far", "htop"}, dest: "far", command: "htop", attach: bootstrap.AttachNew},
		{args: []string{"--", "-p", "2222", "-v", "far", "top", "-d", "1"}, dest: "far", ssh: []string{"-p", "2222", "-v"}, command: "top -d 1", attach: bootstrap.AttachAuto},
		{args: []string{"-s", "work", "--", "-oUser=me", "far", "claude"}, dest: "far", ssh: []string{"-o", "User=me"}, command: "claude", attach: bootstrap.AttachName, name: "work"},
		{args: []string{"localhost", "htop"}, dest: "localhost", command: "htop", attach: bootstrap.AttachAuto},
		{args: []string{"far"}, dest: "far", attach: bootstrap.AttachAuto},
	} {
		got, err := parseArgs(c.args)
		if err != nil {
			t.Errorf("%q: %v", c.args, err)
			continue
		}
		if got.ssh.Destination != c.dest || !slices.Equal(got.ssh.Options.Args, c.ssh) || got.command != c.command ||
			got.attach != c.attach || got.name != c.name || got.dir != c.dir {
			t.Errorf("%q: %+v", c.args, got)
		}
	}
	for _, args := range [][]string{
		{"-list", "far", "ls"},
		{"-kill", "work", "far", "ls"},
		{"-type", "vim", "far", "ls"},
		{"far", "ls\nrm"},
		{"far", strings.Repeat("c", bootstrap.MaxStartText+1)},
		{"far", strings.Repeat("c", bootstrap.MaxStartText/2), strings.Repeat("c", bootstrap.MaxStartText/2)}, // the joining space counts
		{"--", "-p", "22", "localhost", "ls"},
	} {
		_, err := parseArgs(args)
		var u *bootstrap.UsageError
		if !errors.As(err, &u) {
			t.Errorf("%q: %v", args, err)
		}
	}
}

func TestCloseIfIdleIsLocalOnly(t *testing.T) {
	for _, args := range [][]string{
		{"-close-if-idle"},
		{"-new", "-close-if-idle"},
		{"-s", "work", "-close-if-idle"},
		{"-close-if-idle", "localhost"},
		{"-new", "-close-if-idle", "LocalHost"},
	} {
		got, err := parseArgs(args)
		if err != nil || !got.closeIfIdle || !got.ssh.Local() {
			t.Errorf("%q: %+v %v", args, got, err)
		}
	}
	for _, args := range [][]string{
		{"-close-if-idle", "far"},
		{"-close-if-idle", "127.0.0.1"},
		{"-close-if-idle", "-list"},
		{"-close-if-idle", "-kill", "work"},
	} {
		_, err := parseArgs(args)
		var u *bootstrap.UsageError
		if !errors.As(err, &u) {
			t.Errorf("%q: want UsageError, got %v", args, err)
		}
	}
}
