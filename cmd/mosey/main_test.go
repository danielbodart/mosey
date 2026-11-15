package main

import (
	"errors"
	"slices"
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

// -r resumes the user's one session, -r=SESSION a named one, -list lists
// them (bootstrap.md §9.2, §9.4); a plain mosey DEST never resumes.
func TestResumeAndListOnTheCommandLine(t *testing.T) {
	sid := [16]byte{0x0f, 0x3a, 15: 0x01}
	for _, c := range []struct {
		args   []string
		resume bool
		sid    [16]byte
		list   bool
	}{
		{[]string{"far"}, false, [16]byte{}, false},
		{[]string{"-r", "far"}, true, bootstrap.AnySession, false},
		{[]string{"-r=0f3a0000000000000000000000000001", "far"}, true, sid, false},
		{[]string{"-r", "--", "-p", "2222", "far"}, true, bootstrap.AnySession, false},
		{[]string{"-list", "far"}, false, [16]byte{}, true},
	} {
		got, err := parseArgs(c.args)
		if err != nil {
			t.Errorf("%q: %v", c.args, err)
			continue
		}
		if got.resume.set != c.resume || got.resume.sid != c.sid || got.list != c.list || got.ssh.Destination != "far" {
			t.Errorf("%q: %+v", c.args, got)
		}
	}
	for _, args := range [][]string{
		{"-r", "-list", "far"},
		{"-r=0f3a", "far"},
		{"-r=0F3A0000000000000000000000000001x", "far"},
		{"-r=00000000000000000000000000000000", "far"},    // AnySession is never a session's name
		{"-r", "0f3a0000000000000000000000000001", "far"}, // the value needs its =
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
