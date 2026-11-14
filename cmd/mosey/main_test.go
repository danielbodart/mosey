package main

import (
	"errors"
	"slices"
	"testing"

	"github.com/danielbodart/mosey/internal/bootstrap"
)

func TestTheClientCommandLine(t *testing.T) {
	for _, c := range []struct {
		args   []string
		dest   string
		server string
		ssh    []string
		agent  byte
	}{
		{[]string{"far"}, "far", "mosey", nil, 0},
		{[]string{"server"}, "server", "mosey", nil, 0}, // a host called server is a host
		{[]string{"-remote", "~/bin/mosey", "me@far"}, "me@far", "~/bin/mosey", nil, 0},
		{[]string{"-A", "--", "-p2222", "-v", "far"}, "far", "mosey", []string{"-p", "2222", "-v"}, 'A'},
		{[]string{"-A", "-a", "far"}, "far", "mosey", nil, 'a'},
		{[]string{"-a", "-A", "far"}, "far", "mosey", nil, 'A'},
		{[]string{"-A", "--", "-a", "far"}, "far", "mosey", nil, 'a'}, // ssh's options come last, so win
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

func TestVersionNeedsNoDestination(t *testing.T) {
	c, err := parseArgs([]string{"-version"})
	if err != nil || !c.showVersion {
		t.Errorf("%+v %v", c, err)
	}
}
