package bootstrap

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestTheSSHOptionsTableIsFollowed(t *testing.T) {
	for _, l := range passFlags {
		o, err := ParseSSHOptions([]string{"-" + string(l)})
		if err != nil || !slices.Equal(o.Args, []string{"-" + string(l)}) {
			t.Errorf("-%c: %v %v", l, o.Args, err)
		}
	}
	for _, l := range passValues {
		o, err := ParseSSHOptions([]string{"-" + string(l), "v"})
		if err != nil || !slices.Equal(o.Args, []string{"-" + string(l), "v"}) {
			t.Errorf("-%c v: %v %v", l, o.Args, err)
		}
	}
	for _, l := range "tTNnfsGVOWMSLRDXYgewQy1Z" {
		_, err := ParseSSHOptions([]string{"-" + string(l), "x"})
		var u *UsageError
		if !errors.As(err, &u) || !strings.Contains(u.Msg, "-"+string(l)) {
			t.Errorf("-%c was not refused: %v", l, err)
		}
	}
}

func TestSSHOptionsAreNormalised(t *testing.T) {
	for _, c := range []struct {
		in   []string
		want []string
	}{
		{[]string{"-4vC"}, []string{"-4", "-v", "-C"}},
		{[]string{"-p2222"}, []string{"-p", "2222"}},
		{[]string{"-p", "2222"}, []string{"-p", "2222"}},
		{[]string{"-oUser=x", "-o", "Port=1"}, []string{"-o", "User=x", "-o", "Port=1"}},
		{[]string{"-vp22"}, []string{"-v", "-p", "22"}},
		{[]string{"-o", "-X"}, []string{"-o", "-X"}}, // a value, not an option
		{[]string{"-Av"}, []string{"-v"}},
		{nil, nil},
	} {
		o, err := ParseSSHOptions(c.in)
		if err != nil || !slices.Equal(o.Args, c.want) {
			t.Errorf("%q: %q %v", c.in, o.Args, err)
		}
	}
}

func TestTheLastAgentFlagWins(t *testing.T) {
	for in, want := range map[string]byte{
		"":       0,
		"-A":     'A',
		"-a":     'a',
		"-A -a":  'a',
		"-a -A":  'A',
		"-aA":    'A',
		"-v -Aa": 'a',
	} {
		o, err := ParseSSHOptions(strings.Fields(in))
		if err != nil || o.Agent != want {
			t.Errorf("%q: %c %v", in, o.Agent, err)
		}
	}
}

func TestBadSSHOptionsAreUsageErrors(t *testing.T) {
	for _, in := range [][]string{
		{"host"},
		{"-v", "host"},
		{"--"},
		{"-"},
		{"-p"},
		{"-v", "-o"},
		{"-t"},
		{"-L8080:localhost:80"},
	} {
		_, err := ParseSSHOptions(in)
		var u *UsageError
		if !errors.As(err, &u) {
			t.Errorf("%q: %v", in, err)
		}
	}
}

// What follows mosey's -- is ssh's options up to DESTINATION, which is the
// first word that is neither an option nor an option's value, by ssh's
// own getopt rules; everything from it on is the rest (§2).
func TestSSHOptionsEndAtTheDestination(t *testing.T) {
	for _, c := range []struct {
		in, opts, rest []string
	}{
		{nil, nil, nil},
		{[]string{"far"}, []string{}, []string{"far"}},
		{[]string{"-p", "2222", "far", "ls", "-la"}, []string{"-p", "2222"}, []string{"far", "ls", "-la"}},
		{[]string{"-p2222", "-v", "far"}, []string{"-p2222", "-v"}, []string{"far"}},
		{[]string{"-vo", "User=x", "far"}, []string{"-vo", "User=x"}, []string{"far"}},
		{[]string{"-o", "-X", "far"}, []string{"-o", "-X"}, []string{"far"}}, // a value, not an option
		{[]string{"-v", "-", "x"}, []string{"-v"}, []string{"-", "x"}},
		{[]string{"-p"}, []string{"-p"}, []string{}},
		{[]string{"-v", "--", "far"}, []string{"-v", "--"}, []string{"far"}}, // ParseSSHOptions refuses the second --
	} {
		opts, rest := SplitSSHOptions(c.in)
		if !slices.Equal(opts, c.opts) || !slices.Equal(rest, c.rest) {
			t.Errorf("%q: %q then %q", c.in, opts, rest)
		}
	}
}
