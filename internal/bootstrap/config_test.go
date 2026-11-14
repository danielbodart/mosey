package bootstrap

import (
	"slices"
	"strings"
	"testing"
)

func TestSSHGOutputIsReadKeywordByKeyword(t *testing.T) {
	c, err := ParseConfig([]byte("user me\nhostname 192.0.2.7\nidentityfile ~/.ssh/a\nidentityfile ~/.ssh/b\nsendenv LANG\nlocalforward 8080 [x]:80\nkbdinteractivedevices\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Get("hostname") != "192.0.2.7" || c.Get("nothing") != "" {
		t.Errorf("%v", c)
	}
	if !slices.Equal(c["identityfile"], []string{"~/.ssh/a", "~/.ssh/b"}) {
		t.Errorf("identityfile %v", c["identityfile"])
	}
	if c.Get("localforward") != "8080 [x]:80" || !c.Has("kbdinteractivedevices") || c.Has("sessiontype") {
		t.Errorf("%v", c)
	}
	for _, bad := range []string{"Hostname x\n", " x\n", "host-name x\n", strings.Repeat("a b\n", MaxConfig/4+1)} {
		if _, err := ParseConfig([]byte(bad)); err == nil {
			t.Errorf("%.20q was accepted", bad)
		}
	}
}

// §5's table: the socket agent forwarding would use.
func TestTheAgentDecisionFollowsSSHsConfig(t *testing.T) {
	env := map[string]string{"SSH_AUTH_SOCK": "/run/agent", "FOO": "/run/foo"}
	getenv := func(n string) string { return env[n] }
	for _, c := range []struct {
		forward, identity string
		want              string
	}{
		{"no", "", ""},
		{"", "", ""},
		{"yes", "", "/run/agent"},
		{"yes", "none", "/run/agent"},
		{"yes", "SSH_AUTH_SOCK", "/run/agent"},
		{"yes", "/run/quoin", "/run/quoin"},
		{"yes", "$FOO", "/run/foo"},
		{"$FOO", "", "/run/foo"},
		{"$UNSET", "", ""},
		{"/tmp/sock", "/run/quoin", "/tmp/sock"},
	} {
		cfg := Config{}
		if c.forward != "" {
			cfg["forwardagent"] = []string{c.forward}
		}
		if c.identity != "" {
			cfg["identityagent"] = []string{c.identity}
		}
		got, ok := AgentSocket(cfg, getenv)
		if got != c.want || ok != (c.want != "") {
			t.Errorf("forwardagent %q identityagent %q: %q %v", c.forward, c.identity, got, ok)
		}
	}
	env["SSH_AUTH_SOCK"] = ""
	if _, ok := AgentSocket(Config{"forwardagent": {"yes"}}, getenv); ok {
		t.Error("yes with no SSH_AUTH_SOCK is on")
	}
}
