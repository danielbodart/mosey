package bootstrap

import (
	"bytes"
	"fmt"
	"strings"
)

// Config is what `ssh -G` printed (§3): each keyword, lower case, with
// every value in the order printed (identityfile and sendenv repeat). It
// is a plain value so tests build it by hand.
type Config map[string][]string

// MaxConfig bounds ssh -G's output; a typical config prints about 3 KiB.
const MaxConfig = 256 << 10

// ParseConfig reads ssh -G's output: lines of "keyword value". The output
// is the local ssh's, from the user's own config, so it is trusted to be
// ssh's, but still read strictly enough that a wrapper printing something
// else is noticed rather than misread.
func ParseConfig(out []byte) (Config, error) {
	if len(out) > MaxConfig {
		return nil, fmt.Errorf("ssh -G printed over %d bytes", MaxConfig)
	}
	c := Config{}
	for n, line := range bytes.Split(out, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		k, v, _ := bytes.Cut(line, []byte(" "))
		if !validKeyword(k) {
			return nil, fmt.Errorf("ssh -G line %d: %q is not a keyword", n+1, k)
		}
		// ssh keywords are case-insensitive, and some OpenSSH releases
		// (9.6 on Ubuntu 24.04, for one) print a keyword in mixed case:
		// "canonicalizePermittedcnames". Fold it, as ssh itself does.
		key := strings.ToLower(string(k))
		c[key] = append(c[key], string(v))
	}
	return c, nil
}

func validKeyword(k []byte) bool {
	if len(k) == 0 {
		return false
	}
	for _, c := range k {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// Get is keyword's first value, or "". ssh uses the first value it
// obtains for most keywords, and ssh -G prints that one.
func (c Config) Get(keyword string) string {
	if v := c[keyword]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// Has says whether ssh -G printed keyword at all: how the client learns
// whether this ssh knows a keyword, with no version parsing (§3).
func (c Config) Has(keyword string) bool {
	_, ok := c[keyword]
	return ok
}

// AgentSocket is §5: the socket agent forwarding would forward, following
// ssh's own config (ForwardAgent with its socket and $VAR forms, with -A
// and -a already applied by ssh -G), or ok false for agent off. Slice 1
// computes and logs it but always bootstraps with ForwardAgent=no; the
// agent slice acts on it (D25).
func AgentSocket(c Config, getenv func(string) string) (path string, ok bool) {
	fa := c.Get("forwardagent")
	switch {
	case fa == "" || fa == "no":
		return "", false
	case fa == "yes":
		ia := c.Get("identityagent")
		switch {
		case ia == "none":
			// OpenSSH 10.6 forwards no agent at all then (checked
			// black-box: TestForwardAgentYesForwardsTheIdentityAgent).
			return "", false
		case ia == "" || ia == "SSH_AUTH_SOCK":
			path = getenv("SSH_AUTH_SOCK")
		case strings.HasPrefix(ia, "$"):
			// ssh_config(5) lets IdentityAgent name an environment
			// variable, as ForwardAgent does.
			path = getenv(ia[1:])
		default:
			path = ia
		}
	case strings.HasPrefix(fa, "$"):
		path = getenv(fa[1:])
	default:
		path = fa
	}
	return path, path != ""
}
