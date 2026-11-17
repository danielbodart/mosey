//go:build linux

package e2e

import (
	"slices"
	"testing"
)

// A child of a test never inherits the developer's agent or ssh login:
// it gets the throwaway agent only when the test names it, and a bare
// name unsets what the test would otherwise pass on (CLAUDE.md: tests
// never touch the user's agent).
func TestAChildNeverInheritsTheUsersAgentOrLogin(t *testing.T) {
	for _, name := range userSessionVars {
		t.Setenv(name, "/the/users/"+name)
	}
	t.Setenv("MOSEY_E2E_KEPT", "kept")
	t.Setenv("MOSEY_E2E_UNSET", "gone")

	env := childEnv("SSH_AUTH_SOCK=/throwaway/agent.sock", "MOSEY_E2E_UNSET", "MOSEY_E2E_KEPT=replaced")
	for _, kv := range env {
		for _, name := range userSessionVars {
			if kv == name+"=/the/users/"+name {
				t.Errorf("the child inherits %s", kv)
			}
		}
	}
	for _, want := range []string{"SSH_AUTH_SOCK=/throwaway/agent.sock", "MOSEY_E2E_KEPT=replaced"} {
		if n := countOf(env, want); n != 1 {
			t.Errorf("%s is in the child's environment %d times, want once", want, n)
		}
	}
	if slices.ContainsFunc(env, func(kv string) bool { return kv == "MOSEY_E2E_KEPT=kept" || kv == "MOSEY_E2E_UNSET=gone" }) {
		t.Errorf("a named variable kept its inherited value: %q", env)
	}
	if got := command("true").Env; slices.Contains(got, "SSH_AUTH_SOCK=/the/users/SSH_AUTH_SOCK") {
		t.Errorf("command passes on the user's agent")
	}
}

func countOf(env []string, kv string) int {
	n := 0
	for _, e := range env {
		if e == kv {
			n++
		}
	}
	return n
}
