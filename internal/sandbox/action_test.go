package sandbox

import (
	"testing"
)

// D22 locks Kill on amd64, and every green commit is a release (D10), so
// check fails on any build whose amd64 action is anything else (server.md
// §6.1).
func TestReleaseAction(t *testing.T) {
	for _, arch := range []Arch{AMD64, ARM64} {
		if builtAction[arch] != Kill {
			t.Errorf("%s is built with %s; a release needs kill (D22)", arch, builtAction[arch])
		}
	}
}

func TestEveryArchitectureHasABuiltAction(t *testing.T) {
	for _, arch := range arches {
		if _, ok := builtAction[arch]; !ok {
			t.Errorf("%s has no action", arch)
		}
	}
}
