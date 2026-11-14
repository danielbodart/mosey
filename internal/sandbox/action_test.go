package sandbox

import (
	"testing"
)

// D22 locks Kill on amd64, and every green commit is a release (D10), so
// check fails on any build whose amd64 action is anything else (server.md
// §6.1).
func TestReleaseAction(t *testing.T) {
	if builtAction[AMD64] != Kill {
		t.Fatalf("amd64 is built with %s; a release needs kill (D22)", builtAction[AMD64])
	}
}

func TestEveryArchitectureHasABuiltAction(t *testing.T) {
	for _, arch := range arches {
		if _, ok := builtAction[arch]; !ok {
			t.Errorf("%s has no action", arch)
		}
	}
}
