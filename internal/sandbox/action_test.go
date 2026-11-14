package sandbox

import (
	"os"
	"testing"
)

// D22 locks Kill on amd64. Every green commit is a release (D10), so the
// release job runs this with MOSEY_RELEASE_CHECK=1 and refuses to publish
// a build whose amd64 action is anything else (server.md §6.1). Ordinary
// CI skips it while development builds run Errno, until the KILL soak is a
// CI job and amd64 switches.
func TestReleaseAction(t *testing.T) {
	if os.Getenv("MOSEY_RELEASE_CHECK") != "1" {
		t.Skip("only the release job checks this (MOSEY_RELEASE_CHECK=1)")
	}
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
