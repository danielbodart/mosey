//go:build !linux

package nocore

import (
	"strings"
	"testing"
)

func dumpable() string { return "" }

// Off Linux there is no flag to check, and NotDumpable says so.
func checkNotDumpable(t *testing.T, out string) {
	t.Helper()
	if strings.Contains(out, "err=") && !strings.Contains(out, "unsupported") {
		t.Fatalf("the call failed:\n%s", out)
	}
}
