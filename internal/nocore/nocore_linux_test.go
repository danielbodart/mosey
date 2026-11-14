package nocore

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func dumpable() string {
	v, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		return "dumpable=" + err.Error() + "\n"
	}
	return "dumpable=" + itoa(uint64(v)) + "\n"
}

func checkNotDumpable(t *testing.T, out string) {
	t.Helper()
	if strings.Contains(out, "err=") {
		t.Fatalf("the call failed:\n%s", out)
	}
	if !strings.Contains(out, "dumpable=0\n") {
		t.Errorf("the process is still dumpable:\n%s", out)
	}
}
