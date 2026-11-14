package nocore

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// The calls change the process for good, so each runs in a child: this
// test binary, re-executed with the call to make in the environment.
const childEnv = "NOCORE_TEST_CALL"

func TestMain(m *testing.M) {
	switch os.Getenv(childEnv) {
	case "":
		os.Exit(m.Run())
	case "process":
		report(Process())
	case "notdumpable":
		report(NotDumpable())
	}
}

// report prints what the child's call left behind: the error, the core
// rlimit's soft and hard values, and (on Linux) the dumpable flag.
func report(err error) {
	var lim unix.Rlimit
	unix.Getrlimit(unix.RLIMIT_CORE, &lim)
	if err != nil {
		os.Stdout.WriteString("err=" + err.Error() + "\n")
	}
	os.Stdout.WriteString("core=" + itoa(lim.Cur) + "/" + itoa(lim.Max) + "\n")
	os.Stdout.WriteString(dumpable())
	os.Exit(0)
}

func itoa(v uint64) string {
	if v == unix.RLIM_INFINITY {
		return "unlimited"
	}
	return strconv.FormatUint(v, 10)
}

func inChild(t *testing.T, call string) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^$")
	cmd.Env = append(os.Environ(), childEnv+"="+call)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("the child: %v", err)
	}
	return string(out)
}

func TestProcessLeavesNoCore(t *testing.T) {
	out := inChild(t, "process")
	if strings.Contains(out, "err=") {
		t.Fatalf("Process failed:\n%s", out)
	}
	if !strings.Contains(out, "core=0/0\n") {
		t.Errorf("RLIMIT_CORE is not 0 for good:\n%s", out)
	}
	checkNotDumpable(t, out)
}

// The launcher and spawner leave the rlimit alone, for the login shell's
// sake, whatever they do to themselves.
func TestNotDumpableLeavesTheCoreLimitToTheUser(t *testing.T) {
	var before unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &before); err != nil {
		t.Fatal(err)
	}
	out := inChild(t, "notdumpable")
	if !strings.Contains(out, "core="+itoa(before.Cur)+"/"+itoa(before.Max)+"\n") {
		t.Errorf("the core rlimit changed from %d/%d:\n%s", before.Cur, before.Max, out)
	}
	checkNotDumpable(t, out)
}
