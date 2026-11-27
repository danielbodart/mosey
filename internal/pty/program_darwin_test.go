package pty

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// realDir is dir as the kernel names it: on macOS /tmp and /var are
// symlinks into /private.
func realDir(t *testing.T, dir string) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestThisProcessIsDescribedBySysctlAndProcPidinfo(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	p := ProgramOf(os.Getpid())
	if p.Name != filepath.Base(os.Args[0]) || p.Dir != realDir(t, wd) {
		t.Errorf("%+v, want %s in %s", p, filepath.Base(os.Args[0]), realDir(t, wd))
	}
}

// A child is named by the argv[0] it was given, less a login shell's
// "-", and its directory is the one it was started in. cmd.Start returns
// only after the exec, so the arguments are the child's own.
func TestAChildIsNamedByItsArgv0AndFoundInItsDirectory(t *testing.T) {
	dir := t.TempDir()
	cmd := &exec.Cmd{Path: "/bin/cat", Args: []string{"-mosey-test-shell"}, Dir: dir}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Wait()
	defer stdin.Close()
	want := Program{Name: "mosey-test-shell", Dir: realDir(t, dir)}
	if p := ProgramOf(cmd.Process.Pid); p != want {
		t.Errorf("%+v, want %+v", p, want)
	}
}

// launchd, pid 1, is root's: its arguments and directory are not ours to
// read, and its name comes from kinfo_proc. A pid with no process is an
// empty Program. macOS pids stay under PID_MAX, 99999 (sys/proc.h).
func TestAnotherUsersProcessGivesOnlyItsNameAndAGoneOneNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root may read launchd's arguments")
	}
	if p := ProgramOf(1); p != (Program{Name: "launchd"}) {
		t.Errorf("launchd: %+v", p)
	}
	if p := ProgramOf(1 << 30); p != (Program{}) {
		t.Errorf("no process: %+v", p)
	}
}
