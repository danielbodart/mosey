package pty

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// The slave's path is opened, so only a /dev/ttys device passes, and the
// buffer must hold a NUL.
func TestOnlyADevTtysNameIsTakenAsTheSlave(t *testing.T) {
	for in, want := range map[string]string{
		"/dev/ttys003\x00junk":  "/dev/ttys003",
		"/dev/ttys12\x00":       "/dev/ttys12",
		"/dev/ttys\x00":         "",
		"/dev/ttys0x\x00":       "",
		"/dev/ttys/../sda\x00":  "",
		"/tmp/ttys003\x00":      "",
		"/dev/ttys003":          "",
		"\x00":                  "",
		"/dev/ttys003/\x00":     "",
		"/dev/ttys 003\x00junk": "",
	} {
		got, err := checkSlaveName([]byte(in))
		if got != want || (err == nil) != (want != "") {
			t.Errorf("%q: %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestOnlyAnotherProcessOnTheLeadersTerminalIsAnotherMember(t *testing.T) {
	rec := func(pid, tdev int32) unix.KinfoProc {
		var k unix.KinfoProc
		k.Proc.P_pid = pid
		k.Eproc.Tdev = tdev
		return k
	}
	for _, c := range []struct {
		name  string
		procs []unix.KinfoProc
		other bool
	}{
		{"the leader alone", []unix.KinfoProc{rec(7, 5)}, false},
		{"others on another terminal or none", []unix.KinfoProc{rec(1, noDev), rec(7, 5), rec(9, 6)}, false},
		{"a job on the leader's terminal", []unix.KinfoProc{rec(7, 5), rec(8, 5)}, true},
	} {
		got, err := hasOtherOnTerminal(c.procs, 7)
		if err != nil || got != c.other {
			t.Errorf("%s: %v, %v; want %v", c.name, got, err, c.other)
		}
	}
	// With no terminal to compare, no answer is safe.
	for _, procs := range [][]unix.KinfoProc{nil, {rec(8, 5)}, {rec(7, noDev), rec(8, noDev)}} {
		if _, err := hasOtherOnTerminal(procs, 7); err == nil {
			t.Errorf("%d records: no error", len(procs))
		}
	}
}

// The real kinfo_proc of this process gives its effective uid, so a false
// from ForegroundRoot is a measured uid. A pid with no process is not
// root, and launchd, pid 1, the one root process every Mac has, is.
func TestKernProcGivesAProcesssEffectiveUID(t *testing.T) {
	if processRoot(os.Getpid()) != (os.Geteuid() == 0) {
		t.Fatalf("root %v; this test runs as uid %d", processRoot(os.Getpid()), os.Geteuid())
	}
	k, err := unix.SysctlKinfoProc("kern.proc.pid", os.Getpid())
	if err != nil || int(k.Eproc.Ucred.Uid) != os.Geteuid() || int(k.Eproc.Pcred.P_ruid) != os.Getuid() {
		t.Fatalf("kinfo_proc %+v, %v", k, err)
	}
	// macOS pids stay under PID_MAX, 99999 (sys/proc.h in the macOS SDK).
	if processRoot(1 << 30) {
		t.Error("a pid with no process is root")
	}
	if !processRoot(1) {
		t.Error("launchd is not root")
	}
}
