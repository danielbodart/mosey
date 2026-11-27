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

func TestASessionWithOnlyItsLeaderHasNoOtherMember(t *testing.T) {
	rec := func(pid int32) unix.KinfoProc {
		var k unix.KinfoProc
		k.Proc.P_pid = pid
		return k
	}
	if hasOtherPID(nil, 7) || hasOtherPID([]unix.KinfoProc{rec(7)}, 7) {
		t.Error("the leader alone has another member")
	}
	if !hasOtherPID([]unix.KinfoProc{rec(7), rec(8)}, 7) {
		t.Error("a job in the session is not seen")
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
	// macOS pids stay under PID_MAX, 99999 (sys/proc_internal.h).
	if processRoot(1 << 30) {
		t.Error("a pid with no process is root")
	}
	if !processRoot(1) {
		t.Error("launchd is not root")
	}
}
