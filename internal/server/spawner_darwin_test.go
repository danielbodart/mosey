package server

import (
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/danielbodart/mosey/internal/spawn"
)

func init() { roleChildren["alloc"] = childAlloc }

// childAlloc touches MOSEY_TEST_MIB MiB and keeps it, then waits to be
// killed.
func childAlloc() error {
	mib, _ := strconv.Atoi(os.Getenv("MOSEY_TEST_MIB"))
	var keep [][]byte
	for range mib {
		b := make([]byte, 1<<20)
		for i := 0; i < len(b); i += 4096 {
			b[i] = 1
		}
		keep = append(keep, b)
	}
	os.Stdout.WriteString("allocated\n")
	time.Sleep(time.Hour)
	return nil
}

// spawnAlloc starts childAlloc under a jetsam limit of limitMiB and
// returns it and a pipe that says "allocated" once it has.
func spawnAlloc(t *testing.T, mib, limitMiB int) (*os.Process, *os.File) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	p, err := spawn.Start(spawn.Attr{
		Path:           self,
		Args:           []string{self},
		Env:            []string{roleChildEnv + "=alloc", "MOSEY_TEST_MIB=" + strconv.Itoa(mib)},
		Files:          []*os.File{nil, w, w},
		MemoryLimitMiB: limitMiB,
	})
	w.Close()
	if err != nil {
		t.Fatal(err)
	}
	return p, r
}

// TestAnEmuOverItsJetsamLimitIsToldApartFromAKill: the kernel's SIGKILL
// at the limit leaves ru_maxrss at the limit or above, and the spawner
// reads that as the limit hit (server.md §10); a SIGKILL of a small
// process is not.
func TestAnEmuOverItsJetsamLimitIsToldApartFromAKill(t *testing.T) {
	const limit = 64
	p, r := spawnAlloc(t, 4*limit, limit)
	r.Close()
	st, err := p.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if !jetsamKilled(st, limit<<20) {
		t.Errorf("over its limit the child ended with %v, rusage %+v: not taken for the limit", st, st.SysUsage())
	}

	p, r = spawnAlloc(t, 8, limit)
	buf := make([]byte, 64)
	r.Read(buf) // "allocated": it is alive and has its memory
	r.Close()
	p.Signal(syscall.SIGKILL)
	if st, err = p.Wait(); err != nil {
		t.Fatal(err)
	}
	if jetsamKilled(st, limit<<20) {
		t.Errorf("a SIGKILL of a small child (%v) was taken for the limit", st)
	}
	// What classify does with the same state when proto asked for the kill.
	s := &spawner{killAsked: map[uint32]bool{1: true}}
	if s.limitHit(&child{gen: 1}, st) {
		t.Error("a kill proto asked for was taken for the limit")
	}
}

// TestTheSessionsDirectoryOnMacOSIsAlwaysUnderTmp: neither
// XDG_RUNTIME_DIR nor TMPDIR moves it (server.md §10).
func TestTheSessionsDirectoryOnMacOSIsAlwaysUnderTmp(t *testing.T) {
	env := map[string]string{"XDG_RUNTIME_DIR": "/run/user/501", "TMPDIR": "/var/folders/ab/cdefgh/T/"}
	want := "/tmp/mosey-" + strconv.Itoa(os.Getuid())
	if got := sessionsDir(func(k string) string { return env[k] }); got != want {
		t.Errorf("sessionsDir is %s, not %s", got, want)
	}
}

// TestTheSessionsLockOnMacOSIsTheDirectoryItself: no regular file is made,
// the lock is exclusive, and closing it lets the next launcher in.
func TestTheSessionsLockOnMacOSIsTheDirectoryItself(t *testing.T) {
	base := filepath.Join(runtimeDir(t), "mosey")
	first, err := lockSessions(base, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := lockSessions(base, 100*time.Millisecond); err == nil {
		second.Close()
		t.Fatal("a second launcher took the lock while the first held it")
	}
	first.Close()
	again, err := lockSessions(base, time.Second)
	if err != nil {
		t.Fatalf("the lock was not let go: %v", err)
	}
	again.Close()
	entries, _ := os.ReadDir(base)
	for _, e := range entries {
		t.Errorf("the sessions directory holds %s", e.Name())
	}
}
