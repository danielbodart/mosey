package server

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/danielbodart/mosey/internal/spawn"
)

func init() { roleChildren["alloc"] = childAlloc }

// childAlloc touches MOSEY_TEST_MIB MiB and keeps it. Then it says so on
// stdout and keeps the memory until stdin closes. Thus a child that the
// limit does not kill ends when its test lets it go.
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
	_, _ = io.Copy(io.Discard, os.Stdin)
	runtime.KeepAlive(keep)
	return nil
}

// spawnAlloc starts childAlloc under a jetsam limit of limitMiB. It
// returns the child, a pipe that says "allocated" once it has, and the
// child's stdin: closing it ends the child.
func spawnAlloc(t *testing.T, mib, limitMiB int) (p *os.Process, out, in *os.File) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	p, err = spawn.Start(spawn.Attr{
		Path:           self,
		Args:           []string{self},
		Env:            []string{roleChildEnv + "=alloc", "MOSEY_TEST_MIB=" + strconv.Itoa(mib)},
		Files:          []*os.File{inR, w, w},
		MemoryLimitMiB: limitMiB,
	})
	w.Close()
	inR.Close()
	if err != nil {
		t.Fatal(err)
	}
	return p, r, inW
}

// TestAnEmuOverItsJetsamLimitIsToldApartFromAKill: the kernel's SIGKILL
// at the limit leaves ru_maxrss at the limit or above, and the spawner
// reads that as the limit hit (server.md §10); a SIGKILL of a small
// process is not.
func TestAnEmuOverItsJetsamLimitIsToldApartFromAKill(t *testing.T) {
	const limit = 64
	p, r, in := spawnAlloc(t, 4*limit, limit)
	buf := make([]byte, 64)
	if n, _ := r.Read(buf); n > 0 {
		// It holds four times its limit and lives: there is no limit.
		// Closing its stdin lets it end.
		t.Errorf("a child that holds %d MiB under a jetsam limit of %d MiB was not killed", 4*limit, limit)
	}
	r.Close()
	in.Close()
	st, err := p.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if !jetsamKilled(st, limit<<20) {
		t.Errorf("over its limit the child ended with %v, rusage %+v: not taken for the limit", st, st.SysUsage())
	}

	p, r, in = spawnAlloc(t, 8, limit)
	r.Read(buf) // "allocated": it is alive and has its memory
	r.Close()
	p.Signal(syscall.SIGKILL)
	in.Close()
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
