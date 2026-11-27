package spawn

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// childEnv makes this test binary a child: its value says what to do.
const childEnv = "MOSEY_SPAWN_TEST_CHILD"

func TestMain(m *testing.M) {
	switch os.Getenv(childEnv) {
	case "":
		os.Exit(m.Run())
	case "fds":
		childFDs()
	case "alloc":
		n, _ := strconv.Atoi(os.Getenv("MIB"))
		childAlloc(n)
	}
	os.Exit(0)
}

// childFDs writes to fd 2 which of fds 0 to 63 are open, then copies fd
// 3 to fd 2.
func childFDs() {
	var open []string
	for fd := range 64 {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err == nil {
			open = append(open, strconv.Itoa(fd))
		}
	}
	fmt.Fprintf(os.Stderr, "open %s\n", strings.Join(open, ","))
	b, _ := io.ReadAll(os.NewFile(3, "in"))
	os.Stderr.Write(b)
}

// childAlloc touches mib MiB, one page at a time, and keeps it.
func childAlloc(mib int) {
	var keep [][]byte
	for range mib {
		b := make([]byte, 1<<20)
		for i := 0; i < len(b); i += 4096 {
			b[i] = 1
		}
		keep = append(keep, b)
	}
	fmt.Println(len(keep))
}

func self(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

// TestTheChildGetsTheGivenFilesAndNoOthers: Files[i] is the child's fd i,
// nil is /dev/null, and no other fd of the parent reaches the child, not
// even one without close-on-exec (POSIX_SPAWN_CLOEXEC_DEFAULT).
func TestTheChildGetsTheGivenFilesAndNoOthers(t *testing.T) {
	// An fd that os/exec would leak: opened without close-on-exec.
	leak, err := unix.Open("/dev/null", unix.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(leak)
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	p, err := Start(Attr{
		Path:  self(t),
		Args:  []string{"child"},
		Env:   []string{childEnv + "=fds"},
		Files: []*os.File{nil, nil, outW, inR},
	})
	outW.Close()
	inR.Close()
	if err != nil {
		t.Fatal(err)
	}
	inW.Write([]byte("through fd 3\n"))
	inW.Close()
	out, _ := io.ReadAll(outR)
	st, err := p.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if !st.Success() {
		t.Fatalf("the child: %v\n%s", st, out)
	}
	if want := "open 0,1,2,3\nthrough fd 3\n"; string(out) != want {
		t.Errorf("the child said %q, not %q (the leak was fd %d)", out, want, leak)
	}
}

// TestAChildOverItsMemoryLimitIsKilled: the kernel kills a child whose
// footprint passes MemoryLimitMiB with SIGKILL, and wait4's ru_maxrss is
// then at the limit or above, as the spawner's check needs (server.md
// §10). A child under its limit runs to the end.
func TestAChildOverItsMemoryLimitIsKilled(t *testing.T) {
	const limit = 64
	run := func(mib int) (*os.ProcessState, []byte) {
		t.Helper()
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		p, err := Start(Attr{
			Path:           self(t),
			Args:           []string{"child"},
			Env:            []string{childEnv + "=alloc", "MIB=" + strconv.Itoa(mib)},
			Files:          []*os.File{nil, w, w},
			MemoryLimitMiB: limit,
		})
		w.Close()
		if err != nil {
			t.Fatal(err)
		}
		out, _ := io.ReadAll(r)
		st, err := p.Wait()
		if err != nil {
			t.Fatal(err)
		}
		return st, out
	}

	st, out := run(4 * limit)
	ws := st.Sys().(syscall.WaitStatus)
	if !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("over its limit, the child ended with %v:\n%s", st, out)
	}
	maxrss := st.SysUsage().(*syscall.Rusage).Maxrss // bytes on darwin
	if maxrss < limit<<20 {
		t.Errorf("ru_maxrss is %d MiB, under the %d MiB limit", maxrss>>20, limit)
	}
	t.Logf("killed at ru_maxrss %d MiB", maxrss>>20)

	st, out = run(limit / 4)
	if !st.Success() || !bytes.Equal(out, []byte("16\n")) {
		t.Errorf("under its limit, the child ended with %v: %q", st, out)
	}
}
