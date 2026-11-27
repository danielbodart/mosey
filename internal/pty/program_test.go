package pty

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
)

// fakeProgram is a /proc with one process, pid, whose cmdline, comm and
// cwd are as given; an empty one is left out.
func fakeProgram(t *testing.T, pid int, cmdline, comm, cwd string) string {
	t.Helper()
	proc := t.TempDir()
	dir := filepath.Join(proc, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"cmdline": cmdline, "comm": comm} {
		if body != "" {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	if cwd != "" {
		if err := os.Symlink(cwd, filepath.Join(dir, "cwd")); err != nil {
			t.Fatal(err)
		}
	}
	return proc
}

// A program is named as it names itself, argv[0]'s base name, so a Nix
// wrapper's claude is claude and a login shell is bash, not -bash; with
// no cmdline (a zombie's is empty) the kernel's comm stands in.
func TestAProgramIsNamedByItsArgv0(t *testing.T) {
	for _, c := range []struct{ cmdline, comm, want string }{
		{"claude\x00--settings\x00x.json\x00", ".claude-unwrapp\n", "claude"},
		{"/run/current-system/sw/bin/vim\x00a.go\x00", "vim\n", "vim"},
		{"-bash\x00", "bash\n", "bash"},
		{"", "zsh\n", "zsh"},
		{"\x00", "sh\n", "sh"},
		{"-\x00", "bash\n", "-"},
	} {
		proc := fakeProgram(t, 42, c.cmdline, c.comm, "/home/u/src")
		if p := ProgramIn(proc, 42); p.Name != c.want || p.Dir != "/home/u/src" {
			t.Errorf("cmdline %q comm %q: %+v, want %q", c.cmdline, c.comm, p, c.want)
		}
	}
}

// A process that is gone is an empty Program, never an error.
func TestAProcessThatIsGoneIsAnEmptyProgram(t *testing.T) {
	if p := ProgramIn(t.TempDir(), 42); p != (Program{}) {
		t.Errorf("%+v", p)
	}
}

// Against the real /proc, this test's own process is found by its name
// and directory.
func TestThisProcessIsDescribedFromProc(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("/proc is Linux's")
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	p := ProgramOf(os.Getpid())
	if p.Name != filepath.Base(os.Args[0]) || p.Dir != wd {
		t.Errorf("%+v, want %s in %s", p, filepath.Base(os.Args[0]), wd)
	}
}
