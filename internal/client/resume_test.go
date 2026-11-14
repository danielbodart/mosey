package client

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danielbodart/mosey/internal/bootstrap"
)

// A resume's refusals say what the user can do about them (bootstrap.md
// §6.4): another version is not answered with an upload, and an
// ambiguous resume says how to choose.
func TestAResumesRefusalIsExplained(t *testing.T) {
	for line, want := range map[string]string{
		"MOSEY-ERROR 1 version 0.9.9\n": "the session runs version 0.9.9; this is 1.2.3: resume it with mosey 0.9.9, or end it from a new session",
		"MOSEY-ERROR 1 session -\n":     "no session to resume on far",
		"MOSEY-ERROR 1 ambiguous 3\n":   "3 sessions on far: name one with -r=SESSION (mosey -list far shows them)",
		"MOSEY-ERROR 1 internal -\n":    "the server failed to start (see above)",
	} {
		r := &run{dir: t.TempDir()}
		ssh := fakeSSH(t, r.dir, "hostname far\n", 0)
		server := fakeServer(t, r.dir, []byte(line), nil, "1")
		l := testLine()
		l.Resume = true
		b := &spawn{
			ssh:    bootstrap.SSH{Program: ssh, Destination: "far", Server: server},
			line:   l,
			stderr: &r.stderr,
			log:    slog.New(slog.DiscardHandler),
			getenv: func(string) string { return "" },
		}
		_, _, err := b.run(context.Background())
		var f *Failure
		if !errors.As(err, &f) || f.Msg != want {
			t.Errorf("%q: %v", line, err)
		}
	}
}

func TestADetachSaysHowToComeBackAndExitsZero(t *testing.T) {
	d := &DetachedError{SessionID: [16]byte{0xab, 15: 1}, Destination: "far"}
	want := "detached from session ab000000000000000000000000000001; resume with: mosey -r=ab000000000000000000000000000001 far"
	if d.Error() != want {
		t.Errorf("%q", d.Error())
	}
	if ExitStatus(d) != StatusOK {
		t.Errorf("exit status %d", ExitStatus(d))
	}
}

// -list runs --serve=list and copies what it prints, through the filter:
// the client parses none of it, and no escape sequence gets through (D9).
func TestTheListIsCopiedThroughTheFilter(t *testing.T) {
	dir := t.TempDir()
	ssh := fakeSSH(t, dir, "hostname far\n", 0)
	server := filepath.Join(dir, "mosey")
	script := "#!/bin/sh\n[ \"$1\" = --serve=list ] || exit 9\nprintf 'SESSION  STATE\\nabcd  detached \\033[2J\\n'\n"
	if err := os.WriteFile(server, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	err := List(context.Background(), ListOptions{
		SSH:    bootstrap.SSH{Program: ssh, Destination: "far", Server: server},
		Stdout: &out, Stderr: &errs,
	})
	if err != nil {
		t.Fatalf("%v; stderr %q", err, errs.String())
	}
	if !strings.Contains(out.String(), "abcd  detached") || strings.Contains(out.String(), "\x1b") {
		t.Errorf("the list came out as %q", out.String())
	}
	if !strings.Contains(errs.String(), "mosey -r=SESSION far") {
		t.Errorf("no hint: %q", errs.String())
	}
	argv, _ := os.ReadFile(filepath.Join(dir, "argv"))
	if !strings.Contains(string(argv), "--serve=list") {
		t.Errorf("ssh ran %q", argv)
	}
}

// listHost is a far host for -list and -r with no -remote: ssh runs the
// probe under /bin/sh with HOME the test's, and PATH holds no mosey.
func listHost(t *testing.T) (ssh, home, ran string) {
	t.Helper()
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	dir, home := t.TempDir(), t.TempDir()
	ssh = filepath.Join(dir, "ssh")
	ran = filepath.Join(dir, "ran")
	script := `#!/bin/sh
if [ "$1" = -G ]; then printf 'hostname far.example\nuser me\nport 22\n'; exit 0; fi
echo ran >> '` + ran + `'
for last in "$@"; do :; done
HOME='` + home + `' PATH=/usr/bin:/bin exec /bin/sh -c "$last"
`
	if err := os.WriteFile(ssh, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return ssh, home, ran
}

// -list with no -remote finds the copy D7 installed in ~/.cache/mosey,
// which is the only mosey on most hosts (bootstrap.md §9.4).
func TestTheListFindsTheCachedCopy(t *testing.T) {
	ssh, home, _ := listHost(t)
	cached := filepath.Join(home, ".cache", "mosey", "0.4.2", "mosey")
	if err := os.MkdirAll(filepath.Dir(cached), 0o700); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\ncase \"$1\" in\n--serve=version) echo 0.4.2;;\n--serve=list) echo 'SESSION  STATE'; echo 'abcd  detached';;\n*) exit 9;;\nesac\n"
	if err := os.WriteFile(cached, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	err := List(context.Background(), ListOptions{
		SSH:     bootstrap.SSH{Program: ssh, Destination: "far"},
		Version: "0.4.2",
		Stdout:  &out, Stderr: &errs,
	})
	if err != nil || !strings.Contains(out.String(), "abcd  detached") {
		t.Errorf("%v: listed %q; stderr %q", err, out.String(), errs.String())
	}
}

// A host with no mosey of this version is told so by -list, and nothing
// is copied: the probe's line is not shown as a list (§9.4).
func TestTheListCopiesNothingToAHostWithoutMosey(t *testing.T) {
	ssh, home, ran := listHost(t)
	var out, errs bytes.Buffer
	err := List(context.Background(), ListOptions{
		SSH:     bootstrap.SSH{Program: ssh, Destination: "far"},
		Version: "0.4.2",
		Stdout:  &out, Stderr: &errs,
	})
	var f *Failure
	if !errors.As(err, &f) || !errors.Is(err, bootstrap.ErrNoServer) || !strings.HasPrefix(f.Msg, "no mosey 0.4.2 on far") {
		t.Errorf("%v", err)
	}
	if out.Len() != 0 {
		t.Errorf("listed %q", out.String())
	}
	if n, _ := os.ReadFile(ran); strings.Count(string(n), "ran") != 1 {
		t.Errorf("ssh ran %d times, want 1", strings.Count(string(n), "ran"))
	}
	if _, err := os.Stat(filepath.Join(home, ".cache")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("something was written to the cache: %v", err)
	}
}

// A resume never copies mosey over, even with -upload=yes (§9.2 step 5):
// a copy of this version could not serve a session of another.
func TestAResumeCopiesNothing(t *testing.T) {
	ssh, home, ran := listHost(t)
	err := Run(context.Background(), Options{
		SSH:      bootstrap.SSH{Program: ssh, Destination: "far"},
		Version:  "0.4.2",
		Resume:   true,
		Terminal: newFakeTerm(80, 24),
		Stderr:   &bytes.Buffer{},
		Upload:   UploadYes,
		Getenv:   func(string) string { return "" },
		Self:     func() ([]byte, error) { return []byte("#!/bin/sh\nexit 9\n"), nil },
	})
	var f *Failure
	if !errors.As(err, &f) || !errors.Is(err, bootstrap.ErrNoServer) || !strings.HasPrefix(f.Msg, "no mosey 0.4.2 on far, so no session of it to resume") {
		t.Errorf("%v", err)
	}
	if n, _ := os.ReadFile(ran); strings.Count(string(n), "ran") != 1 {
		t.Errorf("ssh ran %d times, want 1 (the probe only)", strings.Count(string(n), "ran"))
	}
	if _, err := os.Stat(filepath.Join(home, ".cache")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("something was written to the cache: %v", err)
	}
}
