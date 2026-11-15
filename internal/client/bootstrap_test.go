package client

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"

	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielbodart/mosey/internal/bootstrap"
)

// fakeSSH writes an ssh stand-in into dir: for -G it prints config; for
// the bootstrap it records its argv, one argument per line, and runs the
// last argument as the remote command, with /bin/sh as the login shell and
// SSH_CONNECTION as sshd sets it, so the real §4.1 remote command runs
// against whatever server the test puts in dir.
func fakeSSH(t *testing.T, dir, config string, exit int) string {
	t.Helper()
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	script := `#!/bin/sh
if [ "$1" = -G ]; then
  printf '%s' '` + config + `'
  exit ` + strconv.Itoa(exit) + `
fi
for a in "$@"; do printf '%s\n' "$a"; done > '` + dir + `/argv'
for last in "$@"; do :; done
SSH_CONNECTION='127.0.0.1 40000 127.0.0.1 22' exec /bin/sh -c "$last"
`
	path := filepath.Join(dir, "ssh")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// fakeServer writes a `mosey` stand-in that saves its stdin, writes what
// the test says to stdout and stderr, and exits with status.
func fakeServer(t *testing.T, dir string, stdout, stderr []byte, status string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "out"), stdout, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "err"), stderr, 0o644); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\n[ \"$1\" = --serve ] || exit 9\ncat > '" + dir + "/stdin'\ncat '" + dir + "/err' >&2\ncat '" + dir + "/out'\nexit " + status + "\n"
	path := filepath.Join(dir, "mosey")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func testLine() bootstrap.ClientLine {
	return bootstrap.ClientLine{
		SoftwareVersion: "1.2.3",
		Cols:            80,
		Rows:            24,
		Env:             map[string]string{"TERM": "xterm"},
		Public:          bytes.Repeat([]byte{5}, bootstrap.PublicKeySize),
	}
}

func credLine() []byte {
	return bootstrap.MarshalCredentialLine(bootstrap.CredentialLine{
		SoftwareVersion: "1.2.3",
		Port:            60001,
		Name:            "work",
		Public:          bytes.Repeat([]byte{6}, bootstrap.PublicKeySize),
	})
}

type run struct {
	dir    string
	stderr bytes.Buffer
	logged bytes.Buffer
	line   bootstrap.CredentialLine
	err    error
}

func bootstrapWith(t *testing.T, config string, configExit int, server string, stdout, stderr []byte, status string) *run {
	t.Helper()
	r := &run{dir: t.TempDir()}
	ssh := fakeSSH(t, r.dir, config, configExit)
	if server == "" {
		server = fakeServer(t, r.dir, stdout, stderr, status)
	}
	b := &spawn{
		ssh:    bootstrap.SSH{Program: ssh, Destination: "far", Server: server},
		line:   testLine(),
		stderr: &r.stderr,
		log:    slog.New(slog.NewTextHandler(&r.logged, &slog.HandlerOptions{Level: slog.LevelDebug})),
		getenv: func(string) string { return "" },
	}
	r.line, _, r.err = b.run(context.Background())
	return r
}

func TestTheLinesAreExchangedThroughSSH(t *testing.T) {
	noise := []byte("Welcome!\n\x1b]0;owned\x07\n")
	r := bootstrapWith(t, "hostname far\nsessiontype default\n", 0, "", append(noise, credLine()...), []byte("rc says hi\x1b[2J\n"), "0")
	if r.err != nil {
		t.Fatal(r.err)
	}
	if r.line.Port != 60001 || r.line.SoftwareVersion != "1.2.3" {
		t.Errorf("line %+v", r.line)
	}
	stdin, err := os.ReadFile(filepath.Join(r.dir, "stdin"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := bootstrap.ParseClientLine(stdin); err != nil || got.Cols != 80 || got.Env["TERM"] != "xterm" {
		t.Errorf("the server read %q: %v", stdin, err)
	}
	argv, _ := os.ReadFile(filepath.Join(r.dir, "argv"))
	args := strings.Split(strings.TrimSuffix(string(argv), "\n"), "\n")
	if args[0] != "-T" || !slices.Contains(args, "ControlMaster=no") || !slices.Contains(args, "SessionType=default") ||
		args[len(args)-2] != "far" || args[len(args)-3] != "--" {
		t.Errorf("ssh ran as %q", args)
	}
	// ssh's stderr reached the user, filtered; nothing from stdout did.
	if !strings.Contains(r.stderr.String(), `rc says hi\x1b[2J`) || strings.Contains(r.stderr.String(), "\x1b") {
		t.Errorf("stderr %q", r.stderr.String())
	}
}

func TestAMissingServerIsReportedAsSuch(t *testing.T) {
	r := bootstrapWith(t, "hostname far\n", 0, "/nonexistent/mosey", nil, nil, "")
	var f *Failure
	if !errors.Is(r.err, bootstrap.ErrNoServer) || !errors.As(r.err, &f) ||
		f.Msg != "no mosey at /nonexistent/mosey on far: install it there or pass -remote" {
		t.Errorf("%v", r.err)
	}
}

func TestTheServersRefusalIsExplained(t *testing.T) {
	for line, want := range map[string]string{
		"MOSEY-ERROR 1 version 0.9.9\n":      "the remote mosey is version 0.9.9, this is 1.2.3: install 1.2.3 there or pass -remote",
		"MOSEY-ERROR 2 version 0.9.9\n":      "the remote mosey is version 0.9.9 (bootstrap protocol 2; this is 1), this is 1.2.3: install 1.2.3 there or pass -remote",
		"MOSEY-ERROR 1 line -\n":             "the server could not read this client's request: a bug, please report it",
		"MOSEY-ERROR 1 unsupported attach\n": "the remote mosey can't do attach yet",
		"MOSEY-ERROR 1 internal -\n":         "the server failed to start (see above)",
		"MOSEY-ERROR 1 overloaded -\n":       "the server refused: overloaded (see above)",
		"MOSEY-CONNECT 1 nope\n":             "far sent a malformed mosey line",
		"MOSEY-CONNECT 9 later\n":            "far sent a mosey line of protocol 9; this mosey speaks 1: install 1.2.3 there or pass -remote",
	} {
		r := bootstrapWith(t, "hostname far\n", 0, "", []byte(line), nil, "1")
		var f *Failure
		if !errors.As(r.err, &f) || f.Msg != want {
			t.Errorf("%q: %v", line, r.err)
		}
	}
}

func TestNoLineShowsWhatTheFarSideSaid(t *testing.T) {
	r := bootstrapWith(t, "hostname far\n", 0, "", []byte("oops: \x1b[31mbroken\n"), nil, "3")
	var f *Failure
	if !errors.As(r.err, &f) || f.Msg != "the remote mosey exited with status 3" {
		t.Errorf("%v", r.err)
	}
	if !strings.Contains(r.stderr.String(), `oops: \x1b[31mbroken`) {
		t.Errorf("stderr %q", r.stderr.String())
	}
}

func TestSSHFailingIsReportedAsSSHFailing(t *testing.T) {
	r := bootstrapWith(t, "hostname far\n", 0, "", nil, []byte("Permission denied\n"), "255")
	var f *Failure
	if !errors.As(r.err, &f) || f.Msg != "ssh to far failed" || !strings.Contains(r.stderr.String(), "Permission denied") {
		t.Errorf("%v; stderr %q", r.err, r.stderr.String())
	}
}

func TestABadSSHConfigStopsBeforeConnecting(t *testing.T) {
	r := bootstrapWith(t, "hostname far\n", 1, "", credLine(), nil, "0")
	var f *Failure
	if !errors.As(r.err, &f) || f.Msg != "ssh -G far failed" {
		t.Errorf("%v", r.err)
	}
	if _, err := os.Stat(filepath.Join(r.dir, "argv")); err == nil {
		t.Error("the bootstrap ssh ran after ssh -G failed")
	}
}

// After the line, ssh's stderr goes to the log and never to the terminal,
// which is about to belong to the session's screen (bootstrap.md §7.4).
func TestLateSSHOutputGoesOnlyToTheLog(t *testing.T) {
	dir := t.TempDir()
	ssh := fakeSSH(t, dir, "hostname far\n", 0)
	script := "#!/bin/sh\ncat > /dev/null\ncat '" + dir + "/out'\nexec 1>&-\nsleep 0.2\necho 'late \x1b[2J news' >&2\n"
	if err := os.WriteFile(filepath.Join(dir, "out"), credLine(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mosey"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	var stderr, logged syncBuffer
	b := &spawn{
		ssh:    bootstrap.SSH{Program: ssh, Destination: "far", Server: filepath.Join(dir, "mosey")},
		line:   testLine(),
		stderr: &stderr,
		log:    slog.New(slog.NewTextHandler(&logged, nil)),
		getenv: func(string) string { return "" },
	}
	if _, _, err := b.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The late line arrives when it arrives; the test's own timeout bounds
	// the wait (D18: no elapsed time is asserted).
	for !strings.Contains(logged.String(), "late") {
		time.Sleep(10 * time.Millisecond)
	}
	if strings.Contains(stderr.String(), "late") {
		t.Errorf("late output reached the terminal: %q", stderr.String())
	}
	if !strings.Contains(logged.String(), `late \\x1b[2J news`) {
		t.Errorf("late output not logged, filtered: %q", logged.String())
	}
}

// syncBuffer is a bytes.Buffer safe to write from one goroutine while
// another reads it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
