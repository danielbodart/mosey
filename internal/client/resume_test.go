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
	"time"

	"github.com/danielbodart/mosey/internal/bootstrap"
)

// A refusal the user can meet says what it means (bootstrap.md §6.4).
func TestARefusalIsExplained(t *testing.T) {
	for line, want := range map[string]string{
		"MOSEY-ERROR 1 version 0.9.9\n": "the remote mosey 0.9.9 cannot read this client's request (bootstrap protocol 1, it speaks 1)",
		"MOSEY-ERROR 1 session -\n":     "no such session on far",
		"MOSEY-ERROR 1 internal -\n":    "the server failed to start (see above)",
	} {
		r := &run{dir: t.TempDir()}
		ssh := fakeSSH(t, r.dir, "hostname far\n", 0)
		server := fakeServer(t, r.dir, []byte(line), nil, "1")
		l := testLine()
		l.Attach, l.SessionID = bootstrap.AttachResume, [16]byte{1}
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

// A detach names the session and how to come back to it, and exits 0
// (bootstrap.md §9.3); a session R3 found gone says so and exits 1; a
// takeover R3 heard of names the session and when (§9.2.2).
func TestTheWaysASessionEndsSayWhatHappened(t *testing.T) {
	d := &DetachedError{Name: "quiet-heron", Destination: "far"}
	if want := "detached from session quiet-heron; resume it with: mosey -s quiet-heron far"; d.Error() != want {
		t.Errorf("%q", d.Error())
	}
	if ExitStatus(d) != StatusOK {
		t.Errorf("exit status %d", ExitStatus(d))
	}
	g := &GoneError{Name: "quiet-heron", Destination: "far"}
	if want := "session quiet-heron on far has ended: its shell exited, or the host restarted"; g.Error() != want || !errors.Is(g, ErrSessionGone) || ExitStatus(g) != StatusFailed {
		t.Errorf("%q, status %d", g.Error(), ExitStatus(g))
	}
	at := time.Date(2026, 11, 14, 9, 30, 12, 0, time.UTC)
	taken := &TakenOverError{At: at, Name: "quiet-heron"}
	if want := "session quiet-heron taken over by another client at " + at.Local().Format(takenOverTime); taken.Error() != want || ExitStatus(taken) != StatusTakenOver {
		t.Errorf("%q", taken.Error())
	}
}

// -list parses the server's MOSEY-LIST lines and lays out the table
// itself: a line with an escape sequence, or anything else of the far
// side's, is never shown (bootstrap.md §9.4, D9).
func TestTheListIsLaidOutFromLinesThatParse(t *testing.T) {
	dir := t.TempDir()
	ssh := fakeSSH(t, dir, "hostname far\n", 0)
	server := filepath.Join(dir, "mosey")
	script := "#!/bin/sh\n[ \"$1\" = --serve=list ] || exit 9\n" +
		"printf 'welcome \\033[2J\\n'\n" +
		"printf 'MOSEY-LIST 1 quiet-heron detached 1794651234 0.4.2\\n'\n" +
		"printf 'MOSEY-LIST 1 evil\\033[2J attached 1 0.4.2\\n'\n" +
		"printf 'MOSEY-LIST 1 - - - 0.3.9\\n'\n"
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
	got := out.String()
	since := time.Unix(1794651234, 0).Local().Format(takenOverTime)
	for _, want := range []string{"NAME", "STATE", "SINCE", "VERSION", "quiet-heron", "detached", since, "0.4.2", "0.3.9"} {
		if !strings.Contains(got, want) {
			t.Errorf("the table lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "\x1b") || strings.Contains(got, "evil") || strings.Contains(got, "welcome") {
		t.Errorf("the table shows what it should not:\n%q", got)
	}
	if !strings.Contains(errs.String(), "mosey -s NAME far") || !strings.Contains(errs.String(), "1 list lines") {
		t.Errorf("stderr %q", errs.String())
	}
	argv, _ := os.ReadFile(filepath.Join(dir, "argv"))
	if !strings.Contains(string(argv), "--serve=list") {
		t.Errorf("ssh ran %q", argv)
	}
}

// -kill runs --serve=kill NAME, and says whether there was such a
// session (bootstrap.md §9.5).
func TestKillRunsServeKillWithTheName(t *testing.T) {
	dir := t.TempDir()
	ssh := fakeSSH(t, dir, "hostname far\n", 0)
	server := filepath.Join(dir, "mosey")
	script := "#!/bin/sh\n[ \"$1\" = --serve=kill ] || exit 9\n[ \"$2\" = work ] && exit 0\necho 'MOSEY-ERROR 1 session -'\nexit 1\n"
	if err := os.WriteFile(server, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	o := KillOptions{SSH: bootstrap.SSH{Program: ssh, Destination: "far", Server: server}, Name: "work", Stdout: &out, Stderr: &errs}
	if err := Kill(context.Background(), o); err != nil || out.String() != "mosey: ended session work on far\n" {
		t.Fatalf("%v: %q; stderr %q", err, out.String(), errs.String())
	}
	o.Name = "play"
	var f *Failure
	if err := Kill(context.Background(), o); !errors.As(err, &f) || f.Msg != "no session called play on far" {
		t.Errorf("a kill of nothing: %v", err)
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
	script := "#!/bin/sh\ncase \"$1\" in\n--serve=version) echo 0.4.2;;\n--serve=list) echo 'MOSEY-LIST 1 abcd detached 1 0.4.2';;\n*) exit 9;;\nesac\n"
	if err := os.WriteFile(cached, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	err := List(context.Background(), ListOptions{
		SSH:     bootstrap.SSH{Program: ssh, Destination: "far"},
		Version: "0.4.2",
		Stdout:  &out, Stderr: &errs,
	})
	if err != nil || !strings.Contains(out.String(), "abcd") || !strings.Contains(out.String(), "detached") {
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
