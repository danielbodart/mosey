package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/danielbodart/mosey/internal/bootstrap"
)

// A refusal the user can meet says what it means (bootstrap.md §6.4).
func TestARefusalIsExplained(t *testing.T) {
	for line, want := range map[string]string{
		"MOSEY-ERROR 3 !code=version\n":  "far's mosey speaks protocol 3; this mosey speaks 1",
		"MOSEY-ERROR 1 !code=session\n":  "no such session on far",
		"MOSEY-ERROR 1 !code=internal\n": "the server failed to start (see above)",
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
		"printf 'MOSEY-LIST 1 name=quiet-heron since=1794651234 state=detached\\n'\n" +
		"printf 'MOSEY-LIST 1 name=evil\\033[2J since=1 state=attached\\n'\n" +
		"printf 'MOSEY-LIST 1 name=old-work since=1794650000 state=new\\n'\n"
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
	for _, want := range []string{"NAME", "STATE", "SINCE", "quiet-heron", "detached", since, "old-work"} {
		if !strings.Contains(got, want) {
			t.Errorf("the table lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "\x1b") || strings.Contains(got, "evil") || strings.Contains(got, "welcome") || strings.Contains(got, "VERSION") ||
		strings.Contains(got, "COMMAND") {
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

// A session's command is listed in a last column, there only when some
// session has one, with what is not printable shown as ? and a long one
// cut (bootstrap.md §9.4, D9).
func TestTheListShowsEachSessionsCommandAndNothingUnprintableOfIt(t *testing.T) {
	dir := t.TempDir()
	ssh := fakeSSH(t, dir, "hostname far\n", 0)
	server := filepath.Join(dir, "mosey")
	cmd := func(text string) string { return base64.RawURLEncoding.EncodeToString([]byte(text)) }
	script := "#!/bin/sh\n[ \"$1\" = --serve=list ] || exit 9\n" +
		"printf 'MOSEY-LIST 1 name=shell since=1794651234 state=detached\\n'\n" +
		"printf 'MOSEY-LIST 1 cmd=" + cmd("claude --resume") + " name=ai since=1794651234 state=attached\\n'\n" +
		"printf 'MOSEY-LIST 1 cmd=" + cmd("ls\tgnp.exe\u202eyes") + " name=tricky since=1794651234 state=detached\\n'\n" +
		"printf 'MOSEY-LIST 1 cmd=" + cmd(strings.Repeat("x", 100)) + " name=long since=1794651234 state=detached\\n'\n" +
		"printf 'MOSEY-LIST 1 cmd=" + cmd("a\x1b[2J") + " name=evil since=1794651234 state=detached\\n'\n"
	if err := os.WriteFile(server, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	if err := List(context.Background(), ListOptions{
		SSH:    bootstrap.SSH{Program: ssh, Destination: "far", Server: server},
		Stdout: &out, Stderr: &errs,
	}); err != nil {
		t.Fatalf("%v; stderr %q", err, errs.String())
	}
	got := out.String()
	since := time.Unix(1794651234, 0).Local().Format(takenOverTime)
	for _, want := range []string{
		"NAME", "COMMAND",
		"ai      attached  " + since + "  claude --resume\n",
		"tricky  detached  " + since + "  ls?gnp.exe?yes\n",
		"shell   detached  " + since + "\n",
		"long    detached  " + since + "  " + strings.Repeat("x", 60) + "…\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the table lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "\x1b") || strings.Contains(got, "\u202e") || strings.Contains(got, "\t") || strings.Contains(got, "evil") {
		t.Errorf("the table shows what it should not:\n%q", got)
	}
	if !strings.Contains(errs.String(), "1 list lines") {
		t.Errorf("stderr %q", errs.String())
	}
}

// What runs in each session and where are columns before the command,
// there only when some session says, filtered as the command is, a long
// directory cut at its start so its end shows (bootstrap.md §9.4, D9).
func TestTheListShowsWhatRunsInEachSessionAndWhere(t *testing.T) {
	dir := t.TempDir()
	ssh := fakeSSH(t, dir, "hostname far\n", 0)
	server := filepath.Join(dir, "mosey")
	b := func(text string) string { return base64.RawURLEncoding.EncodeToString([]byte(text)) }
	script := "#!/bin/sh\n[ \"$1\" = --serve=list ] || exit 9\n" +
		"printf 'MOSEY-LIST 1 cwd=" + b("~/Projects/mosey") + " fg=" + b("claude") + " name=ai since=1794651234 state=attached\\n'\n" +
		"printf 'MOSEY-LIST 1 cwd=" + b("~") + " fg=" + b("bash") + " name=shell since=1794651234 state=detached\\n'\n" +
		"printf 'MOSEY-LIST 1 cwd=" + b("/srv/"+strings.Repeat("d", 40)+"/end") + " fg=" + b("v\u202eim") + " name=deep since=1794651234 state=detached\\n'\n" +
		"printf 'MOSEY-LIST 1 name=old since=1794651234 state=detached\\n'\n"
	if err := os.WriteFile(server, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	if err := List(context.Background(), ListOptions{
		SSH:    bootstrap.SSH{Program: ssh, Destination: "far", Server: server},
		Stdout: &out, Stderr: &errs,
	}); err != nil {
		t.Fatalf("%v; stderr %q", err, errs.String())
	}
	got := out.String()
	since := time.Unix(1794651234, 0).Local().Format(takenOverTime)
	for _, want := range []string{
		"NAME   STATE     SINCE" + strings.Repeat(" ", len(since)-5+2) + "RUNNING  DIR\n",
		"ai     attached  " + since + "  claude   ~/Projects/mosey\n",
		"shell  detached  " + since + "  bash     ~\n",
		"deep   detached  " + since + "  v?im     …" + strings.Repeat("d", 28) + "/end\n",
		"old    detached  " + since + "\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the table lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "COMMAND") || strings.Contains(got, "PEER") || strings.Contains(got, "\u202e") {
		t.Errorf("the table shows what it should not:\n%q", got)
	}
}

// Attached sessions with a known peer gain a PEER column showing the IP
// address, after the client's claimed name when it sent one; detached rows
// leave PEER empty so stale addresses are not shown as active
// (bootstrap.md §9.4).
func TestTheListShowsThePeerOfAttachedSessionsOnly(t *testing.T) {
	dir := t.TempDir()
	ssh := fakeSSH(t, dir, "hostname far\n", 0)
	server := filepath.Join(dir, "mosey")
	b := func(text string) string { return base64.RawURLEncoding.EncodeToString([]byte(text)) }
	script := "#!/bin/sh\n[ \"$1\" = --serve=list ] || exit 9\n" +
		"printf 'MOSEY-LIST 1 cwd=" + b("~/Projects/mosey") + " fg=" + b("claude") + " name=remote peer=100.64.1.2:41234 since=1794651234 state=attached\\n'\n" +
		"printf 'MOSEY-LIST 1 cwd=" + b("~") + " fg=" + b("bash") + " name=local peer=127.0.0.1:50000 since=1794651234 state=attached\\n'\n" +
		"printf 'MOSEY-LIST 1 cwd=" + b("~") + " fg=" + b("vim") + " name=named peer=127.0.0.1:50001 peer-host=desktop since=1794651234 state=attached\\n'\n" +
		"printf 'MOSEY-LIST 1 cwd=" + b("~") + " fg=" + b("bash") + " name=gone peer=192.0.2.7:50000 since=1794651234 state=detached\\n'\n"
	if err := os.WriteFile(server, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	if err := List(context.Background(), ListOptions{
		SSH:    bootstrap.SSH{Program: ssh, Destination: "far", Server: server},
		Stdout: &out, Stderr: &errs,
	}); err != nil {
		t.Fatalf("%v; stderr %q", err, errs.String())
	}
	got := out.String()
	since := time.Unix(1794651234, 0).Local().Format(takenOverTime)
	for _, want := range []string{
		"NAME    STATE     SINCE" + strings.Repeat(" ", len(since)-5+2) + "PEER                 RUNNING  DIR\n",
		"remote  attached  " + since + "  100.64.1.2           claude   ~/Projects/mosey\n",
		"local   attached  " + since + "  127.0.0.1            bash     ~\n",
		"named   attached  " + since + "  desktop (127.0.0.1)  vim      ~\n",
		"gone    detached  " + since + "                       bash     ~\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the table lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "192.0.2.7") || strings.Contains(got, ":41234") {
		t.Errorf("the table shows what it should not:\n%q", got)
	}
}

func FuzzListCommand(f *testing.F) {
	f.Add("claude --resume")
	f.Add("ls\tgnp.exe\u202eyes\u00a0\u200b\x1b[2J\xff")
	f.Add(strings.Repeat("é", 100))
	f.Fuzz(func(t *testing.T, s string) {
		shown := shownCommand(s)
		n := 0
		for _, r := range shown {
			n++
			if !unicode.IsPrint(r) || r == utf8.RuneError {
				t.Fatalf("%q shown as %q, with %U", s, shown, r)
			}
		}
		if n > maxShownCommand+1 || n == maxShownCommand+1 && !strings.HasSuffix(shown, "…") {
			t.Fatalf("%q shown as %d runes: %q", s, n, shown)
		}
		if bootstrap.ValidCommand(s) && utf8.RuneCountInString(s) <= maxShownCommand && utf8.RuneCountInString(shown) != utf8.RuneCountInString(s) {
			t.Fatalf("%q shown as %q, not rune for rune", s, shown)
		}
	})
}

// -kill runs --serve=kill NAME, and says whether there was such a
// session (bootstrap.md §9.5).
func TestKillRunsServeKillWithTheName(t *testing.T) {
	dir := t.TempDir()
	ssh := fakeSSH(t, dir, "hostname far\n", 0)
	server := filepath.Join(dir, "mosey")
	script := "#!/bin/sh\n[ \"$1\" = --serve=kill ] || exit 9\n[ \"$2\" = work ] && exit 0\necho 'MOSEY-ERROR 1 !code=session'\nexit 1\n"
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

// An attach refusal names both attach protocols in the client's own
// line, from the ErrorLine's detail, so it says so even where the
// launcher's stderr is not shown, as in R3's reconnect (bootstrap.md
// §6.4).
func TestAnAttachRefusalNamesBothProtocolsInTheClientsOwnLine(t *testing.T) {
	refusal := &bootstrap.RemoteError{ErrorLine: bootstrap.ErrorLine{Proto: 2, Code: bootstrap.CodeAttach, Detail: "1-2"}}
	b := &spawn{ssh: bootstrap.SSH{Destination: "far"}, line: bootstrap.ClientLine{Name: "work"}}
	var f *Failure
	if err := b.refused(refusal); !errors.As(err, &f) || f.Msg != "session work on far speaks attach protocol 1; far's mosey speaks 2" {
		t.Errorf("attach: %v", err)
	}

	dir := t.TempDir()
	ssh := fakeSSH(t, dir, "hostname far\n", 0)
	server := filepath.Join(dir, "mosey")
	if err := os.WriteFile(server, []byte("#!/bin/sh\necho 'MOSEY-ERROR 1 !code=attach detail=1-2'\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	o := KillOptions{SSH: bootstrap.SSH{Program: ssh, Destination: "far", Server: server}, Name: "elder", Stdout: &out, Stderr: &errs}
	if err := Kill(context.Background(), o); !errors.As(err, &f) || f.Msg != "session elder on far speaks attach protocol 1; far's mosey speaks 2" {
		t.Errorf("kill: %v", err)
	}
}

// listHost is a far host for -list and -kill with no -remote: ssh runs the
// probe under /bin/sh with HOME the test's, and PATH holds no mosey.
func listHost(t *testing.T) (ssh, home, ran string) {
	t.Helper()
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	dir, home := t.TempDir(), t.TempDir()
	ssh = filepath.Join(dir, "ssh")
	ran = filepath.Join(dir, "ran")
	// The probe reads ~/.local/bin's modes with ls (§4.7.2).
	script := `#!/bin/sh
if [ "$1" = -G ]; then printf 'hostname far.example\nuser me\nport 22\n'; exit 0; fi
echo ran >> '` + ran + `'
for last in "$@"; do :; done
HOME='` + home + `' PATH='` + toolsOnly(t, "uname", "ls") + `' exec /bin/sh -c "$last"
`
	if err := os.WriteFile(ssh, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return ssh, home, ran
}

// -list with no -remote finds the copy D7 installed in ~/.local/bin,
// which is the only mosey on most hosts (bootstrap.md §9.4).
func TestTheListFindsTheInstalledCopy(t *testing.T) {
	ssh, home, _ := listHost(t)
	installed := filepath.Join(home, ".local", "bin", "mosey")
	if err := os.MkdirAll(filepath.Dir(installed), 0o700); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\ncase \"$1\" in\n--serve=protocol) echo '" + probeProtocol + "';;\n--serve=list) echo 'MOSEY-LIST 1 name=abcd since=1 state=detached';;\n*) exit 9;;\nesac\n"
	if err := os.WriteFile(installed, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	err := List(context.Background(), ListOptions{
		SSH:    bootstrap.SSH{Program: ssh, Destination: "far"},
		Stdout: &out, Stderr: &errs,
	})
	if err != nil || !strings.Contains(out.String(), "abcd") || !strings.Contains(out.String(), "detached") {
		t.Errorf("%v: listed %q; stderr %q", err, out.String(), errs.String())
	}
}

// A host with no mosey is told so by -list, and nothing is copied: the
// probe's line is not shown as a list (§9.4).
func TestTheListCopiesNothingToAHostWithoutMosey(t *testing.T) {
	ssh, home, ran := listHost(t)
	var out, errs bytes.Buffer
	err := List(context.Background(), ListOptions{
		SSH:    bootstrap.SSH{Program: ssh, Destination: "far"},
		Stdout: &out, Stderr: &errs,
	})
	var f *Failure
	if !errors.As(err, &f) || !errors.Is(err, bootstrap.ErrNoServer) || !strings.HasPrefix(f.Msg, "no mosey on far, so no sessions") {
		t.Errorf("%v", err)
	}
	if out.Len() != 0 {
		t.Errorf("listed %q", out.String())
	}
	if n, _ := os.ReadFile(ran); strings.Count(string(n), "ran") != 1 {
		t.Errorf("ssh ran %d times, want 1", strings.Count(string(n), "ran"))
	}
	if _, err := os.Stat(filepath.Join(home, ".local")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("something was written to ~/.local: %v", err)
	}
}
