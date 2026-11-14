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
