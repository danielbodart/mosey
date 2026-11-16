package server

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/danielbodart/mosey/internal/bootstrap"
	"github.com/danielbodart/mosey/internal/ipc"
)

// A -dir that is not a directory is refused with `dir` before anything
// starts (bootstrap.md §9.2.3): here Self is empty, so a launcher that
// went on to start a spawner would fail with `internal` instead.
func TestAMissingDirIsRefusedBeforeAnythingStarts(t *testing.T) {
	home := t.TempDir()
	os.WriteFile(filepath.Join(home, "file"), nil, 0o600)
	for _, attach := range []bootstrap.ClientLine{
		{Attach: bootstrap.AttachNew},
		{Attach: bootstrap.AttachAuto},
		{Attach: bootstrap.AttachName, Name: "work"},
	} {
		for _, dir := range []string{"missing", "file", "/nonexistent/mosey-dir"} {
			cl := attach
			cl.Dir, cl.Type, cl.Cols, cl.Rows, cl.Public = dir, "echo hi", 80, 24, oneShotKey(t)
			var stdout, stderr bytes.Buffer
			l := &Launcher{Stdin: bytes.NewReader(bootstrap.MarshalClientLine(cl)), Stdout: &stdout, Stderr: &stderr,
				Env: []string{"HOME=" + home, "XDG_RUNTIME_DIR=" + runtimeDir(t)}}
			err := l.Run(t.Context())
			e, perr := bootstrap.ParseErrorLine(stdout.Bytes())
			if err == nil || perr != nil || e.Code != bootstrap.CodeDir || !strings.Contains(stderr.String(), dir) {
				t.Errorf("%v -dir %s: %v, stdout %q, stderr %q", attach.Attach, dir, err, stdout.String(), stderr.String())
			}
		}
	}
}

// Taking an existing session ignores -dir and -type, without an error,
// even a -dir that does not exist: the line its spawner gets has neither
// (bootstrap.md §9.2.3).
func TestResumingASessionIgnoresDirTypeAndCommand(t *testing.T) {
	runtime := runtimeDir(t)
	base := filepath.Join(runtime, "mosey")
	if err := makePrivateDir(base); err != nil {
		t.Fatal(err)
	}
	sid := [16]byte{0x21}
	answer := bootstrap.MarshalCredentialLine(bootstrap.CredentialLine{
		Port: 60001, SessionID: sid, Name: "work", Public: oneShotKey(t),
	})
	got := make(chan []byte, 2)
	fakeSession(t, base, sid, func(f *os.File) {
		f.Write(bootstrap.MarshalSessionLine(bootstrap.SessionLine{AttachProtocol: bootstrap.AttachProtocol, SessionID: sid, Name: "work",
			Started: time.Unix(1794650000, 0), State: bootstrap.SessionDetached, Since: time.Unix(1794650000, 0)}))
		conn, _ := ipc.NewConn(f, ipc.Spawner, ipc.Launcher)
		m, err := conn.Recv()
		if err != nil {
			return
		}
		got <- m.(ipc.ClientLine).Line
		conn.Send(ipc.Ready{Line: answer})
	})
	key := oneShotKey(t)
	for _, attach := range []bootstrap.ClientLine{
		{Attach: bootstrap.AttachAuto},
		{Attach: bootstrap.AttachName, Name: "work"},
	} {
		cl := attach
		cl.Dir, cl.Type, cl.Cols, cl.Rows, cl.Public = "missing", "echo hi", 80, 24, key
		var stdout, stderr bytes.Buffer
		l := &Launcher{Stdin: bytes.NewReader(bootstrap.MarshalClientLine(cl)), Stdout: &stdout, Stderr: &stderr,
			Env: []string{"HOME=" + t.TempDir(), "XDG_RUNTIME_DIR=" + runtime}}
		if err := l.Run(t.Context()); err != nil || stdout.String() != string(answer) {
			t.Fatalf("%v: %v, stdout %q, stderr %q", attach.Attach, err, stdout.String(), stderr.String())
		}
		want := bootstrap.MarshalClientLine(bootstrap.ClientLine{Attach: bootstrap.AttachResume, SessionID: sid, Cols: 80, Rows: 24, Public: key})
		if sent := <-got; !bytes.Equal(sent, want) {
			t.Errorf("%v: the spawner got %q, not resume:SID with no dir or type", attach.Attach, sent)
		}
	}

	// A command is not passed on either, and the client that sent one is
	// told, by existing on the credential line, that it was not run
	// (bootstrap.md §6.3, §9.2.3). Only that client: the lines above,
	// with no command, came back as the session gave them.
	cl := bootstrap.ClientLine{Attach: bootstrap.AttachName, Name: "work", Command: "claude", Dir: "missing", Cols: 80, Rows: 24, Public: key}
	var stdout, stderr bytes.Buffer
	l := &Launcher{Stdin: bytes.NewReader(bootstrap.MarshalClientLine(cl)), Stdout: &stdout, Stderr: &stderr,
		Env: []string{"HOME=" + t.TempDir(), "XDG_RUNTIME_DIR=" + runtime}}
	if err := l.Run(t.Context()); err != nil {
		t.Fatalf("%v, stderr %q", err, stderr.String())
	}
	if c, err := bootstrap.ParseCredentialLine(stdout.Bytes()); err != nil || !c.Existing || c.SessionID != sid || c.Name != "work" {
		t.Errorf("the client got %q: %+v, %v", stdout.String(), c, err)
	}
	want := bootstrap.MarshalClientLine(bootstrap.ClientLine{Attach: bootstrap.AttachResume, SessionID: sid, Cols: 80, Rows: 24, Public: key})
	if sent := <-got; !bytes.Equal(sent, want) {
		t.Errorf("the spawner got %q, not resume:SID with no command", sent)
	}
}

// A plain `mosey HOST claude` returns to the detached session started
// with claude, passing over a detached shell that is newer, and its
// client is not told the command was not run: it is the one running
// (PLAN D8, option C, bootstrap.md §9.2.3).
func TestAPlainCommandReturnsToTheDetachedSessionOfThatCommandAndSaysNothing(t *testing.T) {
	runtime := runtimeDir(t)
	base := filepath.Join(runtime, "mosey")
	if err := makePrivateDir(base); err != nil {
		t.Fatal(err)
	}
	got := make(chan string, 2)
	serve := func(sid [16]byte, name, command string, since int64) {
		answer := bootstrap.MarshalCredentialLine(bootstrap.CredentialLine{
			Port: 60001, SessionID: sid, Name: name, Public: oneShotKey(t),
		})
		fakeSession(t, base, sid, func(f *os.File) {
			f.Write(bootstrap.MarshalSessionLine(bootstrap.SessionLine{AttachProtocol: bootstrap.AttachProtocol, SessionID: sid, Name: name,
				Started: time.Unix(1794650000, 0), State: bootstrap.SessionDetached, Since: time.Unix(since, 0), Command: command}))
			conn, _ := ipc.NewConn(f, ipc.Spawner, ipc.Launcher)
			if _, err := conn.Recv(); err != nil {
				return
			}
			got <- name
			conn.Send(ipc.Ready{Line: answer})
		})
	}
	serve([16]byte{0x31}, "ai", "claude", 1794650100)
	serve([16]byte{0x32}, "shell", "", 1794650200)

	for _, c := range []struct{ command, name string }{{"claude", "ai"}, {"", "shell"}} {
		cl := bootstrap.ClientLine{Attach: bootstrap.AttachAuto, Command: c.command, Cols: 80, Rows: 24, Public: oneShotKey(t)}
		var stdout, stderr bytes.Buffer
		l := &Launcher{Stdin: bytes.NewReader(bootstrap.MarshalClientLine(cl)), Stdout: &stdout, Stderr: &stderr,
			Env: []string{"HOME=" + t.TempDir(), "XDG_RUNTIME_DIR=" + runtime}}
		if err := l.Run(t.Context()); err != nil {
			t.Fatalf("%q: %v, stderr %q", c.command, err, stderr.String())
		}
		if taken := <-got; taken != c.name {
			t.Errorf("%q took %s, not %s", c.command, taken, c.name)
		}
		if cred, err := bootstrap.ParseCredentialLine(stdout.Bytes()); err != nil || cred.Existing || cred.Name != c.name {
			t.Errorf("%q: the client got %q: %+v, %v", c.command, stdout.String(), cred, err)
		}
	}
}
