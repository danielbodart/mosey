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
func TestResumingASessionIgnoresDirAndType(t *testing.T) {
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
}
