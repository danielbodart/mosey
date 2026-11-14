package server

import (
	"bytes"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/danielbodart/mosey/internal/bootstrap"
	"github.com/danielbodart/mosey/internal/handshake"
	"github.com/danielbodart/mosey/internal/ipc"
)

// The attach socket and the resume exchange (server.md §2.6), with a fake
// spawner in this process: the parts a forked spawner would hide.

func oneShotKey(t *testing.T) []byte {
	t.Helper()
	k, err := handshake.NewOneShotKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Wipe)
	return k.PublicKey()
}

func resumeLine(t *testing.T, version string, sid [16]byte) []byte {
	t.Helper()
	return bootstrap.MarshalClientLine(bootstrap.ClientLine{
		SoftwareVersion: version, Resume: true, SessionID: sid,
		Cols: 80, Rows: 24, Public: oneShotKey(t),
	})
}

func TestAPrivateDirectoryIsTheUsersAloneAndNoLink(t *testing.T) {
	base := runtimeDir(t)
	good := filepath.Join(base, "good")
	if err := makePrivateDir(good); err != nil {
		t.Fatalf("a fresh 0700 directory: %v", err)
	}
	open := filepath.Join(base, "open")
	os.Mkdir(open, 0o700)
	os.Chmod(open, 0o750)
	link := filepath.Join(base, "link")
	os.Symlink(good, link)
	file := filepath.Join(base, "file")
	os.WriteFile(file, nil, 0o600)
	for _, p := range []string{open, link, file} {
		if err := checkPrivateDir(p); !errors.Is(err, errNotPrivate) {
			t.Errorf("%s: %v", filepath.Base(p), err)
		}
	}
	if os.Getuid() != 0 {
		if err := checkPrivateDir("/"); !errors.Is(err, errNotPrivate) {
			t.Errorf("a directory owned by root: %v", err)
		}
	}
}

func TestTheSessionsDirectoryFollowsXDGRuntimeDirElseTheUidUnderTmp(t *testing.T) {
	env := func(kv ...string) func(string) string {
		return func(k string) string {
			for i := 0; i < len(kv); i += 2 {
				if kv[i] == k {
					return kv[i+1]
				}
			}
			return ""
		}
	}
	if got := sessionsDir(env("XDG_RUNTIME_DIR", "/run/user/7")); got != "/run/user/7/mosey" {
		t.Errorf("with XDG_RUNTIME_DIR: %s", got)
	}
	if got, want := sessionsDir(env()), "/tmp/mosey-"+strconv.Itoa(os.Getuid()); got != want {
		t.Errorf("without: %s, want %s", got, want)
	}
	if got := sessionsDir(env("XDG_RUNTIME_DIR", "relative", "TMPDIR", "/var/tmp")); !strings.HasPrefix(got, "/var/tmp/mosey-") {
		t.Errorf("a relative XDG_RUNTIME_DIR and TMPDIR: %s", got)
	}
}

// fakeSession listens like a spawner and runs serve on each connection.
func fakeSession(t *testing.T, base string, sid [16]byte, serve func(f *os.File)) {
	t.Helper()
	l, err := listenAttach(base, sid)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			f, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer f.Close()
				serve(f)
			}()
		}
	}()
}

func greet(version string, sid [16]byte) func(f *os.File) {
	return func(f *os.File) {
		f.Write(bootstrap.MarshalSessionLine(bootstrap.SessionLine{
			SoftwareVersion: version, SessionID: sid, Started: time.Unix(1794650000, 0),
			State: bootstrap.SessionDetached, Since: time.Unix(1794650100, 0),
			Peer: netip.MustParseAddrPort("192.0.2.7:50000"),
		}))
		// A lister closes here; a launcher would send its line.
		buf := make([]byte, ipc.MaxMessage)
		f.SetReadDeadline(time.Now().Add(time.Second))
		f.Read(buf)
	}
}

func TestTheAttachSocketGreetsAndLeavesNothingBehind(t *testing.T) {
	base := filepath.Join(runtimeDir(t), "mosey")
	sid := [16]byte{0xab, 1}
	l, err := listenAttach(base, sid)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkPrivateDir(sessionDir(base, sid)); err != nil {
		t.Errorf("the session's directory: %v", err)
	}
	go func() {
		f, err := l.Accept()
		if err == nil {
			greet("v1", sid)(f)
			f.Close()
		}
	}()
	f, greeting, err := dialAttach(sessionDir(base, sid))
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	g, err := bootstrap.ParseSessionLine(greeting)
	if err != nil || g.SessionID != sid || g.SoftwareVersion != "v1" {
		t.Fatalf("greeting %q: %+v %v", greeting, g, err)
	}
	l.Close()
	if _, err := os.Stat(sessionDir(base, sid)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the session's directory outlived its socket: %v", err)
	}
	if _, _, err := dialAttach(sessionDir(base, sid)); err == nil {
		t.Error("dialled a session that has gone")
	}
}

// A resume of AnySession finds the user's one session; with none it is
// CodeSession, with several CodeAmbiguous and their count (bootstrap.md
// §9.2 step 2). A named session that does not answer is CodeSession.
func TestAResumeOfAnySessionNeedsExactlyOne(t *testing.T) {
	base := filepath.Join(runtimeDir(t), "mosey")
	code := func(err error) string {
		var le *LaunchError
		if errors.As(err, &le) {
			return le.Code + " " + le.Detail
		}
		return "?"
	}
	if _, _, err := findSession(base, bootstrap.AnySession); code(err) != "session " {
		t.Errorf("no sessions: %v", err)
	}
	one := [16]byte{1}
	fakeSession(t, base, one, greet("v1", one))
	f, greeting, err := findSession(base, bootstrap.AnySession)
	if err != nil {
		t.Fatalf("one session: %v", err)
	}
	f.Close()
	if g, _ := bootstrap.ParseSessionLine(greeting); g.SessionID != one {
		t.Errorf("found %+v", g)
	}
	// Not a session's directory: skipped, not counted.
	os.Mkdir(filepath.Join(base, "not-a-session"), 0o700)
	two := [16]byte{2}
	fakeSession(t, base, two, greet("v1", two))
	if _, _, err := findSession(base, bootstrap.AnySession); code(err) != "ambiguous 2" {
		t.Errorf("two sessions: %v", err)
	}
	if _, _, err := findSession(base, [16]byte{3}); code(err) != "session " {
		t.Errorf("a named session that is not there: %v", err)
	}
	f, _, err = findSession(base, two)
	if err != nil {
		t.Errorf("a named session: %v", err)
	} else {
		f.Close()
	}
}

// The launcher's resume against a fake spawner: the line goes to the
// session's socket, and the credential line it answers with comes out on
// stdout; a session of another version is refused before anything is sent
// (bootstrap.md §9.2 step 5).
func TestTheLauncherResumesThroughTheAttachSocket(t *testing.T) {
	runtime := runtimeDir(t)
	base := filepath.Join(runtime, "mosey")
	sid := [16]byte{9}
	answer := bootstrap.MarshalCredentialLine(bootstrap.CredentialLine{
		SoftwareVersion: "v1", Port: 60001, SessionID: sid, Public: oneShotKey(t),
	})
	got := make(chan []byte, 1)
	fakeSession(t, base, sid, func(f *os.File) {
		f.Write(bootstrap.MarshalSessionLine(bootstrap.SessionLine{SoftwareVersion: "v1", SessionID: sid, State: bootstrap.SessionNew}))
		conn, _ := ipc.NewConn(f, ipc.Spawner, ipc.Launcher)
		m, err := conn.Recv()
		if err != nil {
			return
		}
		got <- m.(ipc.ClientLine).Line
		conn.Send(ipc.Ready{Line: answer})
	})
	run := func(line []byte) (string, string, error) {
		var stdout, stderr bytes.Buffer
		l := &Launcher{Stdin: bytes.NewReader(line), Stdout: &stdout, Stderr: &stderr, Version: "v2",
			Env: []string{"XDG_RUNTIME_DIR=" + runtime}}
		err := l.Run(t.Context())
		return stdout.String(), stderr.String(), err
	}
	line := resumeLine(t, "v1", bootstrap.AnySession)
	out, errs, err := run(line)
	if err != nil || out != string(answer) {
		t.Fatalf("resume: %v, stdout %q, stderr %q", err, out, errs)
	}
	if sent := <-got; !bytes.Equal(sent, line) {
		t.Errorf("the spawner got %q", sent)
	}
	// The launcher is v2, the session v1: the session's version decides.
	out, _, err = run(resumeLine(t, "v2", sid))
	if e, perr := bootstrap.ParseErrorLine([]byte(out)); err == nil || perr != nil || e.Code != bootstrap.CodeVersion || e.Detail != "v1" {
		t.Errorf("a client of another version than the session's: %v, %q", err, out)
	}
	select {
	case l := <-got:
		t.Errorf("a refused resume still reached the spawner: %q", l)
	default:
	}
}

// What the spawner checks of a resuming client's line before proto hears
// of it (server.md §2.6).
func TestTheSpawnerRefusesAResumeLineThatIsNotForIt(t *testing.T) {
	sid := [16]byte{5}
	good := resumeLine(t, "v1", sid)
	if _, err := checkResumeLine(good, "v1", sid); err != nil {
		t.Fatalf("a good line: %v", err)
	}
	if _, err := checkResumeLine(resumeLine(t, "v1", bootstrap.AnySession), "v1", sid); err != nil {
		t.Errorf("AnySession: %v", err)
	}
	badKey := bootstrap.MarshalClientLine(bootstrap.ClientLine{SoftwareVersion: "v1", Resume: true, SessionID: sid,
		Cols: 80, Rows: 24, Public: bytes.Repeat([]byte{0xff}, bootstrap.PublicKeySize)})
	newLine := bootstrap.MarshalClientLine(bootstrap.ClientLine{SoftwareVersion: "v1", Cols: 80, Rows: 24, Public: oneShotKey(t)})
	agent := bootstrap.MarshalClientLine(bootstrap.ClientLine{SoftwareVersion: "v1", Resume: true, SessionID: sid, Agent: true,
		Cols: 80, Rows: 24, Public: oneShotKey(t)})
	for name, line := range map[string][]byte{
		"another session": resumeLine(t, "v1", [16]byte{6}),
		"another version": resumeLine(t, "v2", sid),
		"a new session":   newLine,
		"agent":           agent,
		"a bad key":       badKey,
		"malformed":       append(bytes.Clone(good[:len(good)-1]), ' ', '\n'),
	} {
		if _, err := checkResumeLine(line, "v1", sid); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestTheListShowsEachSessionAndItsState(t *testing.T) {
	runtime := runtimeDir(t)
	base := filepath.Join(runtime, "mosey")
	getenv := func(k string) string {
		if k == "XDG_RUNTIME_DIR" {
			return runtime
		}
		return ""
	}
	var out bytes.Buffer
	if err := List(&out, getenv); err != nil || out.String() != "no sessions\n" {
		t.Fatalf("%v %q", err, out.String())
	}
	sid := [16]byte{0xab, 0xcd}
	fakeSession(t, base, sid, greet("v1", sid))
	other := [16]byte{0xef}
	fakeSession(t, base, other, func(f *os.File) { f.Write([]byte("MOSEY-SESSION v9 a later version's fields\n")) })
	out.Reset()
	if err := List(&out, getenv); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"abcd0000000000000000000000000000", "detached", "2026-11-14T", "192.0.2.7:50000", "v1", "v9"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the list lacks %q:\n%s", want, out.String())
		}
	}
}
