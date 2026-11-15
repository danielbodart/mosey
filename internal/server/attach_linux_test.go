package server

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

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
		SoftwareVersion: version, Attach: bootstrap.AttachResume, SessionID: sid,
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
			SoftwareVersion: version, AttachMin: 1, AttachMax: 1,
			SessionID: sid, Name: fmt.Sprintf("s-%x", sid[0]), Started: time.Unix(1794650000, 0),
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

// The launcher's resume against a fake spawner: a plain client's line
// (auto) finds the detached session, which gets the line as resume:SID,
// and the credential line it answers with comes out on stdout; a session
// of another version is attached all the same (D8 V1), and one whose
// attach protocol range does not meet this build's is passed over
// (bootstrap.md §9.2 steps 2 and 5).
func TestTheLauncherResumesThroughTheAttachSocket(t *testing.T) {
	runtime := runtimeDir(t)
	base := filepath.Join(runtime, "mosey")
	sid := [16]byte{9}
	answer := bootstrap.MarshalCredentialLine(bootstrap.CredentialLine{
		SoftwareVersion: "v1", Port: 60001, SessionID: sid, Name: "work", Public: oneShotKey(t),
	})
	got := make(chan []byte, 1)
	var sessionVersion atomic.Value
	sessionVersion.Store("v1")
	var dropsV1 atomic.Bool
	fakeSession(t, base, sid, func(f *os.File) {
		lo, hi := 1, 1
		if dropsV1.Load() {
			lo, hi = 2, 3
		}
		f.Write(bootstrap.MarshalSessionLine(bootstrap.SessionLine{SoftwareVersion: sessionVersion.Load().(string), AttachMin: lo, AttachMax: hi,
			SessionID: sid, Name: "work", Started: time.Unix(1794650000, 0), State: bootstrap.SessionDetached, Since: time.Unix(1794650000, 0)}))
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
		l := &Launcher{Stdin: bytes.NewReader(line), Stdout: &stdout, Stderr: &stderr, Version: "v1",
			Env: []string{"XDG_RUNTIME_DIR=" + runtime}}
		err := l.Run(t.Context())
		return stdout.String(), stderr.String(), err
	}
	key := oneShotKey(t)
	auto := bootstrap.MarshalClientLine(bootstrap.ClientLine{SoftwareVersion: "v1", Attach: bootstrap.AttachAuto, Cols: 80, Rows: 24, Public: key})
	out, errs, err := run(auto)
	if err != nil || out != string(answer) {
		t.Fatalf("resume: %v, stdout %q, stderr %q", err, out, errs)
	}
	want := bootstrap.MarshalClientLine(bootstrap.ClientLine{SoftwareVersion: "v1", Attach: bootstrap.AttachResume, SessionID: sid, Cols: 80, Rows: 24, Public: key})
	if sent := <-got; !bytes.Equal(sent, want) {
		t.Errorf("the spawner got %q, not the line as resume:SID", sent)
	}
	// The session is v0, the client and the launcher v1: the session is
	// attached as it is, run by its own binary, never refused for its
	// version (D8 V1).
	sessionVersion.Store("v0")
	out, errs, err = run(auto)
	if err != nil || out != string(answer) {
		t.Fatalf("a session of another version: %v, stdout %q, stderr %q", err, out, errs)
	}
	<-got
	// A session whose attach range this build does not speak is passed
	// over: a plain client starts its own (here there is no spawner to
	// start, Self being empty).
	dropsV1.Store(true)
	out, _, err = run(auto)
	if e, perr := bootstrap.ParseErrorLine([]byte(out)); err == nil || perr != nil || e.Code != bootstrap.CodeInternal ||
		!strings.Contains(err.Error(), "starting the spawner") {
		t.Errorf("a plain client with only a 2-3 session detached: %v, %q; want it to start a session", err, out)
	}
	// R3's reconnect of a session that is not there.
	gone := bootstrap.MarshalClientLine(bootstrap.ClientLine{SoftwareVersion: "v1", Attach: bootstrap.AttachResume,
		SessionID: [16]byte{0x77}, Holder: [8]byte{1}, HasHolder: true, Cols: 80, Rows: 24, Public: key})
	out, _, err = run(gone)
	if e, perr := bootstrap.ParseErrorLine([]byte(out)); err == nil || perr != nil || e.Code != bootstrap.CodeSession {
		t.Errorf("a reconnect of a session that has gone: %v, %q", err, out)
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
	if _, err := checkResumeLine(good, sid); err != nil {
		t.Fatalf("a good line: %v", err)
	}
	// A resuming client may forward its agent: its own login triggered
	// its own bind (bootstrap.md §9.2 step 2).
	agent := bootstrap.MarshalClientLine(bootstrap.ClientLine{SoftwareVersion: "v1", Attach: bootstrap.AttachResume, SessionID: sid, Agent: true,
		Cols: 80, Rows: 24, Public: oneShotKey(t)})
	if _, err := checkResumeLine(agent, sid); err != nil {
		t.Errorf("agent=yes: %v", err)
	}
	// A reconnect's holder passes through as the hold's label (§9.2.2).
	holder := bootstrap.MarshalClientLine(bootstrap.ClientLine{SoftwareVersion: "v1", Attach: bootstrap.AttachResume, SessionID: sid,
		Holder: [8]byte{1}, HasHolder: true, Cols: 80, Rows: 24, Public: oneShotKey(t)})
	if cl, err := checkResumeLine(holder, sid); err != nil || !cl.HasHolder || cl.Holder != [8]byte{1} {
		t.Errorf("a reconnect's line: %v", err)
	}
	badKey := bootstrap.MarshalClientLine(bootstrap.ClientLine{SoftwareVersion: "v1", Attach: bootstrap.AttachResume, SessionID: sid,
		Cols: 80, Rows: 24, Public: bytes.Repeat([]byte{0xff}, bootstrap.PublicKeySize)})
	newLine := bootstrap.MarshalClientLine(bootstrap.ClientLine{SoftwareVersion: "v1", Cols: 80, Rows: 24, Public: oneShotKey(t)})
	auto := bootstrap.MarshalClientLine(bootstrap.ClientLine{SoftwareVersion: "v1", Attach: bootstrap.AttachAuto, Cols: 80, Rows: 24, Public: oneShotKey(t)})
	for name, line := range map[string][]byte{
		"another session":      resumeLine(t, "v1", [16]byte{6}),
		"a new session":        newLine,
		"an unresolved choice": auto,
		"a bad key":            badKey,
		"malformed":            append(bytes.Clone(good[:len(good)-1]), ' ', '\n'),
	} {
		if _, err := checkResumeLine(line, sid); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A client of another version is served (D8 V1).
	if _, err := checkResumeLine(resumeLine(t, "v2", sid), sid); err != nil {
		t.Errorf("a client of another version: %v", err)
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
	if err := List(&out, getenv); err != nil || out.String() != "" {
		t.Fatalf("%v %q", err, out.String())
	}
	sid := [16]byte{0xab, 0xcd}
	fakeSession(t, base, sid, greet("v1", sid))
	// A session of another version is listed like any other (D8 V1), and
	// one whose greeting does not parse is not listed at all.
	other := [16]byte{0xef}
	fakeSession(t, base, other, func(f *os.File) {
		// Started after s-ab's, so it is listed second (oldest first).
		f.Write(bootstrap.MarshalSessionLine(bootstrap.SessionLine{SoftwareVersion: "v9", AttachMin: 1, AttachMax: 1,
			SessionID: other, Name: "s-ef", Started: time.Unix(1794650050, 0), State: bootstrap.SessionDetached, Since: time.Unix(1794650100, 0)}))
	})
	broken := [16]byte{0x01}
	fakeSession(t, base, broken, func(f *os.File) { f.Write([]byte("MOSEY-SESSION v9 not a greeting\n")) })
	out.Reset()
	if err := List(&out, getenv); err != nil {
		t.Fatal(err)
	}
	want := "MOSEY-LIST 1 s-ab detached 1794650100 v1\nMOSEY-LIST 1 s-ef detached 1794650100 v9\n"
	if out.String() != want {
		t.Errorf("the list is\n%s\nnot\n%s", out.String(), want)
	}
	for _, line := range strings.SplitAfter(out.String(), "\n") {
		if line == "" {
			continue
		}
		if _, err := bootstrap.ParseListLine([]byte(line)); err != nil {
			t.Errorf("%q does not parse: %v", line, err)
		}
	}
}

// -kill asks the named session's spawner to hang up, over its attach
// socket, and with no session of the name says so in an ErrorLine
// (bootstrap.md §9.5).
func TestKillSendsHangupToTheNamedSessionOnly(t *testing.T) {
	runtime := runtimeDir(t)
	base := filepath.Join(runtime, "mosey")
	getenv := func(k string) string {
		if k == "XDG_RUNTIME_DIR" {
			return runtime
		}
		return ""
	}
	asked := make(chan [16]byte, 2)
	for _, sid := range [][16]byte{{0x11}, {0x22}} {
		fakeSession(t, base, sid, func(f *os.File) {
			greet("v1", sid)(f)
		})
	}
	// The greeting above reads whatever comes next and returns; a real
	// spawner hands Hangup on. This one records which session got it.
	killed := [16]byte{0x33}
	fakeSession(t, base, killed, func(f *os.File) {
		f.Write(bootstrap.MarshalSessionLine(bootstrap.SessionLine{SoftwareVersion: "v1", AttachMin: 1, AttachMax: 1, SessionID: killed, Name: "doomed",
			Started: time.Unix(1794650000, 0), State: bootstrap.SessionAttached, Since: time.Unix(1794650000, 0)}))
		conn, _ := ipc.NewConn(f, ipc.Spawner, ipc.Launcher)
		if m, err := conn.Recv(); err == nil {
			if _, ok := m.(ipc.Hangup); ok {
				asked <- killed
			}
		}
	})
	var out bytes.Buffer
	if err := Kill(&out, getenv, "doomed"); err != nil || out.Len() != 0 {
		t.Fatalf("kill: %v, %q", err, out.String())
	}
	select {
	case sid := <-asked:
		if sid != killed {
			t.Errorf("hung up %x", sid)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the session was never asked to hang up")
	}
	out.Reset()
	if err := Kill(&out, getenv, "nothing"); !errors.Is(err, ErrNoSuchSession) {
		t.Fatalf("kill of nothing: %v", err)
	}
	if e, err := bootstrap.ParseErrorLine(out.Bytes()); err != nil || e.Code != bootstrap.CodeSession {
		t.Errorf("kill of nothing printed %q", out.String())
	}
}

// A spawner that has stopped accepting, its backlog full, is skipped
// within GreetingTimeout rather than waited on (bootstrap.md §11): a
// blocking connect would sleep until there was room.
func TestASessionWhoseBacklogIsFullIsSkippedNotWaitedOn(t *testing.T) {
	base := filepath.Join(runtimeDir(t), "mosey")
	sid := [16]byte{0xf0}
	l, err := listenAttach(base, sid)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	addr := &unix.SockaddrUnix{Name: filepath.Join(sessionDir(base, sid), attachName)}
	full := false
	for range 64 {
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		if err := unix.Connect(fd, addr); errors.Is(err, unix.EAGAIN) {
			full = true
			break
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if !full {
		t.Fatal("the backlog never filled")
	}
	done := make(chan error, 1)
	go func() {
		f, _, err := dialAttach(sessionDir(base, sid))
		if f != nil {
			f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("dialled a session that is not accepting")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("dialAttach waited on a session that is not accepting")
	}
}

// A launcher checks R/mosey is private before it reads any session or
// takes its lock, not only SID-HEX (server.md §2.6).
func TestNoSessionInASessionsDirectoryOthersCanUseIsReached(t *testing.T) {
	base := filepath.Join(runtimeDir(t), "mosey")
	sid := [16]byte{0xf1}
	fakeSession(t, base, sid, greet("v1", sid))
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(base, 0o700)
	if live := liveSessions(base); len(live) != 0 {
		for _, s := range live {
			s.f.Close()
		}
		t.Errorf("reached %d sessions under an open sessions directory", len(live))
	}
	if f, err := lockSessions(base, time.Second); err == nil {
		f.Close()
		t.Error("took the lock in an open sessions directory")
	}
}

// The launchers' lock is exclusive and is let go when its holder closes
// it (or exits): a second launcher waits, then gives up at its bound
// (bootstrap.md §9.2 "The lock").
func TestTheSessionsLockIsExclusiveAndLetGo(t *testing.T) {
	base := filepath.Join(runtimeDir(t), "mosey")
	first, err := lockSessions(base, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := lockSessions(base, 100*time.Millisecond); err == nil {
		second.Close()
		t.Fatal("two launchers held the lock at once")
	}
	first.Close()
	again, err := lockSessions(base, time.Second)
	if err != nil {
		t.Fatalf("the lock was not let go: %v", err)
	}
	again.Close()
	if fi, err := os.Lstat(filepath.Join(base, lockName)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("the lock file: %v %v", fi.Mode(), err)
	}
	if live := liveSessions(base); len(live) != 0 {
		t.Errorf("the lock file was taken for a session")
	}
}
