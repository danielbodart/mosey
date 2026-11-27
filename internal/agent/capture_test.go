package agent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// script is ssh and the far host as the capture sees them: what they send,
// in order, then EOF.
type script struct {
	in  *bytes.Reader
	out bytes.Buffer
}

func (s *script) Read(p []byte) (int, error)  { return s.in.Read(p) }
func (s *script) Write(p []byte) (int, error) { return s.out.Write(p) }

func run(in ...[]byte) (Bind, error, []byte) {
	s := &script{in: bytes.NewReader(bytes.Join(in, nil))}
	b, err := capture(s)
	return b, err, s.out.Bytes()
}

var trigger = frame(msgRequestIdentities)

// The honest sequence, ssh's bind then the launcher's trigger then EOF,
// is captured, and ssh and the trigger get the answers they expect.
func TestTheHonestSequenceIsCaptured(t *testing.T) {
	bind := bindFrame(t, hostKey(t), sid(), 1)
	b, err, out := run(bind, trigger)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b.Frame(), bind) {
		t.Error("the captured bind is not ssh's bytes")
	}
	want := append(frame(msgSuccess), frame(msgIdentitiesAnswer, 0, 0, 0, 0)...)
	if !bytes.Equal(out, want) {
		t.Errorf("answered %x, want %x", out, want)
	}
}

// Anything but exactly bind, trigger, EOF is no bind at all: whatever
// follows ssh's own frame comes from the far host, which can mint a valid
// bind for any host it reaches [S3 E11].
func TestAnythingButTheHonestSequenceIsNoBind(t *testing.T) {
	key := hostKey(t)
	bind := bindFrame(t, key, sid(), 1)
	injected := bindFrame(t, hostKey(t), []byte("another session"), 1)
	for name, in := range map[string][][]byte{
		"nothing":                              nil,
		"a bind without forwarding":            {bindFrame(t, key, sid(), 0), trigger},
		"a bind as frame 2":                    {trigger, bind},
		"a second bind instead of the trigger": {bind, injected, trigger},
		"a bind injected after the trigger":    {bind, trigger, injected},
		"one byte after the answer":            {bind, trigger, {0}},
		"a trigger with a body":                {bind, frame(msgRequestIdentities, 0)},
		"a sign request":                       {bind, frame(13)},
		"no trigger":                           {bind},
		"a frame over the bound":               {bind, frame(make([]byte, MaxCaptureFrame+1)...)},
		"a zero-length frame":                  {{0, 0, 0, 0}},
	} {
		if _, err, _ := run(in...); err == nil {
			t.Errorf("%s: captured", name)
		} else if !errors.As(err, new(*NoBindError)) {
			t.Errorf("%s: %v is not a NoBindError", name, err)
		}
	}
}

// A far host that holds the agent channel open past the deadline gets no
// bind.
func TestHoldingTheChannelOpenIsNoBind(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		b.Write(bindFrame(t, hostKey(t), sid(), 1))
		io.ReadFull(b, make([]byte, 5))
		b.Write(trigger)
		io.ReadFull(b, make([]byte, 8))
		// and then nothing, without closing
	}()
	a.SetDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := capture(a); err == nil {
		t.Fatal("captured from a channel held open")
	}
}

// The capture socket, through a real unix socket: it is private, takes
// the one connection from the expected pid, refuses a second, and goes
// away on Close.
func TestTheCaptureTakesOneConnectionFromTheExpectedProcess(t *testing.T) {
	dir := shortDir(t)
	c, err := ListenCapture(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fi, err := os.Stat(c.Path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the socket: %v %v", fi, err)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Errorf("the directory has mode %#o", fi.Mode().Perm())
	}
	c.Expect(os.Getpid()) // the test plays ssh
	conn, err := net.Dial("unix", c.Path)
	if err != nil {
		t.Fatal(err)
	}
	bind := bindFrame(t, hostKey(t), sid(), 1)
	conn.Write(bind)
	io.ReadFull(conn, make([]byte, 5))
	// The listener closed on the first accept.
	if second, err := net.Dial("unix", c.Path); err == nil {
		second.Close()
		t.Error("a second connection reached the capture")
	}
	conn.Write(trigger)
	io.ReadFull(conn, make([]byte, 9))
	conn.Close()
	b, err := c.Result(context.Background(), nil)
	if err != nil || !bytes.Equal(b.Frame(), bind) {
		t.Fatalf("captured %x, %v", b.Frame(), err)
	}
}

// A connection from any process but the bootstrap ssh is no bind.
func TestAConnectionFromAnotherProcessIsNoBind(t *testing.T) {
	c, err := ListenCapture(shortDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Expect(os.Getpid() + 1)
	conn, err := net.Dial("unix", c.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write(bindFrame(t, hostKey(t), sid(), 1))
	if _, err := c.Result(context.Background(), nil); err == nil {
		t.Fatal("captured a bind from another process")
	}
}

// If ssh exits and nothing ever connected, the result is no bind, at once:
// the far host did not open the agent channel.
func TestNoConnectionByTheTimeSSHExitsIsNoBind(t *testing.T) {
	c, err := ListenCapture(shortDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	exited := make(chan struct{})
	close(exited)
	_, err = c.Result(context.Background(), exited)
	var nb *NoBindError
	if !errors.As(err, &nb) {
		t.Fatalf("Result: %v", err)
	}
}

// The capture directory must be private to the user.
func TestACaptureDirectoryOthersCanReachIsRefused(t *testing.T) {
	dir := shortDir(t)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ListenCapture(dir); err == nil {
		t.Error("listened in a directory others can enter")
	}
	link := filepath.Join(t.TempDir(), "link")
	os.Symlink(t.TempDir(), link)
	if _, err := ListenCapture(link); err == nil {
		t.Error("listened through a symlink")
	}
}

func TestTheCaptureDirectoryFollowsTheRuntimeDirectory(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("on macOS it is always /tmp/mosey-UID (capture_darwin_test.go)")
	}
	env := map[string]string{"XDG_RUNTIME_DIR": "/run/user/7"}
	if got := CaptureDir(func(k string) string { return env[k] }); got != "/run/user/7/mosey" {
		t.Errorf("got %s", got)
	}
	env = map[string]string{"XDG_RUNTIME_DIR": "relative", "TMPDIR": "/var/tmp"}
	if got := CaptureDir(func(k string) string { return env[k] }); filepath.Dir(got) != "/var/tmp" {
		t.Errorf("got %s", got)
	}
}

// shortDir is a fresh directory under /tmp, not $TMPDIR: a unix socket's
// path must fit in sun_path (108 bytes on Linux, 104 on macOS). On macOS
// $TMPDIR is so long that a capture socket's path does not fit
// (server.md §10 [M]).
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "mc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return filepath.Join(d, "m")
}
