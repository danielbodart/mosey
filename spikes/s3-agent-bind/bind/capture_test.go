package bind

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"testing"

	"golang.org/x/crypto/ssh"
)

func mint(t *testing.T, fwd bool) *Bind {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := ssh.NewSignerFromKey(priv)
	sid := make([]byte, 32)
	rand.Read(sid)
	sig, err := s.Sign(rand.Reader, sid)
	if err != nil {
		t.Fatal(err)
	}
	return &Bind{HostKey: s.PublicKey(), SID: sid, Sig: ssh.Marshal(sig), Fwd: fwd}
}

// run connects as this process (the expected pid unless wantPID says
// otherwise), writes frames, reading a reply after each, and returns what
// Capture took.
func runCapture(t *testing.T, wantPID int, frames ...[]byte) Captured {
	t.Helper()
	c, err := NewCapture(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c.Expect(wantPID, os.Getuid())
	conn, err := net.Dial("unix", c.Path)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range frames {
		if _, err := conn.Write(f); err != nil {
			break
		}
		if _, err := ReadFrame(conn); err != nil {
			break
		}
	}
	conn.Close()
	r := c.Result()
	c.Close()
	return r
}

func bindFrame(b *Bind) []byte { return ExtensionFrame(SessionBindExt, b.Contents()) }

var reqIDs = Frame([]byte{AgentcRequestIDs})

func TestCaptureTakesOnlyBindThenIdentitiesThenEOF(t *testing.T) {
	ours := mint(t, true)
	r := runCapture(t, os.Getpid(), bindFrame(ours), reqIDs)
	if r.Err != nil || r.Bind == nil || string(r.Bind.SID) != string(ours.SID) {
		t.Fatalf("honest: %+v", r)
	}
}

func TestCaptureRefusesABindInjectedAfterTheTrigger(t *testing.T) {
	r := runCapture(t, os.Getpid(), bindFrame(mint(t, true)), reqIDs, bindFrame(mint(t, true)))
	if r.Bind != nil || r.Err == nil {
		t.Fatalf("injected after the trigger: %+v", r)
	}
	r = runCapture(t, os.Getpid(), bindFrame(mint(t, true)), bindFrame(mint(t, true)))
	if r.Bind != nil || r.Err == nil {
		t.Fatalf("second bind as frame 2: %+v", r)
	}
}

func TestCaptureRefusesOtherSendersAndShapes(t *testing.T) {
	if r := runCapture(t, os.Getpid()+1, bindFrame(mint(t, true)), reqIDs); r.Bind != nil {
		t.Fatalf("another pid: %+v", r)
	}
	if r := runCapture(t, os.Getpid(), bindFrame(mint(t, false)), reqIDs); r.Bind != nil {
		t.Fatalf("not forwarding: %+v", r)
	}
	if r := runCapture(t, os.Getpid(), reqIDs, bindFrame(mint(t, true))); r.Bind != nil {
		t.Fatalf("bind second: %+v", r)
	}
	bad := mint(t, true)
	bad.SID[0] ^= 1
	if r := runCapture(t, os.Getpid(), bindFrame(bad), reqIDs); r.Bind != nil {
		t.Fatalf("bad signature: %+v", r)
	}
}

func TestCaptureLegacyTookTheLastBind(t *testing.T) {
	c, _ := NewCapture(t.TempDir())
	c.Legacy = true
	c.Expect(os.Getpid(), os.Getuid())
	conn, _ := net.Dial("unix", c.Path)
	second := mint(t, true)
	for _, f := range [][]byte{bindFrame(mint(t, true)), reqIDs, bindFrame(second)} {
		conn.Write(f)
		ReadFrame(conn)
	}
	conn.Close()
	if r := c.Result(); r.Bind == nil || string(r.Bind.SID) != string(second.SID) {
		t.Fatalf("legacy: %+v", r)
	}
}

func TestCaptureAcceptsOneConnection(t *testing.T) {
	c, _ := NewCapture(t.TempDir())
	c.Expect(os.Getpid(), os.Getuid())
	first, err := net.Dial("unix", c.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	for i := 0; i < 50; i++ {
		if _, err := net.Dial("unix", c.Path); err != nil {
			return // the listener closed on the first accept
		}
	}
	t.Fatal("a second connection was accepted")
}
