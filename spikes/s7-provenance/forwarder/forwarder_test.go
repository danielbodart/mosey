package forwarder

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/danielbodart/quoin/provenance"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// local is the agent at the client's end of the agent channel: a keyring
// that verifies each provenance statement as quoin-signer would and keeps
// what it opened. The test imports quoin; the forwarder does not.
type local struct {
	agent.ExtendedAgent
	mu     sync.Mutex
	opened []*provenance.Opened
	signs  int
}

func (l *local) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	l.mu.Lock()
	l.signs++
	l.mu.Unlock()
	return l.ExtendedAgent.SignWithFlags(key, data, flags)
}

func (l *local) Extension(typ string, contents []byte) ([]byte, error) {
	if typ != provenance.Extension {
		return nil, agent.ErrExtensionUnsupported
	}
	o, err := provenance.Open(contents, time.Now())
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.opened = append(l.opened, o)
	l.mu.Unlock()
	return nil, nil
}

// session is a mosey server's agent socket in one session: each connection
// forwarded through f into a fresh agent channel to l.
func session(t *testing.T, f *Forwarder, l *local) (string, *int) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	attested := new(int)
	var mu sync.Mutex
	go func() {
		for {
			c, err := ln.AcceptUnix()
			if err != nil {
				return
			}
			channel, far := net.Pipe()
			go agent.ServeAgent(l, far)
			go func() {
				ok, _ := f.Forward(c, channel)
				if ok {
					mu.Lock()
					*attested++
					mu.Unlock()
				}
			}()
		}
	}()
	return path, attested
}

func newLocal(t *testing.T) (*local, string) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	kr := agent.NewKeyring()
	if err := kr.Add(agent.AddedKey{PrivateKey: priv}); err != nil {
		t.Fatal(err)
	}
	keys, _ := kr.List()
	pubFile := filepath.Join(t.TempDir(), "user.pub")
	os.WriteFile(pubFile, []byte(keys[0].String()+"\n"), 0o600)
	return &local{ExtendedAgent: kr.(agent.ExtendedAgent)}, pubFile
}

// sign runs stock ssh-keygen -Y sign against the session's socket: the
// client is a real process, not this test.
func sign(t *testing.T, sock, pub string) *exec.Cmd {
	t.Helper()
	file := filepath.Join(t.TempDir(), "commit")
	os.WriteFile(file, []byte("tree 0\n"), 0o600)
	cmd := exec.Command("ssh-keygen", "-Y", "sign", "-n", "git", "-f", pub, file)
	cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+sock)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}
	return cmd
}

func startAttester(t *testing.T) string {
	t.Helper()
	host, key := newSigner(t), newSigner(t)
	now := time.Now()
	d, sig, err := provenance.Delegate(rand.Reader, host, &provenance.Delegation{
		AttesterKey: key.PublicKey().Marshal(), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), Hostname: "remote",
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "handoff.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	p := &provenance.Proxy{Attester: &provenance.Attester{Key: key, Delegation: d, DelegatSig: sig},
		Who: provenance.FromKernel, Hostname: "remote", Session: []byte("mosey-session-id")}
	go provenance.ServeHandoff(ln, p)
	return path
}

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestWithNoAttesterTheChannelIsPlainAgentForwarding(t *testing.T) {
	l, pub := newLocal(t)
	sock, attested := session(t, &Forwarder{Attester: filepath.Join(t.TempDir(), "none")}, l)
	sign(t, sock, pub)
	if l.signs != 1 || len(l.opened) != 0 || *attested != 0 {
		t.Fatalf("signs %d, statements %d, attested %d", l.signs, len(l.opened), *attested)
	}
}

func TestWithAnAttesterEachSignCarriesTheClientsChain(t *testing.T) {
	l, pub := newLocal(t)
	sock, _ := session(t, &Forwarder{Attester: startAttester(t)}, l)
	cmd := sign(t, sock, pub)
	if l.signs != 1 || len(l.opened) != 1 {
		t.Fatalf("signs %d, statements %d", l.signs, len(l.opened))
	}
	o := l.opened[0]
	leaf := o.Chain[0]
	if leaf.Comm != "ssh-keygen" || int(leaf.Pid) != cmd.Process.Pid || int(o.Chain[1].Pid) != os.Getpid() {
		t.Fatalf("the chain is %+v", o.Chain[:2])
	}
	if string(o.Session) != "mosey-session-id" || o.Hostname != "remote" {
		t.Errorf("statement %q %q", o.Session, o.Hostname)
	}
	t.Logf("statement: %d links, leaf %q %q, cwd %q", len(o.Chain), leaf.Comm, leaf.Argv, leaf.Cwd)
}
