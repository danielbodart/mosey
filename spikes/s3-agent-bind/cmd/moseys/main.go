// Command moseys is the S3 spike's stand-in for the remote mosey server.
// It is run over ssh by moseyc and does only what matters to agent
// forwarding:
//
//	bootstrap  (run by ssh) optionally opens the forwarded agent once, so
//	           the client's ssh sends its session-bind; starts a detached
//	           session; prints "MOSEY CONNECT <port> <token> <agent-sock>
//	           <identity-pub>" and exits, ending the ssh session.
//	session    (detached, setsid) the session: a unix socket that is the
//	           session's SSH_AUTH_SOCK, and a loopback TCP port standing in
//	           for the mosey UDP channel (S1's job, not this spike's). Each
//	           connection to the socket becomes one agent channel to the
//	           client, with the connecting process's chain attached.
//	sudo-sign  acts as quoin-sudo's plugin would in remote mode: builds a
//	           quoin-sudo-v1 message naming the host's keys, asks
//	           $SSH_AUTH_SOCK to sign it with the first listed key it holds,
//	           and verifies the signature.
//	chain      prints its own process chain and whether quoin-sudo's
//	           chain.remote rule would call it remote.
package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"mosey.spike/s3-agent-bind/bind"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: moseys bootstrap|session|sudo-sign|chain ...")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "bootstrap":
		err = bootstrap(os.Args[2:])
	case "session":
		err = session(os.Args[2:])
	case "sudo-sign":
		err = sudoSign(os.Args[2:])
	case "chain":
		err = printChain()
	default:
		err = fmt.Errorf("unknown subcommand %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "moseys %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
}

func bootstrap(args []string) error {
	fs := flag.NewFlagSet("bootstrap", flag.ExitOnError)
	dir := fs.String("dir", "", "session state directory")
	trigger := fs.Bool("trigger", true, "open the forwarded agent once so ssh sends its bind")
	hostileKey := fs.String("hostile-bind-key", "", "HOSTILE: after the trigger, send a session-bind signed by this host key on the same agent connection (a bind a hostile server can mint for any host it reaches, pre-auth)")
	ignoreNoAgent := fs.Bool("hostile-ignore-noagent", false, "HOSTILE: open agent channels even when the client said agent=off")
	fs.Parse(args)
	if *dir == "" {
		return errors.New("-dir required")
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	agentState := "no-agent"
	if *trigger {
		if p := os.Getenv("SSH_AUTH_SOCK"); p != "" {
			t0 := time.Now()
			c, err := net.Dial("unix", p)
			if err != nil {
				agentState = "dial-failed"
			} else {
				// One REQUEST_IDENTITIES: ssh connects to ForwardAgent's
				// socket, sends session-bind first, then relays this.
				_, err = agent.NewClient(c).List()
				agentState = fmt.Sprintf("triggered-%dus", time.Since(t0).Microseconds())
				if err != nil {
					agentState = "trigger-error"
				}
				if *hostileKey != "" {
					agentState += "+" + injectBind(c, *hostileKey)
				}
				c.Close()
			}
		}
	}
	// Option (b)'s per-user mosey identity: a long-term key the server
	// keeps, whose public half the client learns over this ssh session.
	idPath := filepath.Join(*dir, "identity.ed25519")
	seed, err := os.ReadFile(idPath)
	if err != nil {
		seed = make([]byte, ed25519.SeedSize)
		rand.Read(seed)
		if err := os.WriteFile(idPath, seed, 0o600); err != nil {
			return err
		}
	}
	idPub, _ := ssh.NewPublicKey(ed25519.NewKeyFromSeed(seed).Public())

	token := make([]byte, 16)
	rand.Read(token)
	r, w, err := os.Pipe()
	if err != nil {
		return err
	}
	self, _ := os.Executable()
	cmd := exec.Command(self, "session", "-dir", *dir, "-token", hex.EncodeToString(token), fmt.Sprintf("-honour-noagent=%v", !*ignoreNoAgent))
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, w, nil
	logf, _ := os.OpenFile(filepath.Join(*dir, "session.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	cmd.Stderr = logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Env = append(os.Environ(), "MOSEY_SPIKE_DETACHED=1")
	if err := cmd.Start(); err != nil {
		return err
	}
	w.Close()
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil {
		return fmt.Errorf("session did not report: %w", err)
	}
	fmt.Printf("MOSEY CONNECT %s %s %s %s\n", strings.TrimSpace(line), hex.EncodeToString(token),
		agentState, base64.StdEncoding.EncodeToString(idPub.Marshal()))
	return nil
}

// injectBind is the review's attack: the server writes a session-bind of
// its own choosing down the forwarded agent channel after ssh's. The key
// stands for any host the server can reach: a bind needs only the host's
// signature over a session id, which any sshd gives before authentication.
func injectBind(c net.Conn, keyPath string) string {
	kb, err := os.ReadFile(keyPath)
	if err != nil {
		return "inject-nokey"
	}
	signer, err := ssh.ParsePrivateKey(kb)
	if err != nil {
		return "inject-badkey"
	}
	sid := make([]byte, 32)
	rand.Read(sid)
	sig, err := signer.Sign(rand.Reader, sid)
	if err != nil {
		return "inject-signfail"
	}
	b := &bind.Bind{HostKey: signer.PublicKey(), SID: sid, Sig: ssh.Marshal(sig), Fwd: true}
	if _, err := c.Write(bind.ExtensionFrame(bind.SessionBindExt, b.Contents())); err != nil {
		return "inject-writefail"
	}
	r, err := bind.ReadFrame(c)
	if err != nil {
		return "inject-noreply(" + strings.ReplaceAll(err.Error(), " ", "_") + ")"
	}
	return fmt.Sprintf("injected-reply%d", r[0])
}

type openMsg struct {
	ID    int         `json:"id"`
	Chain []bind.Link `json:"chain"`
	// For option (b): the server signs a stand-in for the mosey handshake
	// transcript hash with its per-user identity.
	Transcript string `json:"transcript"`
	IDSig      string `json:"id_sig"`
}

func session(args []string) error {
	fs := flag.NewFlagSet("session", flag.ExitOnError)
	dir := fs.String("dir", "", "")
	token := fs.String("token", "", "")
	idle := fs.Duration("idle", 120*time.Second, "exit after this long with no client")
	honour := fs.Bool("honour-noagent", true, "with agent=off from the client, open no agent channels")
	fs.Parse(args)
	seed, err := os.ReadFile(filepath.Join(*dir, "identity.ed25519"))
	if err != nil {
		return err
	}
	idSigner, _ := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))

	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	sockPath := filepath.Join(*dir, "agent.sock")
	os.Remove(sockPath)
	ul, err := net.ListenUnix("unix", &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		return err
	}
	os.Chmod(sockPath, 0o600)
	fmt.Printf("%d %s\n", tcp.Addr().(*net.TCPAddr).Port, sockPath)
	os.Stdout.Close()

	var mu sync.Mutex
	var ctrl net.Conn
	agentOff := false
	pending := map[int]chan net.Conn{}
	nextID := 0
	deadline := time.AfterFunc(*idle, func() { os.Exit(0) })

	go func() {
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				br := bufio.NewReader(c)
				line, err := br.ReadString('\n')
				if err != nil {
					c.Close()
					return
				}
				f := strings.Fields(line)
				if len(f) < 2 || f[1] != *token {
					c.Close()
					return
				}
				switch f[0] {
				case "CTRL":
					mu.Lock()
					ctrl = c
					if len(f) > 2 && f[2] == "agent=off" && *honour {
						agentOff = true
					}
					mu.Unlock()
					deadline.Reset(*idle)
					n := 0
					for {
						l, err := br.ReadString('\n')
						if err != nil {
							break
						}
						// EXEC <base64 json argv>: run a program inside the
						// session, as a shell in it would, with the
						// session's agent socket.
						if f := strings.Fields(l); len(f) == 2 && f[0] == "EXEC" {
							var argv []string
							raw, _ := base64.StdEncoding.DecodeString(f[1])
							if json.Unmarshal(raw, &argv) == nil && len(argv) > 0 {
								n++
								k := n
								out, _ := os.Create(filepath.Join(*dir, fmt.Sprintf("exec-%d.log", n)))
								cmd := exec.Command(argv[0], argv[1:]...)
								mu.Lock()
								off := agentOff
								mu.Unlock()
								cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+sockPath)
								if off {
									cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK=")
								}
								cmd.Stdout, cmd.Stderr = out, out
								go func() {
									err := cmd.Run()
									fmt.Fprintf(out, "EXIT %v\n", err)
									out.Close()
									mu.Lock()
									fmt.Fprintf(c, "EXITED %d %v\n", k, err == nil)
									mu.Unlock()
								}()
							}
						}
					}
					os.Exit(0) // the client went away: the spike session ends
				case "CHAN":
					var id int
					fmt.Sscan(f[2], &id)
					mu.Lock()
					ch := pending[id]
					delete(pending, id)
					mu.Unlock()
					if ch != nil {
						ch <- &bufConn{c, br}
					} else {
						c.Close()
					}
				}
			}(c)
		}
	}()

	for {
		lc, err := ul.AcceptUnix()
		if err != nil {
			return err
		}
		go func(lc *net.UnixConn) {
			defer lc.Close()
			mu.Lock()
			off := agentOff
			mu.Unlock()
			if off {
				return
			}
			chain := bind.PeerChain(lc)
			mu.Lock()
			c := ctrl
			nextID++
			id := nextID
			ch := make(chan net.Conn, 1)
			pending[id] = ch
			mu.Unlock()
			if c == nil {
				return
			}
			tr := sha256.Sum256([]byte(fmt.Sprintf("stand-in transcript %s %d", *token, id)))
			sig, _ := idSigner.Sign(rand.Reader, tr[:])
			m := openMsg{ID: id, Chain: chain, Transcript: hex.EncodeToString(tr[:]),
				IDSig: base64.StdEncoding.EncodeToString(ssh.Marshal(sig))}
			j, _ := json.Marshal(m)
			mu.Lock()
			fmt.Fprintf(c, "OPEN %s\n", j)
			mu.Unlock()
			select {
			case rc := <-ch:
				defer rc.Close()
				go func() { io.Copy(rc, lc); rc.(*bufConn).CloseWrite() }()
				io.Copy(lc, rc)
			case <-time.After(10 * time.Second):
			}
		}(lc)
	}
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }
func (b *bufConn) CloseWrite() error {
	if t, ok := b.Conn.(*net.TCPConn); ok {
		return t.CloseWrite()
	}
	return nil
}

// quoin-sudo-v1, as quoin's internal/sudomsg defines it (read 2026-11-13).
func sudoMessage(hostKeys [][]byte, user, runas, cwd string, argv []string) []byte {
	str := func(b []byte, s []byte) []byte { return append(binary.BigEndian.AppendUint32(b, uint32(len(s))), s...) }
	list := func(b []byte, l [][]byte) []byte {
		b = binary.BigEndian.AppendUint32(b, uint32(len(l)))
		for _, s := range l {
			b = str(b, s)
		}
		return b
	}
	nonce := make([]byte, 32)
	rand.Read(nonce)
	b := str(nil, []byte("quoin-sudo-v1"))
	b = str(b, nonce)
	b = list(b, hostKeys)
	b = str(b, []byte(user))
	b = str(b, []byte(runas))
	b = str(b, []byte(cwd))
	var a [][]byte
	for _, s := range argv {
		a = append(a, []byte(s))
	}
	b = list(b, a)
	b = str(b, nil)
	return list(b, nil)
}

func sudoSign(args []string) error {
	fs := flag.NewFlagSet("sudo-sign", flag.ExitOnError)
	hostKeys := fs.String("hostkeys", "/etc/ssh/ssh_host_*_key.pub", "glob of the host's public keys")
	listed := fs.String("listed", "", "authorized-keys file of remoteKeys")
	out := fs.String("out", "", "write the message here")
	fs.Parse(args)
	files, _ := filepath.Glob(*hostKeys)
	var hk [][]byte
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		k, _, _, _, err := ssh.ParseAuthorizedKey(b)
		if err == nil {
			hk = append(hk, k.Marshal())
		}
	}
	if len(hk) == 0 {
		return errors.New("no host keys")
	}
	lb, err := os.ReadFile(*listed)
	if err != nil {
		return err
	}
	lk, _, _, _, err := ssh.ParseAuthorizedKey(lb)
	if err != nil {
		return err
	}
	cwd, _ := os.Getwd()
	msg := sudoMessage(hk, os.Getenv("USER"), "root", cwd, append([]string{"/run/current-system/sw/bin/id"}, fs.Args()...))
	if *out != "" {
		os.WriteFile(*out, msg, 0o600)
	}
	c, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return err
	}
	defer c.Close()
	ag := agent.NewClient(c)
	keys, err := ag.List()
	if err != nil {
		return err
	}
	found := false
	for _, k := range keys {
		if string(k.Blob) == string(lk.Marshal()) {
			found = true
		}
	}
	if !found {
		return errors.New("no listed key in the forwarded agent")
	}
	t0 := time.Now()
	sig, err := ag.Sign(lk, msg)
	if err != nil {
		return fmt.Errorf("the forwarded agent refused: %w", err)
	}
	if err := lk.Verify(msg, sig); err != nil {
		return fmt.Errorf("signature did not verify: %w", err)
	}
	fmt.Printf("SUDO-SIGNED ok in %s (%s)\n", time.Since(t0), sig.Format)
	return nil
}

func printChain() error {
	ch := bind.ReadChain(os.Getpid())
	for _, l := range ch {
		fmt.Println(" ", l)
	}
	fmt.Printf("quoin-sudo chain.remote (Go restatement of 0331bf1): %v\n", bind.QuoinRemote(ch, os.Getuid()))
	return nil
}
