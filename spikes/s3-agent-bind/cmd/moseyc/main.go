// Command moseyc is the S3 spike's stand-in for the mosey client. It
// bootstraps over SSH, then relays the session's agent channels to a local
// agent, prefixing each with a session-bind made one of four ways:
//
//	-mode capture   option (a'): system ssh -o ForwardAgent=<capture socket>;
//	                the real triple ssh itself sends is kept and replayed.
//	-mode xcrypto   option (a): x/crypto/ssh does the bootstrap (over
//	                "ssh -W" for a ProxyJump), the triple is tapped from
//	                the cleartext key exchange.
//	-mode identity  option (b): a per-user mosey identity, vouched for by
//	                SSH; the bind names that key and a transcript hash.
//	-mode none      no bind (what a plain relay without binds looks like).
//
// -hop adds option (c)'s hop record after the bind.
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"mosey.spike/s3-agent-bind/bind"
)

type openMsg struct {
	ID         int         `json:"id"`
	Chain      []bind.Link `json:"chain"`
	Transcript string      `json:"transcript"`
	IDSig      string      `json:"id_sig"`
}

type result struct {
	Mode          string          `json:"mode"`
	Host          string          `json:"host"`
	BootstrapMS   float64         `json:"bootstrap_ms"`
	AgentState    string          `json:"agent_state"`
	Bind          string          `json:"bind,omitempty"`
	BindHostKey   string          `json:"bind_host_key,omitempty"`
	CapturePeerOK *bool           `json:"capture_peer_is_our_ssh,omitempty"`
	CaptureMsgs   []byte          `json:"capture_msgs,omitempty"`
	Channels      []channelRecord `json:"channels"`
	Execs         map[string]bool `json:"execs"`
	Errors        []string        `json:"errors,omitempty"`
	mu            sync.Mutex
}

type channelRecord struct {
	ID      int                 `json:"id"`
	Chain   []bind.Link         `json:"remote_chain"`
	Prelude []bind.PreludeReply `json:"prelude_replies"`
	Frames  []string            `json:"frames_to_agent_hex"`
	Err     string              `json:"err,omitempty"`
}

func main() {
	cfg := flag.String("F", "", "ssh config file")
	host := flag.String("host", "", "destination, as ssh_config names it")
	mode := flag.String("mode", "capture", "capture|xcrypto|identity|none")
	hop := flag.Bool("hop", false, "send option (c)'s hop record after the bind")
	agentPath := flag.String("agent", "", "local agent to relay to (never the live signer)")
	remote := flag.String("remote", "", "path of moseys on the remote")
	dir := flag.String("dir", "", "remote session state directory")
	capDir := flag.String("capdir", "", "local directory for the capture socket")
	execs := flag.String("exec", "", "JSON list of argv lists to run inside the remote session")
	out := flag.String("out", "", "write the result JSON here")
	extraSSH := flag.String("sshopt", "", "extra -o option for the bootstrap ssh")
	flag.Parse()
	if *agentPath == "" || *host == "" || *remote == "" || *dir == "" {
		fmt.Fprintln(os.Stderr, "moseyc: -agent, -host, -remote and -dir are required")
		os.Exit(2)
	}
	res := &result{Mode: *mode, Host: *host, Execs: map[string]bool{}}
	err := run(res, *cfg, *host, *mode, *hop, *agentPath, *remote, *dir, *capDir, *execs, *extraSSH)
	if err != nil {
		res.Errors = append(res.Errors, err.Error())
	}
	j, _ := json.MarshalIndent(res, "", "  ")
	if *out != "" {
		os.WriteFile(*out, j, 0o600)
	}
	fmt.Fprintf(os.Stderr, "moseyc: mode=%s bootstrap=%.1fms agent=%s bind=%s channels=%d execs=%v errors=%v\n",
		res.Mode, res.BootstrapMS, res.AgentState, res.Bind, len(res.Channels), res.Execs, res.Errors)
	if err != nil {
		os.Exit(1)
	}
}

func run(res *result, cfg, host, mode string, hop bool, agentPath, remote, dir, capDir, execs, extraSSH string) error {
	remoteCmd := fmt.Sprintf("%s bootstrap -dir %s", remote, dir)
	var line string
	var b *bind.Bind
	t0 := time.Now()
	switch mode {
	case "capture", "identity", "none":
		args := []string{}
		if cfg != "" {
			args = append(args, "-F", cfg)
		}
		var cp *bind.Capture
		if mode == "capture" {
			var err error
			if cp, err = bind.NewCapture(capDir); err != nil {
				return err
			}
			defer cp.Close()
			args = append(args, "-o", "ForwardAgent="+cp.Path)
		} else {
			args = append(args, "-o", "ForwardAgent=no")
			remoteCmd += " -trigger=false"
		}
		if extraSSH != "" {
			args = append(args, "-o", extraSSH)
		}
		args = append(args, "-T", host, remoteCmd)
		cmd := exec.Command("ssh", args...)
		cmd.Stderr = os.Stderr
		stdout, _ := cmd.StdoutPipe()
		if err := cmd.Start(); err != nil {
			return err
		}
		l, err := bufio.NewReader(stdout).ReadString('\n')
		werr := cmd.Wait()
		if err != nil {
			return fmt.Errorf("bootstrap: %v (ssh: %v)", err, werr)
		}
		line = l
		if cp != nil {
			select {
			case c := <-cp.C:
				b = c.Bind
				ok := int(c.PeerPID) == cmd.Process.Pid
				res.CapturePeerOK = &ok
				res.CaptureMsgs = c.Msgs
			case <-time.After(2 * time.Second):
				return errors.New("capture: ssh sent no session-bind (agent forwarding refused by the server?)")
			}
			for _, e := range cp.Errors() {
				res.Errors = append(res.Errors, e.Error())
			}
		}
	case "xcrypto":
		var err error
		line, b, err = xcryptoBootstrap(cfg, host, remoteCmd)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("mode %q", mode)
	}
	res.BootstrapMS = float64(time.Since(t0).Microseconds()) / 1000
	f := strings.Fields(line)
	if len(f) < 7 || f[0] != "MOSEY" || f[1] != "CONNECT" {
		return fmt.Errorf("bootstrap said %q", line)
	}
	port, token, agentState, idPubB64 := f[2], f[4], f[5], f[6]
	res.AgentState = agentState
	if b != nil {
		res.Bind = b.String()
		res.BindHostKey = string(ssh.MarshalAuthorizedKey(b.HostKey))
	}
	var idPub ssh.PublicKey
	if raw, err := base64.StdEncoding.DecodeString(idPubB64); err == nil {
		idPub, _ = ssh.ParsePublicKey(raw)
	}

	ctrl, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		return err
	}
	defer ctrl.Close()
	fmt.Fprintf(ctrl, "CTRL %s\n", token)
	var argvs [][]string
	if execs != "" {
		if err := json.Unmarshal([]byte(execs), &argvs); err != nil {
			return err
		}
	}
	for _, a := range argvs {
		j, _ := json.Marshal(a)
		fmt.Fprintf(ctrl, "EXEC %s\n", base64.StdEncoding.EncodeToString(j))
	}
	var wg sync.WaitGroup
	br := bufio.NewReader(ctrl)
	exited := 0
	for exited < len(argvs) {
		l, err := br.ReadString('\n')
		if err != nil {
			return fmt.Errorf("control: %w", err)
		}
		switch {
		case strings.HasPrefix(l, "OPEN "):
			var m openMsg
			if err := json.Unmarshal([]byte(l[5:]), &m); err != nil {
				return err
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				rec := channelRecord{ID: m.ID, Chain: m.Chain}
				err := relayOne(&rec, port, token, m, mode, b, idPub, hop, agentPath)
				if err != nil {
					rec.Err = err.Error()
				}
				res.mu.Lock()
				res.Channels = append(res.Channels, rec)
				res.mu.Unlock()
			}()
		case strings.HasPrefix(l, "EXITED "):
			g := strings.Fields(l)
			res.Execs[g[1]] = g[2] == "true"
			exited++
		}
	}
	wg.Wait()
	return nil
}

func relayOne(rec *channelRecord, port, token string, m openMsg, mode string, b *bind.Bind, idPub ssh.PublicKey, hop bool, agentPath string) error {
	c, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		return err
	}
	fmt.Fprintf(c, "CHAN %s %d\n", token, m.ID)
	var prelude []bind.Prelude
	var hopKey []byte
	switch mode {
	case "capture", "xcrypto":
		// Replay: the same triple on every channel, with is_forwarding set,
		// as OpenSSH's ssh does on each forwarded agent connection.
		prelude = append(prelude, bind.Prelude{Name: bind.SessionBindExt, Contents: b.WithFwd(true).Contents()})
		hopKey = b.HostKey.Marshal()
	case "identity":
		tr, _ := hex.DecodeString(m.Transcript)
		sig, _ := base64.StdEncoding.DecodeString(m.IDSig)
		ib := &bind.Bind{HostKey: idPub, SID: tr, Sig: sig, Fwd: true}
		if err := ib.Verify(); err != nil {
			return fmt.Errorf("identity bind: %w", err)
		}
		prelude = append(prelude, bind.Prelude{Name: bind.SessionBindExt, Contents: ib.Contents()})
		hopKey = idPub.Marshal()
	}
	if hop && hopKey != nil {
		h := &bind.Hop{Transport: "mosey", HostKey: hopKey, Session: "default", Chain: m.Chain}
		prelude = append(prelude, bind.Prelude{Name: bind.HopExt, Contents: h.Marshal(), Optional: true})
	}
	rr := &bind.Recorder{}
	replies, err := bind.Relay(c, agentPath, prelude, rr)
	rec.Prelude = replies
	for _, f := range rr.Frames {
		rec.Frames = append(rec.Frames, hex.EncodeToString(f))
	}
	return err
}

// xcryptoBootstrap is option (a): ssh -G for the few settings it can honour,
// "ssh -W" through the ProxyJump if there is one, then x/crypto/ssh.
func xcryptoBootstrap(cfg, host, remoteCmd string) (string, *bind.Bind, error) {
	g, err := sshG(cfg, host)
	if err != nil {
		return "", nil, err
	}
	addr := net.JoinHostPort(g["hostname"][0], g["port"][0])
	var raw net.Conn
	if pj := g["proxyjump"]; len(pj) > 0 && pj[0] != "none" {
		args := []string{}
		if cfg != "" {
			args = append(args, "-F", cfg)
		}
		args = append(args, "-W", addr, pj[0])
		raw, err = cmdConn(args...)
	} else {
		raw, err = net.Dial("tcp", addr)
	}
	if err != nil {
		return "", nil, err
	}
	tap := &bind.TapConn{Conn: raw}
	var signers []ssh.Signer
	for _, idf := range g["identityfile"] {
		kb, err := os.ReadFile(expand(idf))
		if err != nil {
			continue
		}
		s, err := ssh.ParsePrivateKey(kb)
		if err == nil {
			signers = append(signers, s)
		}
	}
	var kh []string
	for _, f := range g["userknownhostsfile"] {
		kh = append(kh, strings.Fields(expand(f))...)
	}
	var existing []string
	for _, f := range kh {
		if _, err := os.Stat(f); err == nil {
			existing = append(existing, f)
		}
	}
	// Papercut found by the spike: ssh -G prints HostKeyAlias lower-cased
	// and OpenSSH matches known_hosts names case-insensitively, while
	// x/crypto/ssh/knownhosts matches case-sensitively. Lower-case a copy.
	existing, err = lowerKnownHosts(existing)
	if err != nil {
		return "", nil, err
	}
	hkcb, err := knownhosts.New(existing...)
	if err != nil {
		return "", nil, err
	}
	alias := ""
	if a := g["hostkeyalias"]; len(a) > 0 {
		alias = a[0]
	}
	conf := &ssh.ClientConfig{
		User: g["user"][0],
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		HostKeyCallback: func(h string, r net.Addr, k ssh.PublicKey) error {
			// OpenSSH looks a HostKeyAlias up with no port; knownhosts
			// wants host:port and writes [host]:port for any port but 22.
			// It also splits the remote address, which for an "ssh -W"
			// pipe is not host:port: give it the target's.
			r = fixedAddr(addr)
			if alias != "" {
				return hkcb(net.JoinHostPort(alias, "22"), r, k)
			}
			return hkcb(h, r, k)
		},
		Config: ssh.Config{KeyExchanges: []string{ssh.KeyExchangeMLKEM768X25519, ssh.KeyExchangeCurve25519}},
	}
	cc, chans, reqs, err := ssh.NewClientConn(tap, addr, conf)
	if err != nil {
		return "", nil, err
	}
	b, err := bind.BindFromClientConn(tap, cc)
	if err != nil {
		return "", nil, err
	}
	client := ssh.NewClient(cc, chans, reqs)
	defer client.Close()
	// Agent forwarding over x/crypto: serve forwarded channels from the
	// spike's capture-free path: here the bootstrap does not need it.
	sess, err := client.NewSession()
	if err != nil {
		return "", nil, err
	}
	o, err := sess.Output(remoteCmd + " -trigger=false")
	if err != nil {
		return "", nil, err
	}
	return string(o), b, nil
}

func expand(p string) string {
	if strings.HasPrefix(p, "~/") {
		h, _ := os.UserHomeDir()
		return h + p[1:]
	}
	return p
}

func sshG(cfg, host string) (map[string][]string, error) {
	args := []string{}
	if cfg != "" {
		args = append(args, "-F", cfg)
	}
	o, err := exec.Command("ssh", append(args, "-G", host)...).Output()
	if err != nil {
		return nil, err
	}
	m := map[string][]string{}
	for _, l := range strings.Split(string(o), "\n") {
		k, v, ok := strings.Cut(l, " ")
		if ok {
			m[k] = append(m[k], v)
		}
	}
	if _, err := strconv.Atoi(m["port"][0]); err != nil {
		return nil, errors.New("ssh -G: no port")
	}
	return m, nil
}

// cmdConn runs a command and treats its stdin/stdout as a stream.
func cmdConn(args ...string) (net.Conn, error) {
	cmd := exec.CommandContext(context.Background(), "ssh", args...)
	in, _ := cmd.StdinPipe()
	outp, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	a, b := net.Pipe()
	go func() { io.Copy(in, b); in.Close() }()
	go func() { io.Copy(b, outp); b.Close() }()
	return a, nil
}

var _ = agent.NewClient

type fixedAddr string

func (a fixedAddr) Network() string { return "tcp" }
func (a fixedAddr) String() string  { return string(a) }

func lowerKnownHosts(files []string) ([]string, error) {
	var out []string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var lines []string
		for _, l := range strings.Split(string(b), "\n") {
			fs := strings.SplitN(l, " ", 2)
			if len(fs) == 2 && !strings.HasPrefix(fs[0], "|") && !strings.HasPrefix(fs[0], "#") && !strings.HasPrefix(fs[0], "@") {
				l = strings.ToLower(fs[0]) + " " + fs[1]
			}
			lines = append(lines, l)
		}
		tmp, err := os.CreateTemp("", "kh-lower-")
		if err != nil {
			return nil, err
		}
		tmp.WriteString(strings.Join(lines, "\n"))
		tmp.Close()
		out = append(out, tmp.Name())
	}
	return out, nil
}
