//go:build linux

package e2e

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/danielbodart/mosey/internal/bootstrap"
)

// sshd is a throwaway, unprivileged OpenSSH server on 127.0.0.1, with its
// own host key, a throwaway user key it alone accepts, and a client config
// that uses only those: never the system sshd, ~/.ssh, or the user's agent
// (CLAUDE.md), as spikes/s3-agent-bind/harness does.
type sshd struct {
	dir    string
	config string // the client's ssh_config, for ssh -F
	host   string // its Host alias
	// home is $HOME for whoever logs in: a directory of the test's, so
	// nothing a session does (D7's ~/.local/bin/mosey, a shell's history)
	// lands in the user's real home.
	home string
	// runtime is the XDG_RUNTIME_DIR sshd gives its sessions, so the
	// servers' attach sockets are the test's own.
	runtime string
	// port is where it listens, and alias the HostKeyAlias its client
	// config uses, if any.
	port  int
	alias string
}

// sshdOptions vary the throwaway sshd for the agent tests.
type sshdOptions struct {
	// allowAgent sets AllowAgentForwarding yes.
	allowAgent bool
	// alias is the client config's HostKeyAlias, and its known_hosts
	// names the host key by it too.
	alias string
	// authorized, if set, is the only key sshd takes, in place of the
	// throwaway user key: an agent's key, for a hop that must be signed
	// through the forwarded agent.
	authorized string
	// clientExtra is more lines for the client config's Host block.
	clientExtra string
	// identityAgent is the client config's IdentityAgent: none, unless a
	// test forwards an agent, which ssh does only from an agent it uses.
	identityAgent string
	// path, if set, is the PATH sshd gives its sessions, so a test decides
	// which mosey, if any, the far host has on it (bootstrap.md §4.7.2).
	path string
	// shell, if set, is the SHELL sshd gives its sessions, which the
	// spawner starts as the session's login shell (server.md §2.5).
	shell string
	// home, if set, is the HOME sshd gives its sessions, so a test can
	// name directories under it in path; otherwise a fresh t.TempDir.
	home string
	// env is more NAME=value words for sshd's SetEnv, none with a space.
	env []string
}

func startSSHD(t *testing.T) *sshd { return startSSHDWith(t, sshdOptions{}) }

func startSSHDWith(t *testing.T, o sshdOptions) *sshd {
	t.Helper()
	bin, err := exec.LookPath("sshd")
	if err != nil {
		t.Skip("no sshd")
	}
	if bin, err = filepath.EvalSymlinks(bin); err != nil { // sshd wants an absolute path
		t.Skip(err)
	}
	for _, tool := range []string{"ssh", "ssh-keygen"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s", tool)
		}
	}
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	s := &sshd{dir: t.TempDir(), host: "mosey-e2e", home: o.home, runtime: runtimeDir(t)}
	if s.home == "" {
		s.home = t.TempDir()
	}
	for _, k := range []string{"host", "user"} {
		if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "mosey-e2e", "-f", filepath.Join(s.dir, k)).CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen: %v %s", err, out)
		}
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	s.port, s.alias = port, o.alias
	authorized := filepath.Join(s.dir, "user.pub")
	if o.authorized != "" {
		authorized = o.authorized
	}
	allowAgent := "no"
	if o.allowAgent {
		allowAgent = "yes"
	}
	if o.identityAgent == "" {
		o.identityAgent = "none"
	}
	setEnv := fmt.Sprintf("HOME=%s XDG_RUNTIME_DIR=%s", s.home, s.runtime)
	for _, kv := range o.env {
		setEnv += " " + kv
	}
	if o.path != "" {
		setEnv += " PATH=" + o.path
	}
	if o.shell != "" {
		setEnv += " SHELL=" + o.shell
	}

	write := func(name, text string) string {
		path := filepath.Join(s.dir, name)
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	sshdConfig := write("sshd_config", fmt.Sprintf(`Port %d
ListenAddress 127.0.0.1
HostKey %[2]s/host
PidFile %[2]s/sshd.pid
AuthorizedKeysFile %[5]s
PasswordAuthentication no
KbdInteractiveAuthentication no
StrictModes no
UsePAM no
AllowAgentForwarding %[6]s
AllowTcpForwarding no
X11Forwarding no
SetEnv %[3]s
`, port, s.dir, setEnv, s.runtime, authorized, allowAgent))
	hostPub, err := os.ReadFile(filepath.Join(s.dir, "host.pub"))
	if err != nil {
		t.Fatal(err)
	}
	known := fmt.Sprintf("[127.0.0.1]:%d %s", port, hostPub)
	if o.alias != "" {
		known += fmt.Sprintf("%s %s", o.alias, hostPub)
		o.clientExtra += "\n  HostKeyAlias " + o.alias
	}
	write("known_hosts", known)
	s.config = write("ssh_config", fmt.Sprintf(`Host %s
  HostName 127.0.0.1
  Port %d
  User %s
  IdentityFile %[4]s/user
  IdentitiesOnly yes
  IdentityAgent %[6]s
  UserKnownHostsFile %[4]s/known_hosts
  GlobalKnownHostsFile /dev/null
  StrictHostKeyChecking yes
  BatchMode yes%[5]s
`, s.host, port, me.Username, s.dir, o.clientExtra, o.identityAgent))

	if out, err := exec.Command(bin, "-t", "-f", sshdConfig).CombinedOutput(); err != nil {
		t.Skipf("this sshd will not take a throwaway config: %v %s", err, out)
	}
	cmd := exec.Command(bin, "-D", "-f", sshdConfig, "-E", filepath.Join(s.dir, "sshd.log"))
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	waitFor(t, "sshd to listen", func() bool {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			c.Close()
		}
		return err == nil
	})
	return s
}

// The throwaway sshd logs its user in with the throwaway key alone, and
// the bootstrap's own ssh options are accepted by it: the harness the
// real end-to-end test stands on.
func TestTheThrowawaySSHDTakesTheBootstrapsSSH(t *testing.T) {
	s := startSSHD(t)
	b := bootstrap.SSH{
		Program:     "ssh",
		Destination: s.host,
		Server:      "true",
		Options:     bootstrap.SSHOptions{Args: []string{"-F", s.config}},
	}
	c, err := b.Resolve(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	cmd := b.Command(t.Context(), c)
	// `true --serve` exits 0 with nothing on stdout: the bootstrap ssh got
	// in and ran the remote command through /bin/sh.
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s\nsshd log:\n%s", err, out, readFile(filepath.Join(s.dir, "sshd.log")))
	}
}

// The real mosey, client and server, over loopback UDP, bootstrapped
// through a real sshd: an interactive login shell end to end. What is typed
// reaches the far shell, what it prints is drawn on the user's terminal,
// UTF-8 included, and when the shell exits the client exits 0 by itself,
// the terminal put back and no process of the session left behind.
func TestARealSessionOverLoopbackThroughSSH(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	s := startSSHD(t)
	mosey := buildMosey(t, "e2e")

	master, slave := openPTY(t)
	state := t.TempDir()
	cmd := exec.Command(mosey, "-remote", mosey, "--", "-F", s.config, s.host)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
	// Its log goes to the test's directory, not the user's state.
	cmd.Env = append(os.Environ(), "XDG_STATE_HOME="+state, "TERM=xterm-256color", "LANG=C.UTF-8")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	slave.Close()
	var screen screenLog
	go screen.collect(master)
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	defer func() {
		select {
		case <-exited:
		default:
			cmd.Process.Signal(syscall.SIGTERM)
			<-exited
		}
	}()

	// A session that shows a screen has done the bootstrap, the handshake
	// and the first SSP round. 6*7 is worked out by the far shell, so the
	// answer cannot be the echo of what was typed.
	waitFor(t, "the session's screen", func() bool { return strings.Contains(screen.String(), "\x1b[22;2t\x1b[?7l") })
	if _, err := master.Write([]byte("echo hello mosey-$((6*7)) h\u00e9llo\r")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the shell's answer", func() bool {
		// The renderer places runs of cells itself (D9), so the answer is
		// read off the screen its bytes draw, not out of the bytes.
		return strings.Contains(screenOf([]byte(screen.String()), 100, 30), "hello mosey-42 h\u00e9llo")
	})
	spawner := findSpawner(t, mosey)
	// The client holds the session's keys for as long as it runs: neither
	// the user's other processes nor a core dump may read them
	// (threat-model.md §4.10).
	if os.Getuid() != 0 {
		if !notDumpable(cmd.Process.Pid) {
			t.Error("the client is dumpable")
		}
		if core := coreLimit(cmd.Process.Pid); core != "0 0" {
			t.Errorf("the client may dump %q bytes of core", core)
		}
	}

	if _, err := master.Write([]byte("exit\r")); err != nil {
		t.Fatal(err)
	}
	var err error
	waitFor(t, "mosey to exit after the shell did", func() bool {
		select {
		case err = <-exited:
			exited <- err
			return true
		default:
			return false
		}
	})
	if bootstrap.ExitStatus(err) != 0 {
		t.Errorf("mosey exited %v; log:\n%s", err, readFile(filepath.Join(state, "mosey", "client.log")))
	}
	// The terminal is back as it was: the alternate screen left.
	waitFor(t, "the terminal to be restored", func() bool { return strings.Contains(screen.String(), "\x1b[?25h\x1b[?7h") })
	waitFor(t, "the session's processes to end", func() bool { return !running(spawner) })
}

// The client against the real server through a fake ssh (bootstrap.md
// §12): a server that prints rc noise first, and a server of another
// version, which serves the client all the same (D8 V1: nothing refuses
// another mosey version; the handshake agrees on a protocol version).
func TestTheRealServerAnswersThroughAFakeSSH(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	mosey := buildMosey(t, "1.0.1")
	other := buildMosey(t, "2.0.1")
	dir := t.TempDir()
	ssh := filepath.Join(dir, "ssh")
	if err := os.WriteFile(ssh, []byte(`#!/bin/sh
if [ "$1" = -G ]; then printf 'hostname 127.0.0.1\n'; exit 0; fi
for last in "$@"; do :; done
echo 'rc file noise'
SSH_CONNECTION='127.0.0.1 40000 127.0.0.1 22' exec /bin/sh -c "$last"
`), 0o755); err != nil {
		t.Fatal(err)
	}
	type run struct {
		master *os.File
		screen *screenLog
		exited chan error
	}
	start := func(remote string) *run {
		master, slave := openPTY(t)
		cmd := exec.Command(mosey, "-ssh", ssh, "-remote", remote, "127.0.0.1")
		cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
		cmd.Env = append(os.Environ(), "XDG_STATE_HOME="+t.TempDir(), "XDG_RUNTIME_DIR="+runtimeDir(t), "TERM=xterm-256color")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		slave.Close()
		r := &run{master: master, screen: &screenLog{}, exited: make(chan error, 1)}
		go r.screen.collect(master)
		go func() { r.exited <- cmd.Wait() }()
		t.Cleanup(func() { cmd.Process.Kill() })
		return r
	}
	status := func(r *run) int {
		var err error
		waitFor(t, "the client to exit", func() bool {
			select {
			case err = <-r.exited:
				r.exited <- err
				return true
			default:
				return false
			}
		})
		return bootstrap.ExitStatus(err)
	}

	r := start(other)
	r.master.Write([]byte("echo across-$((40+2))\r"))
	waitFor(t, "a session with a server of another version", func() bool {
		return strings.Contains(screenOf([]byte(r.screen.String()), 100, 30), "across-42")
	})
	r.master.Write([]byte("exit\r"))
	if s := status(r); s != 0 {
		t.Errorf("a server of another version: exit %d %q", s, r.screen.String())
	}

	r = start(filepath.Join(dir, "nothing-here"))
	if s := status(r); s != 1 || !strings.Contains(r.screen.String(), "no mosey at") {
		t.Errorf("no server: %d %q", s, r.screen.String())
	}
}

func readFile(path string) string {
	b, _ := os.ReadFile(path)
	return string(bytes.TrimSpace(b))
}
