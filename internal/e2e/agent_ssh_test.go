//go:build linux

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// throwawayAgent is an OpenSSH ssh-agent on a socket of the test's own,
// never the user's (CLAUDE.md), and a throwaway key for it.
type throwawayAgent struct {
	t    *testing.T
	sock string
	// key is the private key file; key+".pub" its public half.
	key string
}

const agentKeyComment = "mosey-agent-test-key"

func startAgent(t *testing.T) *throwawayAgent {
	t.Helper()
	for _, tool := range []string{"ssh-agent", "ssh-add", "ssh-keygen"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s", tool)
		}
	}
	a := &throwawayAgent{t: t, sock: filepath.Join(runtimeDir(t), "agent.sock"), key: filepath.Join(t.TempDir(), "agentkey")}
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", agentKeyComment, "-f", a.key).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v %s", err, out)
	}
	cmd := exec.Command("ssh-agent", "-D", "-a", a.sock)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	waitFor(t, "ssh-agent to listen", func() bool { _, err := os.Stat(a.sock); return err == nil })
	return a
}

// add runs ssh-add against the throwaway agent with args.
func (a *throwawayAgent) add(args ...string) {
	a.t.Helper()
	cmd := exec.Command("ssh-add", args...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "SSH_AUTH_SOCK=" + a.sock}
	if out, err := cmd.CombinedOutput(); err != nil {
		a.t.Fatalf("ssh-add %v: %v %s", args, err, out)
	}
}

// startAgentClient is startClient with the throwaway agent as the user's
// SSH_AUTH_SOCK, and a runtime directory of the test's own for the
// capture socket (bootstrap.md §8), so neither touches the user's.
func startAgentClient(t *testing.T, name, mosey string, s *sshd, a *throwawayAgent, flags ...string) *realClient {
	t.Helper()
	master, slave := openPTY(t)
	c := &realClient{t: t, label: name, master: master, screen: &screenLog{}, exited: make(chan error, 1), state: t.TempDir()}
	args := append(append([]string{}, flags...), "-remote", mosey, "--", "-F", s.config, s.host)
	c.cmd = exec.Command(mosey, args...)
	c.cmd.Stdin, c.cmd.Stdout, c.cmd.Stderr = slave, slave, slave
	c.cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
	env := []string{}
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "SSH_AUTH_SOCK=") && !strings.HasPrefix(kv, "XDG_RUNTIME_DIR=") {
			env = append(env, kv)
		}
	}
	c.cmd.Env = append(env, "XDG_STATE_HOME="+c.state, "XDG_RUNTIME_DIR="+runtimeDir(t), "SSH_AUTH_SOCK="+a.sock,
		"TERM=xterm-256color", "LANG=C.UTF-8")
	if err := c.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	slave.Close()
	go c.screen.collect(master)
	go func() { c.exited <- c.cmd.Wait() }()
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("%s's screen:\n%s\nits log:\n%s", name, screenOf([]byte(c.screen.String()), 100, 30), c.log())
		}
		select {
		case <-c.exited:
		default:
			c.cmd.Process.Kill()
			<-c.exited
		}
	})
	return c
}

// hopConfig is an ssh_config for an ssh run inside the session to hop to
// b, authenticating only with the agent's key (IdentitiesOnly with the
// public half names it), so it reads no key of the user's.
func hopConfig(t *testing.T, b *sshd, a *throwawayAgent) string {
	t.Helper()
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	p := filepath.Join(t.TempDir(), "hop_config")
	if err := os.WriteFile(p, []byte(fmt.Sprintf(`Host hop
  HostName 127.0.0.1
  Port %d
  User %s
  HostKeyAlias %s
  IdentityFile %s.pub
  IdentitiesOnly yes
  UserKnownHostsFile %s
  GlobalKnownHostsFile /dev/null
  StrictHostKeyChecking yes
  BatchMode yes
`, b.port, me.Username, b.alias, a.key, filepath.Join(b.dir, "known_hosts"))), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// knownByAlias is a known_hosts file naming each sshd's host key by its
// alias, for ssh-add -h's destination constraints.
func knownByAlias(t *testing.T, hosts ...*sshd) string {
	t.Helper()
	var b strings.Builder
	for _, h := range hosts {
		pub, err := os.ReadFile(filepath.Join(h.dir, "host.pub"))
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&b, "%s %s", h.alias, pub)
	}
	p := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The user's agent forwarded through a real session, with the real
// binaries and a throwaway sshd and ssh-agent (agent.md §7): the far shell
// has mosey's agent socket; ssh-add -l there lists the agent's key; an ssh
// from there to a second sshd that takes only that key is signed through
// the forwarded agent; and a key the agent holds under destination
// constraints (ssh-add -h) works for exactly the hop it allows, as under
// ssh -A, because the bind ssh sent at the bootstrap is replayed [S3 E8].
func TestTheAgentIsForwardedThroughARealSession(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	agentKeys := startAgent(t)
	hop := startSSHDWith(t, sshdOptions{alias: "mosey-hop", authorized: agentKeys.key + ".pub"})
	other := startSSHDWith(t, sshdOptions{alias: "mosey-elsewhere"})
	s := startSSHDWith(t, sshdOptions{allowAgent: true, alias: "mosey-first", clientExtra: "\n  ForwardAgent yes", identityAgent: "SSH_AUTH_SOCK"})
	mosey := buildMosey(t, "e2e")
	agentKeys.add(agentKeys.key)

	c := startAgentClient(t, "the client", mosey, s, agentKeys)
	c.shows("$")
	c.typeLine("printenv SSH_AUTH_SOCK")
	c.shows("/agent.sock")
	c.typeLine("ssh-add -l")
	c.shows(agentKeyComment)

	cfg := hopConfig(t, hop, agentKeys)
	c.typeLine(fmt.Sprintf(`ssh -F %s hop printf "hop-%%s\\n" one`, cfg))
	c.shows("hop-one")

	// Constrained to this very path: the first host, then the hop.
	known := knownByAlias(t, s, hop, other)
	agentKeys.add("-D")
	agentKeys.add("-H", known, "-h", s.alias, "-h", s.alias+">"+hop.alias, agentKeys.key)
	c.typeLine(fmt.Sprintf(`ssh -F %s hop printf "hop-%%s\\n" two`, cfg))
	c.shows("hop-two")

	// Constrained to a hop elsewhere: the agent refuses this one.
	agentKeys.add("-D")
	agentKeys.add("-H", known, "-h", s.alias, "-h", s.alias+">"+other.alias, agentKeys.key)
	c.typeLine(fmt.Sprintf(`ssh -F %s hop printf "hop-%%s\\n" three; echo hop-done`, cfg))
	c.shows("hop-done")
	if strings.Contains(screenOf([]byte(c.screen.String()), 100, 30), "hop-three") {
		t.Error("a key constrained to another hop signed this one")
	}

	c.typeLine("exit")
	if st := c.exits(); st != 0 {
		t.Errorf("exit status %d; log:\n%s", st, c.log())
	}
}

// No forwarding unless ssh would forward: with ForwardAgent off, or with
// -a over a config that turns it on, the far shell has no SSH_AUTH_SOCK
// and nothing is said about it (bootstrap.md §5).
func TestTheAgentIsNotForwardedWhenSSHWouldNotForwardIt(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	agentKeys := startAgent(t)
	agentKeys.add(agentKeys.key)
	mosey := buildMosey(t, "e2e")
	for name, c := range map[string]struct {
		opts  sshdOptions
		flags []string
	}{
		"ForwardAgent no": {sshdOptions{allowAgent: true, identityAgent: "SSH_AUTH_SOCK"}, nil},
		"-a":              {sshdOptions{allowAgent: true, clientExtra: "\n  ForwardAgent yes", identityAgent: "SSH_AUTH_SOCK"}, []string{"-a"}},
	} {
		t.Run(name, func(t *testing.T) {
			s := startSSHDWith(t, c.opts)
			cl := startAgentClient(t, name, mosey, s, agentKeys, c.flags...)
			cl.shows("$")
			cl.typeLine("printenv SSH_AUTH_SOCK; echo env-checked")
			cl.shows("env-checked")
			got := screenOf([]byte(cl.screen.String()), 100, 30)
			if strings.Contains(got, "agent.sock") || strings.Contains(got, "not forwarding") {
				t.Errorf("the screen:\n%s", got)
			}
			cl.typeLine("exit")
			cl.exits()
		})
	}
}

// A server with AllowAgentForwarding no opens no agent channel at the
// bootstrap, so there is no bind: the client says it is not forwarding
// the agent, and the session goes on without it [S3 E7].
func TestTheSessionGoesOnWithoutTheAgentWhenTheServerRefusesIt(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	agentKeys := startAgent(t)
	agentKeys.add(agentKeys.key)
	s := startSSHDWith(t, sshdOptions{clientExtra: "\n  ForwardAgent yes", identityAgent: "SSH_AUTH_SOCK"})
	mosey := buildMosey(t, "e2e")
	c := startAgentClient(t, "the client", mosey, s, agentKeys)
	c.shows("$")
	if !strings.Contains(c.screen.String(), "not forwarding the agent: the server did not open the agent channel") {
		t.Errorf("no word about the agent; the screen:\n%s", c.screen.String())
	}
	c.typeLine("ssh-add -l; echo listed")
	c.shows("listed")
	if strings.Contains(screenOf([]byte(c.screen.String()), 100, 30), agentKeyComment) {
		t.Error("the agent's key reached a session that forwards no agent")
	}
	c.typeLine("exit")
	if st := c.exits(); st != 0 {
		t.Errorf("exit status %d; log:\n%s", st, c.log())
	}
}

// OpenSSH's own choice of which agent ForwardAgent yes forwards, which
// bootstrap.md §5's table follows: the IdentityAgent socket when one is
// named, SSH_AUTH_SOCK when that is named, and none at all for
// IdentityAgent none. Checked black-box with ssh -A against the throwaway
// sshd and two throwaway agents.
func TestForwardAgentYesForwardsTheIdentityAgent(t *testing.T) {
	envAgent, idAgent := startAgent(t), startAgent(t)
	envAgent.add(envAgent.key)
	// The second agent's key, under another comment, to tell them apart.
	other := filepath.Join(t.TempDir(), "idkey")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "identity-agent-key", "-f", other).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v %s", err, out)
	}
	idAgent.add(other)
	s := startSSHDWith(t, sshdOptions{allowAgent: true})
	list := func(opts ...string) string {
		args := append([]string{"-F", s.config, "-o", "ForwardAgent=yes"}, opts...)
		args = append(args, s.host, "ssh-add -l")
		cmd := exec.Command("ssh", args...)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "SSH_AUTH_SOCK=" + envAgent.sock}
		out, _ := cmd.CombinedOutput()
		return string(out)
	}
	if got := list("-o", "IdentityAgent="+idAgent.sock); !strings.Contains(got, "identity-agent-key") {
		t.Errorf("with IdentityAgent set, the far side lists %q", got)
	}
	if got := list("-o", "IdentityAgent=SSH_AUTH_SOCK"); !strings.Contains(got, agentKeyComment) {
		t.Errorf("with IdentityAgent SSH_AUTH_SOCK, the far side lists %q", got)
	}
	// The config's IdentityAgent none: no agent goes at all.
	if got := list(); strings.Contains(got, agentKeyComment) || strings.Contains(got, "identity-agent-key") {
		t.Errorf("with IdentityAgent none, the far side lists %q", got)
	}
}

// A resume brings the resuming client's own agent: its own SSH login
// triggers its own bind (bootstrap.md §9.2 step 2), and the shell's
// SSH_AUTH_SOCK, unchanged for the shell's life, now reaches the second
// device's agent, not the first's (agent.md §4.1).
func TestAResumedSessionForwardsTheResumingClientsAgent(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	first, second := startAgent(t), startAgent(t)
	first.add(first.key)
	secondKey := filepath.Join(t.TempDir(), "secondkey")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "second-device-key", "-f", secondKey).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v %s", err, out)
	}
	second.add(secondKey)
	s := startSSHDWith(t, sshdOptions{allowAgent: true, clientExtra: "\n  ForwardAgent yes", identityAgent: "SSH_AUTH_SOCK"})
	mosey := buildMosey(t, "e2e")

	a := startAgentClient(t, "the first device", mosey, s, first)
	a.shows("$")
	a.typeLine("ssh-add -l")
	a.shows(agentKeyComment)
	a.cmd.Process.Signal(syscall.SIGHUP)
	if st := a.exits(); st != 0 {
		t.Fatalf("the first device exited %d", st)
	}

	// A plain mosey: the session the first device detached from is the
	// newest detached one (D8 R1).
	b := startAgentClient(t, "the second device", mosey, s, second)
	b.shows(agentKeyComment) // the screen as the first device left it
	b.typeLine("ssh-add -l")
	b.shows("second-device-key")
	b.typeLine("exit")
	if st := b.exits(); st != 0 {
		t.Errorf("exit status %d; log:\n%s", st, b.log())
	}
}

// Resume, agent forwarding and prediction together, with the real binaries
// through a real sshd: both devices predict on every key (`-predict
// always`; over loopback the default, adaptive, draws nothing), type
// before and after the `-r`, and the second device's screen shows what it
// typed, its own agent's key, and nothing of the first's predictions
// (prediction.md §3.1: the echo ack restarts with each attach, so the
// second device's predictions are judged against its own keystrokes).
func TestPredictionAndTheAgentBothCarryOverAResume(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	first, second := startAgent(t), startAgent(t)
	first.add(first.key)
	secondKey := filepath.Join(t.TempDir(), "secondkey")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "second-device-key", "-f", secondKey).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v %s", err, out)
	}
	second.add(secondKey)
	s := startSSHDWith(t, sshdOptions{allowAgent: true, clientExtra: "\n  ForwardAgent yes", identityAgent: "SSH_AUTH_SOCK"})
	mosey := buildMosey(t, "e2e")

	a := startAgentClient(t, "the first device", mosey, s, first, "-predict", "always")
	a.shows("$")
	a.typeLine("echo before-$((40+2))")
	a.shows("before-42")
	a.typeLine("ssh-add -l")
	a.shows(agentKeyComment)
	a.cmd.Process.Signal(syscall.SIGHUP)
	if st := a.exits(); st != 0 {
		t.Fatalf("the first device exited %d", st)
	}
	if n := predictedIn(t, a.log()); n == 0 {
		t.Errorf("the first device predicted nothing; log:\n%s", a.log())
	}

	b := startAgentClient(t, "the second device", mosey, s, second, "-predict", "always")
	b.shows("before-42") // the screen as the first device left it
	b.typeLine("echo after-$((50+3))")
	b.shows("after-53")
	b.typeLine("ssh-add -l")
	b.shows("second-device-key")
	b.typeLine("exit")
	if st := b.exits(); st != 0 {
		t.Errorf("exit status %d; log:\n%s", st, b.log())
	}
	if n := predictedIn(t, b.log()); n == 0 {
		t.Errorf("the second device predicted nothing; log:\n%s", b.log())
	}
}

// predictedIn is the Predicted count of the last prediction stats a
// client logged as it left (internal/client's session).
func predictedIn(t *testing.T, log string) int {
	t.Helper()
	all := regexp.MustCompile(`Predicted:(\d+)`).FindAllStringSubmatch(log, -1)
	if all == nil {
		t.Fatalf("no prediction stats logged:\n%s", log)
	}
	n, _ := strconv.Atoi(all[len(all)-1][1])
	return n
}
