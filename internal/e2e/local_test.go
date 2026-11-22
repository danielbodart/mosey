//go:build linux

package e2e

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/danielbodart/mosey/internal/bootstrap"
)

// thisMachine is what a local mosey (localhost, bootstrap.md §2.2)
// sees of the machine it runs on: a home, a runtime directory for the
// attach sockets and a login shell, all the test's own, so nothing
// touches the user's sessions, agent or rc files (CLAUDE.md).
type thisMachine struct {
	home, runtime string
}

func newMachine(t *testing.T) *thisMachine {
	t.Helper()
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	return &thisMachine{home: t.TempDir(), runtime: runtimeDir(t)}
}

// env is the client's environment on this machine: the test's own, less
// anything of the user's that a session would use, plus the machine's
// directories, and the agent socket if one is given. Local mode passes
// the client's SSH_AUTH_SOCK to the session on purpose (bootstrap.md
// §2.2), so it is only ever the throwaway agent's, or unset, and the
// login shell reads no system environment that could name another.
func (m *thisMachine) env(state, agentSock string) []string {
	agent := "SSH_AUTH_SOCK"
	if agentSock != "" {
		agent += "=" + agentSock
	}
	return childEnv("XDG_CONFIG_HOME", "ENV", "BASH_ENV", agent,
		"HOME="+m.home, "XDG_RUNTIME_DIR="+m.runtime, "XDG_STATE_HOME="+state,
		"SHELL=/bin/sh", "TERM=xterm-256color", "LANG=C.UTF-8", noSystemEnvironment)
}

// startLocal is the real mosey client given flags and then localhost, and
// after it any words, on a pty of its own, as a user at a terminal on this
// machine runs it.
func startLocal(t *testing.T, name, mosey string, m *thisMachine, agentSock string, flags []string, words ...string) *realClient {
	t.Helper()
	return startLocalTTY(t, true, name, mosey, m, agentSock, flags, words...)
}

// startLocalTTY is startLocal with the pty its controlling terminal or
// not. Without one, closing the master reaches the client only as EIO on
// its reads, never as SIGHUP, which pins the path a closed window takes
// when its EIO beats its SIGHUP.
func startLocalTTY(t *testing.T, ctty bool, name, mosey string, m *thisMachine, agentSock string, flags []string, words ...string) *realClient {
	t.Helper()
	master, slave := openPTY(t)
	c := &realClient{t: t, label: name, master: master, screen: &screenLog{}, exited: make(chan error, 1), state: t.TempDir()}
	c.cmd = command(mosey, append(append(slices.Clone(flags), "localhost"), words...)...)
	c.cmd.Stdin, c.cmd.Stdout, c.cmd.Stderr = slave, slave, slave
	c.cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: ctty}
	c.cmd.Env = m.env(c.state, agentSock)
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

// localCmd runs a local mosey that does not attach (-list, -kill), with
// no DESTINATION, which is this machine (bootstrap.md §2.2), and returns
// what it printed and its exit status.
func localCmd(t *testing.T, mosey string, m *thisMachine, args ...string) (string, int) {
	t.Helper()
	cmd := command(mosey, args...)
	cmd.Env = m.env(t.TempDir(), "")
	out, err := cmd.CombinedOutput()
	return string(out), bootstrap.ExitStatus(err)
}

var detachedHere = regexp.MustCompile(`detached from session ([A-Za-z0-9._-]+); resume it with: mosey -s ([A-Za-z0-9._-]+)\r?\n`)

// mosey localhost is this machine, with no ssh at all (no sshd is
// started; bootstrap.md §2.2), and is the same session life as over
// ssh: a plain client starts a session and runs its shell, with the
// prediction path drawing typing ahead of the echo; closing its terminal
// detaches and names the session with a hint that names localhost; -list
// shows it detached; -s NAME reattaches it, the shell's state intact;
// -kill ends another; and exit ends the session and leaves nothing.
func TestALocalSessionStartsDetachesListsAndReattachesWithNoSSH(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	m := newMachine(t)
	mosey := buildMosey(t, "e2e")

	first := startLocal(t, "the first local client", mosey, m, "", []string{"-predict", "always"})
	first.shows("$")
	first.typeLine("mkdir proj; cd proj; M=kept-$((40+2)); echo set-$((1+1))")
	first.shows("set-2")
	name := first.name()
	// mosey localhost is this machine: the tab is not marked remote
	// (screen.md §8.8).
	if strings.Contains(first.screen.String(), "vte.ext.mosey") {
		t.Errorf("a local session marked the tab:\n%q", first.screen.String())
	}

	first.cmd.Process.Signal(syscall.SIGHUP)
	if status := first.exits(); status != 0 {
		t.Fatalf("the first client exited %d after SIGHUP, not 0", status)
	}
	if m := detachedHere.FindStringSubmatch(first.screen.String()); m == nil || m[1] != name || m[2] != name {
		t.Errorf("the first client did not say how to come back to %s here:\n%q", name, first.screen.String())
	}
	if n := predictedIn(t, first.log()); n == 0 {
		t.Errorf("the local client predicted nothing; log:\n%s", first.log())
	}

	// -list shows what runs in it and where (bootstrap.md §9.4): the
	// shell, at its prompt, in the directory it went to.
	out, status := localCmd(t, mosey, m, "-list")
	if status != 0 || !regexp.MustCompile(`(?m)^`+regexp.QuoteMeta(name)+`\s+detached\s+\d{4}-\S+\s+sh\s+~/proj$`).MatchString(out) ||
		!strings.Contains(out, "attach to one with: mosey -s NAME\n") {
		t.Fatalf("mosey -list exited %d:\n%s", status, out)
	}

	second := startLocal(t, "the second local client", mosey, m, "", []string{"-s", name})
	second.shows("set-2") // the screen as the shell left it
	second.typeLine("echo got-$M")
	second.shows("got-kept-42")
	if got := second.name(); got != name {
		t.Errorf("-s %s attached %s", name, got)
	}

	// -dir names no directory yet: nothing is started, and the client
	// says where it looked.
	none := startLocal(t, "a client given no directory", mosey, m, "", []string{"-new", "-dir", "work"})
	if status := none.exits(); status != 1 || !strings.Contains(none.screen.String(), "work is not a directory on localhost") {
		t.Errorf("-dir of no directory exited %d:\n%s", status, none.screen.String())
	}
	if err := os.Mkdir(filepath.Join(m.home, "work"), 0o700); err != nil {
		t.Fatal(err)
	}
	third := startLocal(t, "the third local client", mosey, m, "", []string{"-new", "-dir", "work", "-type", "echo typed-$((6*7)); pwd"})
	third.shows("typed-42")
	third.shows(filepath.Join(m.home, "work"))
	fresh := third.name()
	// A job the shell runs is what -list shows of it.
	third.typeLine("sleep 1000")
	waitFor(t, "-list to show the sleep", func() bool {
		out, _ := localCmd(t, mosey, m, "-list")
		return regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(fresh) + `\s+attached\s+\S+\s+127\.0\.0\.1\s+sleep\s+~/work$`).MatchString(out)
	})
	if out, status := localCmd(t, mosey, m, "-kill", fresh); status != 0 || !strings.Contains(out, "ended session "+fresh+" on localhost") {
		t.Errorf("mosey -kill %s exited %d:\n%s", fresh, status, out)
	}
	if status := third.exits(); status != 0 {
		t.Errorf("the killed session's client exited %d, not 0", status)
	}

	second.typeLine("exit")
	if status := second.exits(); status != 0 {
		t.Errorf("the second client exited %d after exit, not 0", status)
	}
	waitFor(t, "every session's processes to end", func() bool { return len(spawners(mosey)) == 0 })
	if out, _ := localCmd(t, mosey, m, "-list"); !strings.Contains(out, "no sessions on localhost") {
		t.Errorf("mosey -list after the end:\n%s", out)
	}
}

// A local session's shell has the client's own agent, through the
// session's agent socket, as a shell in that terminal would; -a gives it
// none (bootstrap.md §2.2). The agent is a throwaway one.
func TestALocalSessionHasTheTerminalsAgentUnlessToldNot(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	keys := startAgent(t)
	keys.add(keys.key)
	m := newMachine(t)
	mosey := buildMosey(t, "e2e")

	c := startLocal(t, "the local client", mosey, m, keys.sock, nil)
	c.shows("$")
	c.typeLine("printenv SSH_AUTH_SOCK; ssh-add -l")
	c.shows(agentKeyComment)
	if strings.Contains(c.screen.String(), keys.sock) {
		t.Error("the shell has the client's agent socket itself, not the session's")
	}
	c.typeLine("exit")
	if st := c.exits(); st != 0 {
		t.Errorf("exit status %d", st)
	}

	off := startLocal(t, "the local client with -a", mosey, m, keys.sock, []string{"-a"})
	off.shows("$")
	off.typeLine("echo agent-${SSH_AUTH_SOCK:-none}")
	off.shows("agent-none")
	off.typeLine("exit")
	if st := off.exits(); st != 0 {
		t.Errorf("exit status %d", st)
	}
}

// A session started here with no ssh is one of this user's sessions on
// this host like any other (bootstrap.md §2.2): mosey -list over ssh to
// this host shows it, and mosey -s NAME HOST takes it from "another
// device", whose taking the local client is told of.
func TestALocalSessionCanBeTakenOverSSHFromElsewhere(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	s := startSSHD(t)
	m := &thisMachine{home: s.home, runtime: s.runtime}
	mosey := buildMosey(t, "e2e")

	local := startLocal(t, "the local client", mosey, m, "", nil)
	local.shows("$")
	local.typeLine("M=here-$((40+2))")
	name := local.name()

	out, status := moseyCmd(t, mosey, s, "-list")
	if status != 0 || !regexp.MustCompile(`(?m)^`+regexp.QuoteMeta(name)+`\s+attached\s`).MatchString(out) {
		t.Fatalf("mosey -list over ssh exited %d:\n%s", status, out)
	}

	far := startClient(t, "the client over ssh", mosey, s, "-s", name)
	far.typeLine("echo far-$M")
	far.shows("far-here-42")
	if status := local.exits(); status != 3 {
		t.Errorf("the local client exited %d, not 3", status)
	}
	local.shows("session taken over from 127.0.0.1:")
	far.typeLine("exit")
	if st := far.exits(); st != 0 {
		t.Errorf("exit status %d", st)
	}
}
