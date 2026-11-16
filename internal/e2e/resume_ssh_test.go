//go:build linux

package e2e

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/danielbodart/mosey/internal/bootstrap"
)

// realClient is the real mosey client binary on a pty of its own, as a
// user at a terminal runs it.
type realClient struct {
	t      *testing.T
	label  string
	cmd    *exec.Cmd
	master *os.File
	screen *screenLog
	exited chan error
	state  string
}

func startClient(t *testing.T, name, mosey string, s *sshd, flags ...string) *realClient {
	t.Helper()
	return startCommand(t, name, mosey, s, flags)
}

// startCommand is startClient with words after the host: a command
// (bootstrap.md §2, §9.2.3).
func startCommand(t *testing.T, name, mosey string, s *sshd, flags []string, words ...string) *realClient {
	t.Helper()
	master, slave := openPTY(t)
	c := &realClient{t: t, label: name, master: master, screen: &screenLog{}, exited: make(chan error, 1), state: t.TempDir()}
	args := append(append(append([]string{}, flags...), "-remote", mosey, "--", "-F", s.config, s.host), words...)
	c.cmd = exec.Command(mosey, args...)
	c.cmd.Stdin, c.cmd.Stdout, c.cmd.Stderr = slave, slave, slave
	c.cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
	c.cmd.Env = append(os.Environ(), "XDG_STATE_HOME="+c.state, "TERM=xterm-256color", "LANG=C.UTF-8")
	if err := c.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	slave.Close()
	go c.screen.collect(master)
	go func() { c.exited <- c.cmd.Wait() }()
	t.Cleanup(func() {
		select {
		case <-c.exited:
		default:
			c.cmd.Process.Kill()
			<-c.exited
		}
	})
	return c
}

// shows waits until the client's screen, as a terminal would draw it,
// holds want.
func (c *realClient) shows(want string) {
	c.t.Helper()
	waitFor(c.t, c.label+" to show "+want, func() bool {
		return strings.Contains(screenOf([]byte(c.screen.String()), 100, 30), want)
	})
}

func (c *realClient) typeLine(line string) {
	c.t.Helper()
	if _, err := c.master.Write([]byte(line + "\r")); err != nil {
		c.t.Fatal(err)
	}
}

// exits waits for the client to exit and returns its status.
func (c *realClient) exits() int {
	c.t.Helper()
	var err error
	waitFor(c.t, c.label+" to exit", func() bool {
		select {
		case err = <-c.exited:
			c.exited <- err
			return true
		default:
			return false
		}
	})
	return bootstrap.ExitStatus(err)
}

func (c *realClient) log() string {
	return readFile(filepath.Join(c.state, "mosey", "client.log"))
}

var (
	detachedFrom = regexp.MustCompile(`detached from session ([A-Za-z0-9._-]+); resume it with: mosey -s ([A-Za-z0-9._-]+) `)
	sessionName  = regexp.MustCompile(`msg=session name=([A-Za-z0-9._-]+)`)
)

// name is the session the client is in, from its log.
func (c *realClient) name() string {
	c.t.Helper()
	var m []string
	waitFor(c.t, c.label+"'s session name", func() bool {
		m = sessionName.FindStringSubmatch(c.log())
		return m != nil
	})
	return m[1]
}

// spawners is every spawner of the binary at path that is running.
func spawners(path string) []int {
	var found []int
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		argv, _ := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if args := bytes.Split(argv, []byte{0}); len(args) > 1 && string(args[0]) == path && string(args[1]) == "--serve=spawner" && running(pid) {
			found = append(found, pid)
		}
	}
	return found
}

func moseyCmd(t *testing.T, mosey string, s *sshd, args ...string) (string, int) {
	t.Helper()
	all := append(append([]string{}, args...), "-remote", mosey, "--", "-F", s.config, s.host)
	cmd := exec.Command(mosey, all...)
	cmd.Env = append(os.Environ(), "XDG_STATE_HOME="+t.TempDir())
	out, err := cmd.CombinedOutput()
	return string(out), bootstrap.ExitStatus(err)
}

// Sessions end to end with the real binaries through a real sshd (D8 R1,
// R2, R4; D26; bootstrap.md §9, §12):
//   - a plain client starts a session; a second plain client, the first
//     still attached, gets a new session of its own;
//   - the first, sent SIGHUP as a closed terminal would, detaches, names
//     its session and exits 0, and the session runs on;
//   - a third plain client resumes that session (a variable set in it is
//     still set): the newest detached one, never the attached second;
//   - -s NAME takes it over: the third exits 3 saying who took it;
//   - -new starts a session with a generated name; -list shows every name
//     and state; -kill NAME ends the second, whose client exits 0;
//   - exit in the others ends them, their clients exit 0, and nothing of
//     any session is left running.
func TestSessionsThroughRealSSH(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	s := startSSHD(t)
	mosey := buildMosey(t, "e2e")

	first := startClient(t, "the first client", mosey, s)
	first.shows("$")
	first.typeLine("M=kept-$((40+2)); echo set-$((1+1))")
	first.shows("set-2")
	name := first.name()

	second := startClient(t, "the second client", mosey, s)
	second.shows("$")
	second.typeLine("echo second-${M:-unset}")
	second.shows("second-unset") // a session of its own, not the first's
	other := second.name()
	if other == name {
		t.Fatalf("the second plain client got the first's session %s", name)
	}
	if n := len(spawners(mosey)); n != 2 {
		t.Fatalf("%d sessions, want 2", n)
	}

	first.cmd.Process.Signal(syscall.SIGHUP)
	if status := first.exits(); status != 0 {
		t.Errorf("the first client exited %d after SIGHUP, not 0; log:\n%s", status, first.log())
	}
	if m := detachedFrom.FindStringSubmatch(first.screen.String()); m == nil || m[1] != name || m[2] != name {
		t.Errorf("the first client did not say it detached from %s:\n%s", name, first.screen.String())
	}

	third := startClient(t, "the third client", mosey, s)
	third.shows("set-2") // the whole screen, as the shell left it
	third.typeLine("echo got-$M")
	third.shows("got-kept-42")
	if got := third.name(); got != name {
		t.Errorf("the third plain client resumed %s, not the detached %s", got, name)
	}

	fourth := startClient(t, "the fourth client", mosey, s, "-s", name)
	fourth.shows("got-kept-42")
	if status := third.exits(); status != 3 {
		t.Errorf("the third client exited %d, not 3; log:\n%s", status, third.log())
	}
	third.shows("session taken over from 127.0.0.1:")

	fifth := startClient(t, "the fifth client", mosey, s, "-new")
	fifth.shows("$")
	fifth.typeLine("echo fifth-${M:-unset}")
	fifth.shows("fifth-unset")
	fresh := fifth.name()
	if fresh == name || fresh == other {
		t.Errorf("-new joined %s", fresh)
	}

	out, status := moseyCmd(t, mosey, s, "-list")
	if status != 0 {
		t.Fatalf("mosey -list exited %d:\n%s", status, out)
	}
	for _, n := range []string{name, other, fresh} {
		if !regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(n) + `\s+attached\s+\d{4}-\d\d-\d\dT\S+\s*$`).MatchString(out) {
			t.Errorf("mosey -list does not show %s attached:\n%s", n, out)
		}
	}

	out, status = moseyCmd(t, mosey, s, "-kill", other)
	if status != 0 || !strings.Contains(out, "ended session "+other) {
		t.Errorf("mosey -kill %s exited %d:\n%s", other, status, out)
	}
	if status := second.exits(); status != 0 {
		t.Errorf("the killed session's client exited %d, not 0; log:\n%s", status, second.log())
	}
	waitFor(t, "the killed session to end", func() bool { return len(spawners(mosey)) == 2 })
	if out, status := moseyCmd(t, mosey, s, "-kill", other); status != 1 || !strings.Contains(out, "no session called "+other) {
		t.Errorf("a second -kill %s exited %d:\n%s", other, status, out)
	}

	for _, c := range []*realClient{fourth, fifth} {
		c.typeLine("exit")
		if status := c.exits(); status != 0 {
			t.Errorf("%s exited %d after exit, not 0; log:\n%s", c.label, status, c.log())
		}
	}
	waitFor(t, "every session's processes to end", func() bool { return len(spawners(mosey)) == 0 })
	if entries, _ := os.ReadDir(filepath.Join(s.runtime, "mosey")); len(entries) != 1 || entries[0].Name() != "lock" {
		t.Errorf("the ended sessions left %v in the runtime directory", entries)
	}
	if out, _ := moseyCmd(t, mosey, s, "-list"); !strings.Contains(out, "no sessions on "+s.host) {
		t.Errorf("mosey -list after the end:\n%s", out)
	}
}
