//go:build linux

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"

	"github.com/danielbodart/mosey/internal/bootstrap"
)

// realClient is the real mosey client binary on a pty of its own, as a
// user at a terminal runs it.
type realClient struct {
	t      *testing.T
	name   string
	cmd    *exec.Cmd
	master *os.File
	screen *screenLog
	exited chan error
	state  string
}

func startClient(t *testing.T, name, mosey string, s *sshd, flags ...string) *realClient {
	t.Helper()
	master, slave := openPTY(t)
	c := &realClient{t: t, name: name, master: master, screen: &screenLog{}, exited: make(chan error, 1), state: t.TempDir()}
	args := append(append([]string{}, flags...), "-remote", mosey, "--", "-F", s.config, s.host)
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
	waitFor(c.t, c.name+" to show "+want, func() bool {
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
	waitFor(c.t, c.name+" to exit", func() bool {
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

var detachedFrom = regexp.MustCompile(`detached from session ([0-9a-f]{32})`)

// Resume end to end with the real binaries through a real sshd (D8, D26;
// bootstrap.md §12): a session started on one terminal is taken over by
// `mosey -r` on another, whose shell is the same one (a variable set in
// the first is still set); the first client exits 3 saying who took it.
// The second, sent SIGHUP as a closed terminal would, detaches and exits
// 0; `mosey -list` shows the session detached; `mosey -r=SESSION` resumes
// it once more, and `exit` there ends it, leaving nothing running.
func TestResumeTakeOverDetachAndListThroughRealSSH(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	s := startSSHD(t)
	mosey := buildMosey(t, "e2e")

	first := startClient(t, "the first client", mosey, s)
	first.shows("$")
	first.typeLine("M=resumed-$((40+2)); echo set-$((1+1))")
	first.shows("set-2")
	spawner := findSpawner(t, mosey)

	second := startClient(t, "the second client", mosey, s, "-r")
	second.shows("set-2") // the whole screen, as the shell left it
	if status := first.exits(); status != 3 {
		t.Errorf("the first client exited %d, not 3; log:\n%s", status, first.log())
	}
	first.shows("session taken over from 127.0.0.1:")
	second.typeLine("echo got-$M")
	second.shows("got-resumed-42")

	second.cmd.Process.Signal(syscall.SIGHUP)
	if status := second.exits(); status != 0 {
		t.Errorf("the second client exited %d after SIGHUP, not 0; log:\n%s", status, second.log())
	}
	m := detachedFrom.FindStringSubmatch(second.screen.String())
	if m == nil {
		t.Fatalf("the second client did not say what it detached from:\n%s", second.screen.String())
	}
	sid := m[1]
	if !running(spawner) {
		t.Fatal("the session ended when its client detached")
	}

	out, err := exec.Command(mosey, "-list", "-remote", mosey, "--", "-F", s.config, s.host).CombinedOutput()
	if err != nil {
		t.Fatalf("mosey -list: %v\n%s", err, out)
	}
	if !regexp.MustCompile(sid + `\s+detached\s`).Match(out) {
		t.Errorf("mosey -list does not show %s detached:\n%s", sid, out)
	}

	third := startClient(t, "the third client", mosey, s, "-r="+sid)
	third.shows("got-resumed-42")
	third.typeLine("exit")
	if status := third.exits(); status != 0 {
		t.Errorf("the third client exited %d after exit, not 0; log:\n%s", status, third.log())
	}
	waitFor(t, "the session's processes to end", func() bool { return !running(spawner) })
	if entries, _ := os.ReadDir(filepath.Join(s.runtime, "mosey")); len(entries) != 0 {
		t.Errorf("the ended session left %v in its runtime directory", entries)
	}

	// Nothing left to resume.
	none := startClient(t, "a resume of nothing", mosey, s, "-r")
	if status := none.exits(); status != 1 {
		t.Errorf("a resume with no session exited %d, not 1", status)
	}
	none.shows(fmt.Sprintf("no session to resume on %s", s.host))
}
