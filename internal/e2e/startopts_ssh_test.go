//go:build linux

package e2e

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
)

// showsLine waits until a whole line of the client's screen matches re:
// output of the shell, not the command that was typed to make it.
func (c *realClient) showsLine(re string) {
	c.t.Helper()
	line := regexp.MustCompile(`(?m)^` + re + `$`)
	waitFor(c.t, c.label+" to show a line "+re, func() bool {
		return line.MatchString(screenOf([]byte(c.screen.String()), 100, 30))
	})
}

// -dir and -type through a real sshd (bootstrap.md §9.2.3), what Dan's
// tmux `new-session -c DIR` and `send-keys TEXT Enter` did:
//   - -s work -dir sub -type 'echo hi' creates session work, whose
//     shell runs in ~/sub and whose screen shows hi as output;
//   - after it detaches, -s work -dir other -type … resumes it with no
//     error though ~/other does not exist, still in ~/sub, and nothing is
//     typed;
//   - -new -dir missing is refused with the dir message, exit 1, and
//     starts no session.
func TestDirAndTypeStartASessionAndAreIgnoredOnResume(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	s := startSSHD(t)
	mosey := buildMosey(t, "e2e")
	if err := os.Mkdir(filepath.Join(s.home, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}

	first := startClient(t, "the first client", mosey, s, "-s", "work", "-dir", "sub", "-type", "echo hi")
	first.showsLine(`hi`)
	first.typeLine(`echo at-${PWD#"$HOME"}`)
	first.showsLine(`at-/sub`)
	if got := first.name(); got != "work" {
		t.Errorf("the session is %s, not work", got)
	}
	first.cmd.Process.Signal(syscall.SIGHUP)
	if status := first.exits(); status != 0 {
		t.Fatalf("the first client exited %d after SIGHUP, not 0; log:\n%s", status, first.log())
	}

	second := startClient(t, "the second client", mosey, s, "-s", "work", "-dir", "other", "-type", "echo typed-again")
	second.typeLine(`echo still-${PWD#"$HOME"}`)
	second.showsLine(`still-/sub`)
	// -type's text would have been in the shell's input before the line
	// just typed, so by now it would show.
	if screen := screenOf([]byte(second.screen.String()), 100, 30); strings.Contains(screen, "typed-again") {
		t.Errorf("resuming typed -type's text into the session:\n%s", screen)
	}
	if n := len(spawners(mosey)); n != 1 {
		t.Errorf("%d sessions after the resume, want 1", n)
	}

	third := startClient(t, "the third client", mosey, s, "-new", "-dir", "missing")
	if status := third.exits(); status != 1 {
		t.Errorf("-new -dir missing exited %d, not 1; log:\n%s", status, third.log())
	}
	third.shows("missing is not a directory on " + s.host + ", so no session was started")
	if n := len(spawners(mosey)); n != 1 {
		t.Errorf("%d sessions after a refused -dir, want 1", n)
	}

	second.typeLine("exit")
	if status := second.exits(); status != 0 {
		t.Errorf("the second client exited %d after exit, not 0; log:\n%s", status, second.log())
	}
	waitFor(t, "the session to end", func() bool { return len(spawners(mosey)) == 0 })
}
