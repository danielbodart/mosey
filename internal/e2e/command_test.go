//go:build linux

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mosey localhost COMMAND runs the command in place of the shell, as ssh
// HOST COMMAND would (Dan, 2026-11-16; bootstrap.md §2, §9.2.3), with no
// sshd:
//   - the words are joined with spaces and read by the user's shell, so
//     its $((…)) is expanded, and the session and the client end when it
//     exits, with status 0, whatever the command's;
//   - the command's own flags are its own, quotes are its shell's, and
//     -dir is where it runs;
//   - -s NAME with NAME running takes it as it is, and says the command
//     was not run.
func TestALocalCommandRunsInPlaceOfTheShellAndItsEndEndsTheClient(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	m := newMachine(t)
	mosey := buildMosey(t, "e2e")

	ran := startLocal(t, "a client running a command", mosey, m, "", nil, "echo", "ran-$((6*7));", "exit", "3")
	ran.shows("ran-42")
	if st := ran.exits(); st != 0 {
		t.Errorf("the client exited %d when its command did, not 0", st)
	}

	if err := os.Mkdir(filepath.Join(m.home, "work"), 0o700); err != nil {
		t.Fatal(err)
	}
	words := startLocal(t, "a client running a command with flags", mosey, m, "", []string{"-dir", "work"},
		"printf", "'%s|%s|%s\\n'", "\"$(pwd)\"", "'a  b'", "-la")
	words.shows(filepath.Join(m.home, "work") + "|a  b|-la")
	if st := words.exits(); st != 0 {
		t.Errorf("the client exited %d, not 0", st)
	}

	shell := startLocal(t, "an interactive client", mosey, m, "", []string{"-s", "work"})
	shell.shows("$")
	shell.typeLine("M=kept-$((40+2)); echo set-$((1+1))")
	shell.shows("set-2")
	taker := startLocal(t, "a client naming a running session", mosey, m, "", []string{"-s", "work"}, "echo", "never-$((6*7))")
	// Said on stderr before the screen is drawn over it.
	waitFor(t, "the notice that the command was not run", func() bool {
		return strings.Contains(taker.screen.String(), "mosey: session work was already running, so the command was not run")
	})
	if st := shell.exits(); st != 3 {
		t.Errorf("the taken client exited %d, not 3", st)
	}
	taker.typeLine("echo got-$M")
	taker.shows("got-kept-42")
	if strings.Contains(taker.screen.String(), "never-42") {
		t.Error("the command ran in a session that was already running")
	}
	taker.typeLine("exit")
	if st := taker.exits(); st != 0 {
		t.Errorf("the taker exited %d, not 0", st)
	}
	waitFor(t, "every session's processes to end", func() bool { return len(spawners(mosey)) == 0 })
}

// The same through a real sshd: mosey HOST COMMAND runs it there and
// exits when it does (bootstrap.md §9.2.3).
func TestACommandOverSSHRunsThereAndEndsTheClient(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	s := startSSHD(t)
	mosey := buildMosey(t, "e2e")

	c := startCommand(t, "a client running a command over ssh", mosey, s, nil, "echo", "far-$((6*7))", "-n")
	c.shows("far-42 -n")
	if st := c.exits(); st != 0 {
		t.Errorf("the client exited %d when its command did, not 0", st)
	}
	if out, _ := moseyCmd(t, mosey, s, "-list"); !strings.Contains(out, "no sessions on") {
		t.Errorf("mosey -list after the command:\n%s", out)
	}
}
