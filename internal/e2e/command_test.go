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
	// The directory is printed relative to $HOME, so the line is short
	// enough never to wrap whatever the temporary directory's name: a
	// full path under a long TMPDIR wrapped at the screen's 100 columns.
	words := startLocal(t, "a client running a command with flags", mosey, m, "", []string{"-dir", "work"},
		"printf", "'%s|%s|%s\\n'", "\"in:${PWD#\"$HOME\"/}\"", "'a  b'", "-la")
	words.shows("in:work|a  b|-la")
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

// mosey localhost COMMAND is R1 keyed by the command (PLAN D8, Dan,
// 2026-11-16, option C; bootstrap.md §9.2.3), with no sshd:
//   - closed and run again, the same line returns to the same session,
//     its state intact, though a shell session was detached since;
//   - -list shows the command;
//   - while it is attached, the same line gets a second session;
//   - a plain mosey localhost never takes the detached command session,
//     nor mosey localhost COMMAND a detached shell, which a plain mosey
//     localhost then does take.
//
// The command is sh, an interactive shell of its own, so it has state
// to keep and reads typed lines (CI's /bin/sh is dash).
func TestALocalCommandIsReturnedToAfterADetachAndNeverMixedWithAShell(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	m := newMachine(t)
	mosey := buildMosey(t, "e2e")

	first := startLocal(t, "the first sh client", mosey, m, "", nil, "sh")
	first.shows("$")
	first.typeLine("M=kept-$((40+2)); echo set-$((1+1))")
	first.shows("set-2")
	ai := first.name()
	first.cmd.Process.Signal(syscall.SIGHUP)
	if st := first.exits(); st != 0 {
		t.Fatalf("the first sh client exited %d after SIGHUP, not 0", st)
	}

	out, st := localCmd(t, mosey, m, "-list")
	if st != 0 || !regexp.MustCompile(`(?m)^`+regexp.QuoteMeta(ai)+`\s+detached\s+\S+\s+sh$`).MatchString(out) ||
		!regexp.MustCompile(`(?m)^NAME\s+STATE\s+SINCE\s+COMMAND$`).MatchString(out) {
		t.Fatalf("mosey -list exited %d, without %s and its command:\n%s", st, ai, out)
	}

	// A plain client passes over the detached sh and starts a shell,
	// which is then detached more recently than the sh.
	plain := startLocal(t, "a plain client", mosey, m, "", nil)
	plain.shows("$")
	shell := plain.name()
	if shell == ai {
		t.Fatalf("a plain mosey localhost took %s, the detached sh", ai)
	}
	plain.cmd.Process.Signal(syscall.SIGHUP)
	if st := plain.exits(); st != 0 {
		t.Fatalf("the plain client exited %d after SIGHUP, not 0", st)
	}

	again := startLocal(t, "the same sh line again", mosey, m, "", nil, "sh")
	if got := again.name(); got != ai {
		t.Fatalf("mosey localhost sh went to %s, not back to %s", got, ai)
	}
	again.typeLine("echo got-$M")
	again.shows("got-kept-42")
	if strings.Contains(again.screen.String(), "was already running") {
		t.Errorf("returning to its own command said it was not run:\n%s", again.screen.String())
	}

	// That one attached: a second window gets a second sh, not the
	// attached one and not the detached shell.
	second := startLocal(t, "a second sh window", mosey, m, "", nil, "sh")
	second.shows("$")
	if got := second.name(); got == ai || got == shell {
		t.Fatalf("a second mosey localhost sh took %s", got)
	}
	second.typeLine("exit")
	if st := second.exits(); st != 0 {
		t.Errorf("the second sh client exited %d, not 0", st)
	}
	again.typeLine("exit")
	if st := again.exits(); st != 0 {
		t.Errorf("the returning sh client exited %d, not 0", st)
	}

	back := startLocal(t, "a plain client again", mosey, m, "", nil)
	if got := back.name(); got != shell {
		t.Fatalf("a plain mosey localhost went to %s, not back to the shell %s", got, shell)
	}
	back.typeLine("exit")
	if st := back.exits(); st != 0 {
		t.Errorf("the plain client exited %d, not 0", st)
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
