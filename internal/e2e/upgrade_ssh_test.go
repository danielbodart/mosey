//go:build linux

package e2e

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// roles is every running process of the binary at path in role (proto,
// emu, spawner), by its argv: those that hold a secret are not dumpable,
// so their exe link is not ours to read (threat-model.md §4.10).
func roles(path, role string) []int {
	var found []int
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		argv, _ := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if args := bytes.Split(argv, []byte{0}); len(args) > 1 && string(args[0]) == path &&
			string(args[1]) == "--serve="+role && running(pid) {
			found = append(found, pid)
		}
	}
	return found
}

// sessionLogs is every server log under the throwaway sshd's home, for a
// failure's message.
func sessionLogs(s *sshd) string {
	var b strings.Builder
	filepath.WalkDir(s.home, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(path, ".log") {
			b.WriteString("== " + path + "\n" + readFile(path) + "\n")
		}
		return nil
	})
	return b.String()
}

var shellPid = regexp.MustCompile(`shell-pid-(\d+)`)

// A live upgrade end to end (D8 V2, server.md §2.8), with two builds of
// cmd/mosey that differ only in their version, through a real sshd:
//   - a session started by the older build is resumed by the newer: the
//     shell is the same process (same pid) with its state (a variable)
//     intact, the client sees the whole screen the shell left, the older
//     build's spawner, proto and emu have exited, and the newer's serve
//     the session, with the shell no longer the old spawner's child;
//   - the older build then resumes the upgraded session: it attaches, and
//     the session still runs the newer build (no downgrade, D8 V2), and
//     -list says so;
//   - exit ends it, and nothing of either build is left running.
func TestALiveUpgradeKeepsTheShellAndOnlyGoesForward(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	s := startSSHD(t)
	older := buildMosey(t, "0.1.1")
	newer := buildMosey(t, "0.2.1")
	defer func() {
		if t.Failed() {
			t.Logf("server logs:\n%s", sessionLogs(s))
		}
	}()

	first := startClient(t, "the older client", older, s)
	first.shows("$")
	first.typeLine("KEPT=yes-$((40+2)); echo shell-pid-$$")
	first.shows("shell-pid-")
	m := shellPid.FindStringSubmatch(screenOf([]byte(first.screen.String()), 100, 30))
	if m == nil {
		t.Fatal("no shell pid on the screen")
	}
	pid, _ := strconv.Atoi(m[1])
	name := first.name()
	oldSpawner, oldProto, oldEmu := roles(older, "spawner"), roles(older, "proto"), roles(older, "emu")
	if len(oldSpawner) != 1 || len(oldProto) != 1 || len(oldEmu) != 1 {
		t.Fatalf("the older build runs spawners %v, protos %v, emus %v", oldSpawner, oldProto, oldEmu)
	}
	if ppid, _ := parentOf(pid); ppid != oldSpawner[0] {
		t.Fatalf("the shell %d is not the older spawner's child", pid)
	}
	first.cmd.Process.Signal(syscall.SIGHUP)
	if status := first.exits(); status != 0 {
		t.Fatalf("the older client exited %d after SIGHUP; log:\n%s", status, first.log())
	}

	second := startClient(t, "the newer client", newer, s)
	// The whole screen as the shell left it: the old session's snapshot,
	// painted into the new emu.
	second.shows("shell-pid-" + m[1])
	second.typeLine("echo got-$KEPT-pid-$$")
	second.shows("got-yes-42-pid-" + m[1])
	if got := second.name(); got != name {
		t.Errorf("the newer client resumed %s, not %s", got, name)
	}
	defer func() {
		if t.Failed() {
			t.Logf("the newer client's log:\n%s", second.log())
		}
	}()
	waitFor(t, "the older build's spawner, proto and emu to exit", func() bool {
		return !running(oldSpawner[0]) && !running(oldProto[0]) && !running(oldEmu[0])
	})
	if !running(pid) {
		t.Fatal("the shell did not survive the upgrade")
	}
	if n := len(roles(newer, "spawner")); n != 1 || len(roles(newer, "proto")) != 1 || len(roles(newer, "emu")) != 1 {
		t.Errorf("the newer build does not serve the session: %d spawners", n)
	}
	if ppid, _ := parentOf(pid); ppid == oldSpawner[0] {
		t.Error("the shell's parent is still the old spawner")
	}

	second.cmd.Process.Signal(syscall.SIGHUP)
	if status := second.exits(); status != 0 {
		t.Fatalf("the newer client exited %d after SIGHUP; log:\n%s", status, second.log())
	}
	third := startClient(t, "the older client again", older, s)
	third.shows("got-yes-42-pid-" + m[1])
	third.typeLine("echo again-$KEPT-pid-$$")
	third.shows("again-yes-42-pid-" + m[1])
	if n := len(roles(older, "spawner")) + len(roles(older, "proto")); n != 0 {
		t.Errorf("the older build serves the session again: %d of its roles run", n)
	}
	if len(roles(newer, "spawner")) != 1 {
		t.Error("the newer build no longer serves the session")
	}
	out, status := moseyCmd(t, older, s, "-list")
	if status != 0 || !regexp.MustCompile(`(?m)^`+regexp.QuoteMeta(name)+`\s+attached\s+\S+\s+0\.2\.1\s*$`).MatchString(out) {
		t.Errorf("-list from the older build does not show %s running 0.2.1:\n%s", name, out)
	}

	third.typeLine("exit")
	if status := third.exits(); status != 0 {
		t.Errorf("the older client exited %d after exit; log:\n%s", status, third.log())
	}
	waitFor(t, "every process of the session to end", func() bool {
		return !running(pid) && len(roles(newer, "spawner")) == 0 && len(roles(older, "spawner")) == 0
	})
}

// A chain of live upgrades, with an agent and a takeover (server.md
// §2.8), through a real sshd and three builds:
//   - the oldest build's session forwards the agent; the middle build
//     takes it over with -s NAME while the first client is attached, so
//     that client is told at once that the session was taken over
//     (D26), and the agent socket the shell knows still reaches an agent;
//   - the newest build then resumes it with a plain mosey, upgrading a
//     session that was itself adopted: a second hand-off, from a spawner
//     that is not the shell's parent and holds only a pidfd for it;
//   - the shell is the same process throughout, and exit ends it all.
func TestAChainOfUpgradesKeepsTheShellAndTheAgentAndTellsATakenOverClient(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	agentKeys := startAgent(t)
	agentKeys.add(agentKeys.key)
	s := startSSHDWith(t, sshdOptions{allowAgent: true, clientExtra: "\n  ForwardAgent yes", identityAgent: "SSH_AUTH_SOCK"})
	a, b, c := buildMosey(t, "0.1.1"), buildMosey(t, "0.2.1"), buildMosey(t, "0.3.1")
	defer func() {
		if t.Failed() {
			t.Logf("server logs:\n%s", sessionLogs(s))
		}
	}()

	first := startAgentClient(t, "the oldest client", a, s, agentKeys)
	first.shows("$")
	first.typeLine("KEPT=chain; echo shell-pid-$$; ssh-add -l")
	first.shows(agentKeyComment)
	m := shellPid.FindStringSubmatch(screenOf([]byte(first.screen.String()), 100, 30))
	if m == nil {
		t.Fatal("no shell pid on the screen")
	}
	pid, _ := strconv.Atoi(m[1])
	name := first.name()

	// A takeover that is also an upgrade: the attached oldest client is
	// told now, not after its silence timeout.
	second := startAgentClient(t, "the middle client", b, s, agentKeys, "-s", name)
	second.shows("shell-pid-" + m[1])
	if status := first.exits(); status != 3 {
		t.Errorf("the taken-over client exited %d, not 3; log:\n%s", status, first.log())
	}
	first.shows("session " + name + " taken over by another client")
	second.typeLine("ssh-add -l; echo middle-$KEPT-$$")
	second.shows("middle-chain-" + m[1])
	if strings.Count(screenOf([]byte(second.screen.String()), 100, 30), agentKeyComment) < 2 {
		t.Errorf("the agent socket did not survive the first upgrade:\n%s", screenOf([]byte(second.screen.String()), 100, 30))
	}
	waitFor(t, "the oldest build's roles to exit", func() bool {
		return len(roles(a, "spawner"))+len(roles(a, "proto"))+len(roles(a, "emu")) == 0
	})
	second.cmd.Process.Signal(syscall.SIGHUP)
	if status := second.exits(); status != 0 {
		t.Fatalf("the middle client exited %d after SIGHUP", status)
	}

	// The second hand-off is from an adopted spawner.
	middle := roles(b, "spawner")
	if len(middle) != 1 {
		t.Fatalf("the middle build runs spawners %v", middle)
	}
	third := startAgentClient(t, "the newest client", c, s, agentKeys)
	third.shows("middle-chain-" + m[1])
	// ssh-add first, as for the middle client: the line's echo then
	// shows only once ssh-add has printed, so the count below never
	// races its output.
	third.typeLine("ssh-add -l; echo newest-$KEPT-$$")
	third.shows("newest-chain-" + m[1])
	waitFor(t, "the middle build's roles to exit", func() bool {
		return len(roles(b, "spawner"))+len(roles(b, "proto"))+len(roles(b, "emu")) == 0
	})
	if !running(pid) {
		t.Fatal("the shell did not survive the second upgrade")
	}
	if len(roles(c, "spawner")) != 1 || len(roles(c, "proto")) != 1 {
		t.Error("the newest build does not serve the session")
	}
	if strings.Count(screenOf([]byte(third.screen.String()), 100, 30), agentKeyComment) < 3 {
		t.Error("the agent socket did not survive the second upgrade")
	}

	third.typeLine("exit")
	if status := third.exits(); status != 0 {
		t.Errorf("the newest client exited %d after exit; log:\n%s", status, third.log())
	}
	waitFor(t, "every process of the session to end", func() bool {
		return !running(pid) && len(roles(c, "spawner")) == 0
	})
}
