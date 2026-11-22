//go:build linux

package e2e

import (
	"regexp"
	"strings"
	"syscall"
	"testing"
)

// Local `mosey -close-if-idle` ends an idle bare shell when the client
// receives SIGHUP, and leaves the session alive and resumable when a
// foreground command or background job is running in the session, or when
// another client has taken it over (bootstrap.md §2.2, server.md §2.4).
func TestCloseIfIdleEndsIdleShellAndKeepsBusyOrTakenOverSessionsAlive(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	m := newMachine(t)
	mosey := buildMosey(t, "e2e")

	// 1. Idle bare shell: SIGHUP ends the session and it disappears from -list.
	idle := startLocal(t, "idle -close-if-idle client", mosey, m, "", []string{"-new", "-close-if-idle"})
	idle.shows("$")
	idleName := idle.name()
	idle.cmd.Process.Signal(syscall.SIGHUP)
	if status := idle.exits(); status != 0 {
		t.Fatalf("idle client exited %d after SIGHUP, not 0", status)
	}
	waitFor(t, "idle session to disappear from -list", func() bool {
		out, _ := localCmd(t, mosey, m, "-list")
		return !strings.Contains(out, idleName)
	})

	// 1b. The window closes and the client's read fails with EIO, with no
	// SIGHUP at all: the same detach, so the idle shell still ends.
	hung := startLocalTTY(t, false, "hung-up -close-if-idle client", mosey, m, "", []string{"-new", "-close-if-idle"})
	hung.shows("$")
	hungName := hung.name()
	hung.master.Close()
	if status := hung.exits(); status != 0 {
		t.Fatalf("hung-up client exited %d after EIO, not 0", status)
	}
	waitFor(t, "hung-up session to disappear from -list", func() bool {
		out, _ := localCmd(t, mosey, m, "-list")
		return !strings.Contains(out, hungName)
	})

	// 2. Foreground command running: SIGHUP detaches; session stays alive and resumable.
	fg := startLocal(t, "foreground-busy -close-if-idle client", mosey, m, "", []string{"-new", "-close-if-idle"})
	fg.shows("$")
	fgName := fg.name()
	fg.typeLine("sleep 1000")
	waitFor(t, "-list to show foreground sleep", func() bool {
		out, _ := localCmd(t, mosey, m, "-list")
		return regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(fgName) + `\s+attached\s+\S+\s+127\.0\.0\.1\s+sleep\b`).MatchString(out)
	})
	fg.cmd.Process.Signal(syscall.SIGHUP)
	if status := fg.exits(); status != 0 {
		t.Fatalf("foreground-busy client exited %d after SIGHUP, not 0", status)
	}
	waitFor(t, "foreground-busy session to stay alive as detached", func() bool {
		out, _ := localCmd(t, mosey, m, "-list")
		return regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(fgName) + `\s+detached\s`).MatchString(out)
	})
	if out, status := localCmd(t, mosey, m, "-kill", fgName); status != 0 {
		t.Fatalf("killing %s: exit %d:\n%s", fgName, status, out)
	}

	// 3. Backgrounded job at prompt: shell is foreground (fg_pgid == shell_pid)
	// but a child shares sid == shell_pid -> SIGHUP keeps session alive.
	bg := startLocal(t, "background-busy -close-if-idle client", mosey, m, "", []string{"-new", "-close-if-idle"})
	bg.shows("$")
	bgName := bg.name()
	bg.typeLine("sleep 1000 & echo bg-ready-$((1+1))")
	bg.shows("bg-ready-2")
	waitFor(t, "-list to show shell back at foreground", func() bool {
		out, _ := localCmd(t, mosey, m, "-list")
		return regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(bgName) + `\s+attached\s+\S+\s+127\.0\.0\.1\s+sh\b`).MatchString(out)
	})
	bg.cmd.Process.Signal(syscall.SIGHUP)
	if status := bg.exits(); status != 0 {
		t.Fatalf("background-busy client exited %d after SIGHUP, not 0", status)
	}
	waitFor(t, "background-busy session to stay alive as detached", func() bool {
		out, _ := localCmd(t, mosey, m, "-list")
		return regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(bgName) + `\s+detached\s`).MatchString(out)
	})
	if out, status := localCmd(t, mosey, m, "-kill", bgName); status != 0 {
		t.Fatalf("killing %s: exit %d:\n%s", bgName, status, out)
	}

	// 4. Taken-over session: another client takes over before client 1 leaves;
	// session stays alive for the new client.
	first := startLocal(t, "taken-over -close-if-idle client", mosey, m, "", []string{"-new", "-close-if-idle"})
	first.shows("$")
	takenName := first.name()
	second := startLocal(t, "takeover client", mosey, m, "", []string{"-s", takenName})
	second.shows("$")
	if status := first.exits(); status != 3 {
		t.Fatalf("taken-over client exited %d, not 3", status)
	}
	second.typeLine("echo still-here-$((40+2))")
	second.shows("still-here-42")
	second.typeLine("exit")
	if status := second.exits(); status != 0 {
		t.Fatalf("second client exited %d, not 0", status)
	}

	waitFor(t, "all sessions to end", func() bool { return len(spawners(mosey)) == 0 })
}
