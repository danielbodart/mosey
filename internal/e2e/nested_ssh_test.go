//go:build linux

package e2e

import (
	"strings"
	"testing"
)

// Every terminal window runs a local session, and the user types mosey HOST
// in it. The nested client writes its remote mark to the local session's
// emulator, which carries it as FarRemote, and the outer client marks the
// user's tab remote with the nested client's host. When the nested client
// leaves, the tab is local again (screen.md §4.6, §8.8). Both clients are
// the real binary; the far host is the throwaway sshd.
func TestANestedMoseysRemoteMarkReachesTheTab(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	s := startSSHD(t)
	m := newMachine(t)
	mosey := buildMosey(t, "e2e")

	outer := startLocal(t, "the local client", mosey, m, "", nil)
	outer.shows("$")
	if strings.Contains(outer.screen.String(), "vte.ext.mosey") {
		t.Fatalf("the local session marked the tab before anything was nested:\n%q", outer.screen.String())
	}

	mark := "\x1b]666;vte.ext.mosey.remote=" + s.host + "\x1b\\"
	unset := "\x1b]666;vte.ext.mosey.remote\x1b\\"
	outer.typeLine(mosey + " -remote " + mosey + " -- -F " + s.config + " " + s.host)
	waitFor(t, "the tab to be marked with the nested client's host", func() bool {
		return strings.Contains(outer.screen.String(), mark)
	})
	outer.typeLine("echo inner-$((6*7))")
	outer.shows("inner-42")

	marked := strings.LastIndex(outer.screen.String(), mark)
	outer.typeLine("exit")
	waitFor(t, "the tab to be local again", func() bool {
		return strings.Contains(outer.screen.String()[marked:], unset)
	})
	outer.typeLine("echo outer-$((6*7))")
	outer.shows("outer-42")

	outer.typeLine("exit")
	if status := outer.exits(); status != 0 {
		t.Errorf("the local client exited %d after exit, not 0; log:\n%s", status, outer.log())
	}
	waitFor(t, "every session's processes to end", func() bool { return len(spawners(mosey)) == 0 })
}
