//go:build linux

package e2e

import (
	"bytes"
	"testing"
	"testing/synctest"

	"github.com/danielbodart/mosey/internal/netsim"
)

// A container launcher on the far side marks the terminal (OSC 666, as
// flong writes it) and the shell reports its directory (OSC 7): over a
// lossy network the user's terminal gets the mark, re-escaped by the
// client, and the directory; the far side's clear clears it; and the
// client's exit leaves no mark behind (screen.md §4.6, §4.7, §8.4, §8.6).
func TestTheFarSidesContainerMarkAndDirectoryReachTheUsersTerminal(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	synctest.Test(t, func(t *testing.T) {
		s := startSimSession(t, netsim.HotelWifi())
		s.wait("prompt", func() bool { return bytes.Contains(s.user.bytes(), []byte("$")) })
		say := func(b string) {
			s.prog.mu.Lock()
			s.prog.print(b)
			s.prog.mu.Unlock()
		}
		const (
			unmark = "\x1b]666;vte.container.\x1b\\"
			mark   = "\x1b]666;vte.container.name=a\\sbox;vte.container.runtime=flong;vte.container.uid=1000\x1b\\"
			cwd    = "\x1b]7;file://far/home/dan/a%20b\x1b\\"
		)
		say(mark + "\x1b]7;file://far/home/dan/a b\x1b\\")
		s.wait("the mark and the directory", func() bool {
			b := s.user.bytes()
			return bytes.Contains(b, []byte(unmark+mark)) && bytes.Contains(b, []byte(cwd))
		})
		marked := len(s.user.bytes())
		say(unmark + "$ ")
		s.wait("the mark cleared", func() bool { return bytes.Contains(s.user.bytes()[marked:], []byte(unmark)) })
		say(mark)
		s.wait("the mark again", func() bool { return bytes.Count(s.user.bytes(), []byte(mark)) == 2 })
		s.exit()
		b := s.user.bytes()
		if last := bytes.LastIndex(b, []byte(unmark)); last < bytes.LastIndex(b, []byte(mark)) {
			t.Fatalf("the client left the far side's mark on the terminal: %q", b[max(0, len(b)-200):])
		}
	})
}
