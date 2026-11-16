//go:build linux

package e2e

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"tuios.dev/vt"

	"github.com/danielbodart/mosey/internal/netsim"
)

// Scrollback (PLAN §1: Mosh has none, so everyone runs tmux inside it),
// end to end: what scrolls off the remote screen reaches the user's own
// terminal's scrollback (docs/spec/screen.md §2.5, §8.7). The user's
// terminal here is a reference emulator with a scrollback of its own,
// played the client's output; the client never parses it (D9), the test
// does, to see what the user would.

// transcript is everything the user's terminal holds after b: its
// scrollback, then its screen, one line each, blank lines left out.
func transcript(b []byte, cols, rows int) []string {
	t := vt.NewWithScrollback(cols, rows, 100_000)
	defer t.Close()
	_, _ = t.Write(b)
	var out []string
	add := func(w int, cell func(x int) string) {
		var line strings.Builder
		for x := range w {
			line.WriteString(cell(x))
		}
		if s := strings.TrimRight(line.String(), " "); s != "" {
			out = append(out, s)
		}
	}
	for i := range t.ScrollbackLen() {
		l := t.ScrollbackLine(i)
		add(len(l), func(x int) string {
			if c := l[x].Content; c != "" {
				return c
			}
			return " "
		})
	}
	for y := range t.Height() {
		add(t.Width(), func(x int) string {
			if c := t.CellAt(x, y); c != nil && c.Content != "" {
				return c.Content
			}
			return " "
		})
	}
	return out
}

var (
	numberedLine = regexp.MustCompile(`^line-(\d+)$`)
	notShown     = regexp.MustCompile(`^… (\d+) lines not shown$`)
)

// numbers is the numbered lines of a transcript in order, with a marker
// as -N for N lines not shown.
func numbers(lines []string) []int {
	var out []int
	for _, l := range lines {
		if m := numberedLine.FindStringSubmatch(l); m != nil {
			n, _ := strconv.Atoi(m[1])
			out = append(out, n)
		} else if m := notShown.FindStringSubmatch(l); m != nil {
			n, _ := strconv.Atoi(m[1])
			out = append(out, -n)
		}
	}
	return out
}

// exactlyOnce says whether got is 1..n, each once, in order.
func exactlyOnce(got []int, n int) error {
	if len(got) != n {
		return fmt.Errorf("%d numbered lines, want %d", len(got), n)
	}
	for i, v := range got {
		if v != i+1 {
			return fmt.Errorf("line %d is line-%04d", i+1, v)
		}
	}
	return nil
}

// A thousand lines printed at once all reach the user's terminal, in its
// scrollback and then on its screen, in order and exactly once, over every
// network profile: through loss, outages and roaming, in virtual time
// (D18).
func TestAThousandLinesReachTheLocalScrollbackInOrderExactlyOnce(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	for _, p := range netsim.Profiles() {
		t.Run(p.Name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := startSimSession(t, p)
				s.wait("prompt", func() bool { return strings.Contains(s.clientScreen(), "$") })
				s.typeLine("seq 1000")
				s.wait("the last line", func() bool { return strings.Contains(s.clientScreen(), "line-1000") })
				s.converge()
				if err := exactlyOnce(numbers(transcript(s.user.bytes(), 80, 24)), 1000); err != nil {
					t.Errorf("%s: %v", p.Name, err)
				}
				s.exit()
			})
		})
	}
}

// A client that resumes a session first prints its recent history, then
// its screen (§2.5): what scrolled off before it attached is in its
// terminal's scrollback too.
func TestAResumingClientReprintsTheRecentHistory(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	synctest.Test(t, func(t *testing.T) {
		w := newResumeWorld(t)
		a := w.first()
		a.sees("$")
		a.typeLine("seq 60")
		a.sees("line-0060")
		a.leave()
		a.ends()
		b := w.another("laptop", laptopAddr)
		b.sees("line-0060")
		if err := exactlyOnce(numbers(transcript(b.user.bytes(), 80, 24)), 60); err != nil {
			t.Errorf("the resuming client: %v", err)
		}
		w.exitShell(b)
	})
}

// A client that falls behind by more than the window, through an outage
// while a program floods the screen, prints one marker saying how many
// lines it missed, and carries on with the rest in order (§2.5, §8.7).
func TestAClientThatFallsBehindPastTheWindowPrintsAMarker(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	synctest.Test(t, func(t *testing.T) {
		w := newResumeWorld(t)
		a := w.first()
		a.sees("$")
		w.prog.flood("\r\n" + numbered(1, 100))
		a.sees("line-0100")
		w.cut(true)
		w.prog.flood(numbered(101, 3000))
		time.Sleep(5 * time.Second)
		w.cut(false)
		a.sees("line-3000")
		got := numbers(transcript(a.user.bytes(), 80, 24))
		marker := -1
		for i, v := range got {
			if v < 0 {
				if marker >= 0 {
					t.Fatalf("two markers: %v", got)
				}
				marker = i
			}
		}
		if marker < 0 {
			t.Fatalf("no marker in %d numbered lines", len(got))
		}
		// Before the marker, 1..k; the marker says how many follow k
		// unseen; after it, the rest, contiguous to 3000.
		for i := range marker {
			if got[i] != i+1 {
				t.Fatalf("before the marker, line %d is %d", i+1, got[i])
			}
		}
		next := marker + 1 - got[marker]
		for _, v := range got[marker+1:] {
			if v != next {
				t.Fatalf("after the marker (%d not shown), %d where %d was due", -got[marker], v, next)
			}
			next++
		}
		if next != 3001 {
			t.Fatalf("the lines end at %d", next-1)
		}
		if missed := -got[marker]; missed < 1000 {
			t.Errorf("only %d lines not shown; the window is 1000 lines", missed)
		}
		w.exitShell(a)
	})
}
