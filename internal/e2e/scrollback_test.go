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
	"github.com/danielbodart/mosey/internal/screen"
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

// Five windows' worth of lines, printed a few hundred at a time, all reach
// the user's terminal, in its scrollback and then on its screen, in order
// and exactly once, over every network profile: through loss, outages and
// roaming, in virtual time (D18). Each batch is smaller than the window
// and the next waits until the user sees the last, so nothing is cut
// (§2.5); what is checked is that no line is lost or printed twice across
// the many diffs, retransmissions and acknowledgements in between.
func TestManyWindowsOfLinesReachTheLocalScrollbackInOrderExactlyOnce(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	const batch, total = 400, 5 * screen.HistoryLines
	for _, p := range netsim.Profiles() {
		t.Run(p.Name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := startSimSession(t, p)
				s.wait("prompt", func() bool { return strings.Contains(s.clientScreen(), "$") })
				s.prog.flood("\r\n")
				for from := 1; from <= total; from += batch {
					to := min(from+batch-1, total)
					s.prog.flood(numbered(from, to))
					last := fmt.Sprintf("line-%04d", to)
					s.wait(last, func() bool { return strings.Contains(s.clientScreen(), last) })
				}
				s.converge()
				if err := exactlyOnce(numbers(transcript(s.user.bytes(), 80, 24)), total); err != nil {
					t.Errorf("%s: %v", p.Name, err)
				}
				s.exit()
			})
		})
	}
}

// More lines than the window, scrolled between two frames, are cut even
// on a healthy link: nothing paces the program's output, and the server
// keeps only the newest HistoryLines (§2.5). What the user's terminal gets
// is still honest: every line it shows is in order and shown once, and a
// marker stands for exactly the lines in each gap.
func TestABurstLongerThanTheWindowIsCutWithAMarkerForTheGap(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	const total = 5 * screen.HistoryLines
	for _, p := range netsim.Profiles() {
		t.Run(p.Name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := startSimSession(t, p)
				s.wait("prompt", func() bool { return strings.Contains(s.clientScreen(), "$") })
				// From the prompt's own row, so every line that scrolls off
				// is a numbered one and a marker's count is all numbered.
				s.prog.flood("\r" + numbered(1, total))
				last := fmt.Sprintf("line-%04d", total)
				s.wait(last, func() bool { return strings.Contains(s.clientScreen(), last) })
				s.converge()
				got := numbers(transcript(s.user.bytes(), 80, 24))
				markers, err := accountedFor(got, total)
				if err != nil {
					t.Errorf("%s: %v", p.Name, err)
				} else if markers == 0 {
					t.Errorf("%s: %d lines and no marker; the burst was %d lines", p.Name, len(got), total)
				}
				s.exit()
			})
		})
	}
}

// accountedFor checks that got is 1..n in order, each line once, but for
// markers, each standing for exactly the lines missing where it is; it
// returns how many markers there were.
func accountedFor(got []int, n int) (markers int, err error) {
	next := 1
	for i, v := range got {
		if v < 0 {
			markers++
			next += -v
			continue
		}
		if v != next {
			return markers, fmt.Errorf("entry %d is line-%04d where line-%04d was due", i, v, next)
		}
		next++
	}
	if next != n+1 {
		return markers, fmt.Errorf("the lines end at %d, want %d", next-1, n)
	}
	return markers, nil
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
		markers, err := accountedFor(got, 3000)
		if err != nil {
			t.Fatal(err)
		}
		if markers != 1 {
			t.Fatalf("%d markers in %v", markers, got)
		}
		missed := 0
		for _, v := range got {
			if v < 0 {
				missed = -v
			}
		}
		if missed < screen.HistoryLines {
			t.Errorf("only %d lines not shown; the window is %d lines", missed, screen.HistoryLines)
		}
		w.exitShell(a)
	})
}
