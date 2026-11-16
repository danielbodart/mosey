//go:build linux

package e2e

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/danielbodart/mosey/internal/netsim"
	"github.com/danielbodart/mosey/internal/server"
)

// Holding the program back (docs/spec/screen.md §2.5, Dan 2026-11-16):
// while a client is listening, proto reads the pty only as fast as the
// client acknowledges what scrolled, so a flood reaches the user's
// scrollback whole, as under ssh; while nobody listens, the program runs
// on and the window keeps the newest lines.

// The kernel's pty, as measured on Linux 6.18 by
// internal/pty's TestAnInterruptDiscardsTheOutputNotYetRead [M]: a
// writer blocks once 20-22 KB wait unread, and an interrupt from the
// keyboard discards all of it but what already sits in the master's
// line-discipline buffer, 4095 bytes.
const (
	ttyBuffer = 22 << 10
	ttyKept   = 4095
)

// ttyShell is a shell on that model of a pty. Its programs write a line
// at a time and block while the buffer is full, as seq does; ^C
// interrupts the running one (SIGINT) and discards the unread output but
// for ttyKept bytes, as n_tty does without NOFLSH. It answers "echo
// WORDS" with WORDS in capitals, "seq N" with line-1 to line-N, and ends
// on "exit".
type ttyShell struct {
	mu   sync.Mutex
	cond *sync.Cond
	// buf is the kernel's: written, not yet read by the server.
	buf    []byte
	closed bool
	line   []byte
	// running is whether a seq is writing, interrupted whether ^C has
	// stopped it; finished counts the seqs that ended, either way.
	running, interrupted bool
	finished             int
	// written counts the lines the seqs wrote; read is all the server
	// read, which is what its emulator saw.
	written int
	read    bytes.Buffer
}

func newTTYShell() *ttyShell {
	s := &ttyShell{}
	s.cond = sync.NewCond(&s.mu)
	s.out("$ ")
	return s
}

// out puts output in the kernel's buffer whatever its fill, as an echo
// or a short prompt goes; the caller holds mu, or is newTTYShell.
func (s *ttyShell) out(b string) {
	s.buf = append(s.buf, b...)
	s.cond.Broadcast()
}

func (s *ttyShell) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.buf) == 0 && !s.closed {
		s.cond.Wait()
	}
	if len(s.buf) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s.buf)
	s.read.Write(p[:n])
	s.buf = append(s.buf[:0], s.buf[n:]...)
	s.cond.Broadcast()
	return n, nil
}

// Write is the keys the server writes: the line discipline acts on ^C,
// and the shell echoes and runs the rest.
func (s *ttyShell) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, io.ErrClosedPipe
	}
	for _, c := range p {
		switch {
		case c == 0x03:
			if s.running {
				s.interrupted = true
				s.buf = s.buf[:min(len(s.buf), ttyKept)]
				s.out("^C")
			} else {
				s.line = s.line[:0]
				s.out("^C\r\n$ ")
			}
			s.cond.Broadcast()
		case c != '\r':
			s.line = append(s.line, c)
			s.out(string(c))
		default:
			s.run(string(s.line))
			s.line = s.line[:0]
		}
	}
	return len(p), nil
}

// run runs one command line; the caller holds mu.
func (s *ttyShell) run(cmd string) {
	switch {
	case cmd == "exit":
		s.out("\r\n")
		s.closed = true
		s.cond.Broadcast()
	case strings.HasPrefix(cmd, "echo "):
		s.out("\r\n" + strings.ToUpper(cmd[5:]) + "\r\n$ ")
	case strings.HasPrefix(cmd, "seq "):
		s.out("\r\n")
		s.running, s.interrupted = true, false
		go s.seq(atoi(cmd[4:]))
	default:
		s.out("\r\n$ ")
	}
}

// seq writes line-1 to line-n a line at a time, blocking while the
// kernel's buffer is full, until it is done or interrupted.
func (s *ttyShell) seq(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := 1; i <= n; i++ {
		for len(s.buf) >= ttyBuffer && !s.interrupted && !s.closed {
			s.cond.Wait()
		}
		if s.interrupted || s.closed {
			break
		}
		s.out(fmt.Sprintf("line-%04d\r\n", i))
		s.written++
	}
	if s.interrupted {
		s.out("\r\n")
	}
	s.out("$ ")
	s.running = false
	s.finished++
}

// done is how many seqs have ended, and how many lines they wrote.
func (s *ttyShell) done() (finished, written int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.finished, s.written
}

// output is all the server has read: what its emulator was given.
func (s *ttyShell) output() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.read.Bytes())
}

func (s *ttyShell) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.cond.Broadcast()
	return nil
}

func (s *ttyShell) Resize(cols, rows int) error { return nil }
func (s *ttyShell) EchoOff() (bool, error)      { return false, nil }

// silences records each time the server says the client went silent or
// left, for a test to tell "listening throughout" from "cut off".
type silences struct {
	mu sync.Mutex
	n  int
}

func (c *silences) hook(s *server.Session) {
	s.Detached = func() {
		c.mu.Lock()
		c.n++
		c.mu.Unlock()
	}
}

func (c *silences) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// startTTYSession is startSimSession with prog as the shell; it waits
// for the prompt and clears the screen, so every line that scrolls off
// after is one a test printed.
func startTTYSession(t *testing.T, p netsim.Profile, prog *ttyShell, hook func(*server.Session)) *simSession {
	s := startSimSessionWith(t, p, prog, hook)
	s.wait("prompt", func() bool { return strings.Contains(s.clientScreen(), "$") })
	prog.mu.Lock()
	prog.out("\x1b[H\x1b[2J$ ")
	prog.mu.Unlock()
	return s
}

// cuttable is a LAN whose two links a test can cut, as a dead spot does.
type cuttable struct{ up, down *netsim.Link }

func (c *cuttable) profile() netsim.Profile {
	return netsim.Profile{Name: "lan", Setup: func(n *netsim.Network, cl, sv *netsim.Host, _ *netsim.Conn) {
		l := netsim.LinkParams{Delay: 250 * time.Microsecond, MTU: netsim.ProfileMTU}
		c.up, c.down = n.Connect(cl, sv, l), n.Connect(sv, cl, l)
	}}
}

func (c *cuttable) cut(lost bool) {
	l := netsim.LinkParams{Delay: 250 * time.Microsecond, MTU: netsim.ProfileMTU}
	if lost {
		l.Loss = 1
	}
	c.up.SetParams(l)
	c.down.SetParams(l)
}

// waitFinished sleeps in virtual time until prog's seqs have ended n
// times, and says when that was, or fails after limit.
func waitFinished(t *testing.T, prog *ttyShell, n int, limit time.Duration) time.Time {
	t.Helper()
	for deadline := time.Now().Add(limit); ; {
		if f, _ := prog.done(); f >= n {
			return time.Now()
		}
		if time.Now().After(deadline) {
			_, w := prog.done()
			t.Fatalf("the program has not finished %v on, %d lines written", limit, w)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The program's output reaches the user's scrollback whole while the
// client listens: seq 5000 and seq 20000, far more than the 1000-line
// window, scroll past at whatever pace the client acknowledges, and every
// line is printed once, in order, with no marker, over every network
// profile. A profile's outage of SilentAfter or more makes the client
// silent, and then the window may cut; that run must still account for
// every line, and says so.
func TestAFloodWhileTheClientListensReachesTheScrollbackWhole(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	for _, total := range []int{5000, 20000} {
		for _, p := range netsim.Profiles() {
			t.Run(fmt.Sprintf("%s/seq-%d", p.Name, total), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					prog := newTTYShell()
					var quiet silences
					s := startTTYSession(t, p, prog, quiet.hook)
					began := time.Now()
					s.typeLine(fmt.Sprintf("seq %d", total))
					last := fmt.Sprintf("line-%04d", total)
					s.wait(last, func() bool { return strings.Contains(s.clientScreen(), last) })
					took := time.Since(began)
					s.converge()
					got := numbers(transcript(s.user.bytes(), 80, 24))
					if quiet.count() > 0 {
						markers, err := accountedFor(got, total)
						if err != nil {
							t.Errorf("%s: silent %d times; %v", p.Name, quiet.count(), err)
						}
						t.Logf("%s: the client went silent %d times; %d markers", p.Name, quiet.count(), markers)
					} else if err := exactlyOnce(got, total); err != nil {
						t.Errorf("%s: %v", p.Name, err)
					}
					t.Logf("%s: seq %d took %v (%.0f lines/s)", p.Name, total, took.Round(time.Millisecond), float64(total)/took.Seconds())
					s.exit()
				})
			})
		}
	}
}

// A client cut off mid-flood holds the program only until it counts as
// silent (SilentAfter, the state that reports the session detached):
// then the program runs to its end without the client, the window keeps
// the newest lines, and when the client is heard again it prints one
// marker for exactly the lines it missed, and the rest in order.
func TestAFloodWhileTheClientIsSilentRunsOnAndAMarkerCountsTheGap(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	synctest.Test(t, func(t *testing.T) {
		var link cuttable
		prog := newTTYShell()
		s := startTTYSession(t, link.profile(), prog, nil)
		const total = 20000
		s.typeLine(fmt.Sprintf("seq %d", total))
		s.wait("a flood under way", func() bool { _, w := prog.done(); return w >= 2000 })
		link.cut(true)
		cut := time.Now()
		time.Sleep(server.SilentAfter / 2)
		if f, w := prog.done(); f > 0 {
			t.Fatalf("the program finished, %d lines, while the client was only in a dead spot", w)
		}
		finished := waitFinished(t, prog, 1, time.Minute)
		if took := finished.Sub(cut); took > server.SilentAfter+2*time.Second {
			t.Errorf("the program finished %v after the client was cut off; it should wait only SilentAfter (%v)", took, server.SilentAfter)
		}
		link.cut(false)
		last := fmt.Sprintf("line-%04d", total)
		s.wait(last, func() bool { return strings.Contains(s.clientScreen(), last) })
		s.converge()
		got := numbers(transcript(s.user.bytes(), 80, 24))
		markers, err := accountedFor(got, total)
		if err != nil {
			t.Fatal(err)
		}
		if markers != 1 {
			t.Errorf("%d markers, want 1", markers)
		}
		s.exit()
	})
}

// A client that leaves while the program is held back releases it: the
// session counts as detached, the pty reader stops waiting for an
// acknowledgement that will never come, and the program runs to its end
// at once, as a build must while the laptop is shut. No deadlock.
func TestAClientLeavingMidFloodReleasesTheProgram(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	synctest.Test(t, func(t *testing.T) {
		prog := newTTYShell()
		var quiet silences
		s := startTTYSession(t, netsim.LAN(), prog, quiet.hook)
		s.typeLine("seq 100000")
		s.wait("a flood under way", func() bool { _, w := prog.done(); return w >= 2000 })
		if f, _ := prog.done(); f > 0 {
			t.Fatal("the program finished before the client left: nothing held it back")
		}
		s.quit()
		<-s.client
		left := time.Now()
		finished := waitFinished(t, prog, 1, time.Minute)
		if quiet.count() != 1 {
			t.Errorf("the session counted %d detaches, want 1", quiet.count())
		}
		if took := finished.Sub(left); took > time.Second {
			t.Errorf("the program took %v to finish after the client left", took)
		}
		if _, w := prog.done(); w != 100000 {
			t.Errorf("the program wrote %d lines, want 100000", w)
		}
	})
}

// slowLink is the heads-up's slow link: a 300 ms round trip and 1 Mbit/s
// each way (one 1500-byte delivery every 12 ms), behind a 64 KB queue,
// with nothing lost [D].
func slowLink(t *testing.T) netsim.Profile {
	trace, err := netsim.LoadTrace(strings.NewReader("12\n"))
	if err != nil {
		t.Fatal(err)
	}
	return netsim.Profile{Name: "slow", Setup: func(n *netsim.Network, c, s *netsim.Host, _ *netsim.Conn) {
		l := netsim.LinkParams{Delay: 150 * time.Millisecond, MTU: netsim.ProfileMTU, Trace: trace, QueueBytes: 64 << 10}
		n.Connect(c, s, l)
		n.Connect(s, c, l)
	}}
}

// Ctrl-C during a flood gives the prompt back promptly on a slow link:
// the program gets SIGINT at once (keys go to the pty whatever the hold),
// the kernel discards its unread output but for ttyKept bytes, and what
// is still to cross is the small queue: the lines the client has not
// acknowledged, at most half the window, and those ttyKept bytes. The
// bound is the time an ordinary command takes to answer on the same
// link, plus two hold cycles of a round trip, the 100 ms delayed ack and
// a frame interval each (docs/spec/screen.md §2.5). On the slow link an
// answer takes 450 ms and the prompt is back 900-950 ms after ^C, inside
// the bound of 1550 ms [measured here].
func TestCtrlCDuringAFloodGivesThePromptBackPromptly(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	profiles := []netsim.Profile{slowLink(t)}
	for _, p := range netsim.Profiles() {
		if p.Name == "train" || p.Name == "lte-driving" {
			profiles = append(profiles, p)
		}
	}
	for _, p := range profiles {
		t.Run(p.Name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				prog := newTTYShell()
				s := startTTYSession(t, p, prog, nil)
				typed := time.Now()
				s.typeLine("echo ping")
				s.wait("answer", func() bool { return strings.Contains(s.clientScreen(), "PING") })
				answer := time.Since(typed)

				s.typeLine("seq 1000000")
				s.wait("a flood under way", func() bool { _, w := prog.done(); return w >= 5000 })
				interrupted := time.Now()
				select {
				case s.user.keys <- []byte{0x03}:
				case <-time.After(time.Minute):
					t.Fatal("the client stopped reading its terminal")
				}
				s.wait("prompt after ^C", func() bool {
					sc := strings.TrimRight(s.clientScreen(), "\n")
					return strings.HasSuffix(sc, "^C\n$")
				})
				back := time.Since(interrupted)
				finished, written := prog.done()
				if finished != 1 || written >= 1000000 {
					t.Fatalf("the program was not interrupted: %d finished, %d lines", finished, written)
				}
				srtt := 300 * time.Millisecond
				if p.Name != "slow" {
					srtt = answer
				}
				cycle := srtt + 100*time.Millisecond + srtt/2
				// The train's fades and delay spikes, random per run, can
				// hold up any packet for seconds, ^C's as much as an
				// ordinary key's; there the run is logged, not bounded.
				if bound := answer + 2*cycle; p.Name != "train" && back > bound {
					t.Errorf("%s: the prompt came back %v after ^C; an answer takes %v, the bound is %v", p.Name, back, answer, bound)
				}
				t.Logf("%s: an answer took %v, the prompt after ^C %v, at line %d", p.Name, answer.Round(time.Millisecond), back.Round(time.Millisecond), written)
				s.converge()
				again := time.Now()
				s.typeLine("echo pong")
				s.wait("answer", func() bool { return strings.Contains(s.clientScreen(), "PONG") })
				t.Logf("%s: an answer after it took %v", p.Name, time.Since(again).Round(time.Millisecond))
				if got := numbers(transcript(s.user.bytes(), 80, 24)); len(got) > 0 {
					if _, err := accountedFor(got, got[len(got)-1]); err != nil || hasMarker(got) {
						t.Errorf("%s: the lines before ^C are not whole: %v", p.Name, err)
					}
				}
				s.exit()
			})
		})
	}
}

func hasMarker(got []int) bool {
	for _, v := range got {
		if v < 0 {
			return true
		}
	}
	return false
}
