package server

import (
	"strings"
	"testing"
	"time"

	"github.com/danielbodart/mosey/internal/ipc"
	"github.com/danielbodart/mosey/internal/screen"
)

func TestASilentEmuIsKilledAtTheDeadline(t *testing.T) {
	h := newEmuHarness(t, 20, 5)
	// T4 is 30 s; a fake that never answers needs only to outlast this.
	h.e.deadline = 50 * time.Millisecond
	h.link(ipc.EmuFirst, func(*fakeEmu, ipc.Message) []ipc.Message { return nil })
	h.e.Write([]byte("x"))
	h.wantKill(ipc.KillDeadline)
}

func TestAMessageWhileIdleIsAViolation(t *testing.T) {
	h := newEmuHarness(t, 20, 5)
	f := h.link(ipc.EmuFirst, honest(""))
	if err := f.conn.Send(ipc.Update{}); err != nil {
		t.Fatal(err)
	}
	// Let it arrive before the next request looks.
	time.Sleep(10 * time.Millisecond)
	h.e.Write([]byte("x"))
	h.wantKill(ipc.KillViolation)
}

// The reply allowance on the IPC emulator (server.md §12): emu can add
// replies only to requests whose output held queries, and only as many.
func TestTheReplyAllowanceBoundsWhatEmuCanType(t *testing.T) {
	cpr := "\x1b[1;1R"
	for _, c := range []struct {
		name    string
		outputs []string
		replies string
		want    string
	}{
		{"no introducer after none", []string{"ls", "-l"}, cpr, ""},
		{"two tokens after one introducer", []string{"\x1b[6n"}, cpr + cpr, cpr},
		{"nine tokens after twenty introducers", []string{strings.Repeat("\x1b[6n", 20)}, strings.Repeat(cpr, 9), strings.Repeat(cpr, MaxReplyTokens)},
		{"a query split as ESC | [6n", []string{"\x1b", "[6n"}, cpr, cpr},
		{"a query split as ESC [6 | n", []string{"\x1b[6", "n"}, cpr, cpr},
		{"a token off the list", []string{"\x1b[6n"}, "\x1b]52;c;?\x07", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newEmuHarness(t, 20, 5)
			n := 0
			h.link(ipc.EmuFirst, func(f *fakeEmu, req ipc.Message) []ipc.Message {
				n++
				// Only the last request's answer carries the replies, so
				// the allowance in play is the last Output's.
				if n == len(c.outputs) {
					return honest(c.replies)(f, req)
				}
				return honest("")(f, req)
			})
			for _, o := range c.outputs {
				h.e.Write([]byte(o))
			}
			if got := string(h.e.TakeReplies()); got != c.want {
				t.Errorf("replies %q, want %q", got, c.want)
			}
			h.wantNoKill()
		})
	}
}

func TestRepliesToAResizeAreAViolation(t *testing.T) {
	h := newEmuHarness(t, 20, 5)
	h.link(ipc.EmuFirst, func(f *fakeEmu, req ipc.Message) []ipc.Message {
		return []ipc.Message{ipc.Replies{Data: []byte("\x1b[1;1R")}, f.update()}
	})
	h.e.Resize(30, 6)
	h.wantKill(ipc.KillViolation)
	if r := h.e.TakeReplies(); len(r) != 0 {
		t.Errorf("replies %q", r)
	}
}

// A rebuild (server.md §3.6, screen.md §7.3): the mirror starts again from
// a blank grid, Rebuilt rises with the reason mapped from the EmuLink and
// from why proto asked, the program is made to repaint, and the counters
// the client holds never go backwards.
func TestARebuildResetsTheMirrorAndTellsTheClientWhy(t *testing.T) {
	for _, c := range []struct {
		name   string
		reason ipc.EmuEnd
		asked  ipc.KillReason
		want   screen.RebuiltReason
	}{
		{"exited", ipc.EmuExited, 0, screen.RebuiltCrash},
		{"killed by a signal", ipc.EmuSignalled, 0, screen.RebuiltCrash},
		{"over its memory limit", ipc.EmuMemory, 0, screen.RebuiltMemory},
		{"killed for a violation", ipc.EmuKilled, ipc.KillViolation, screen.RebuiltCrash},
		{"killed at the deadline", ipc.EmuKilled, ipc.KillDeadline, screen.RebuiltOther},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newEmuHarness(t, 20, 5)
			repainted := make(chan struct{}, 1)
			h.e.repaint = func() { repainted <- struct{}{} }
			h.link(ipc.EmuFirst, func(f *fakeEmu, req ipc.Message) []ipc.Message {
				f.mu.Lock()
				f.screen.SetCell(0, 0, screen.Cell{Text: "x", Width: 1})
				f.screen.Bell++
				f.screen.Clipboard = screen.Clipboard{Seq: f.screen.Clipboard.Seq + 1, Data: []byte("copied")}
				f.mu.Unlock()
				return []ipc.Message{f.update()}
			})
			h.e.Write([]byte("x\a"))
			first := h.snapshot()
			if first.Bell != 1 || first.Clipboard.Seq != 1 {
				t.Fatalf("bell %d, clipboard %d", first.Bell, first.Clipboard.Seq)
			}
			if c.asked != 0 {
				h.e.mu.Lock()
				h.e.killed[h.gen] = c.asked
				h.e.mu.Unlock()
			}
			h.link(c.reason, honest(""))
			got := h.snapshot()
			if got.Rebuilt.Seq != 1 || got.Rebuilt.Reason != c.want {
				t.Errorf("Rebuilt %+v, want {1 %v}", got.Rebuilt, c.want)
			}
			if text(got, 0) != "" {
				t.Errorf("the old screen survived the rebuild: %q", text(got, 0))
			}
			if got.Bell != 1 || got.Clipboard.Seq != 1 || string(got.Clipboard.Data) != "copied" {
				t.Errorf("counters after the rebuild: bell %d, clipboard %+v", got.Bell, got.Clipboard)
			}
			select {
			case <-repainted:
			case <-time.After(5 * time.Second):
				t.Error("no repaint")
			}
		})
	}
}

// Counters going backwards within a generation are a violation, and the
// client's counters stay where they were (screen.md §7.2).
func TestCountersGoingBackwardsAreAViolation(t *testing.T) {
	h := newEmuHarness(t, 20, 5)
	h.link(ipc.EmuFirst, func(f *fakeEmu, req ipc.Message) []ipc.Message {
		f.mu.Lock()
		if f.screen.Bell == 0 {
			f.screen.Bell = 2
		} else {
			f.screen.Bell = 1
		}
		f.mu.Unlock()
		return []ipc.Message{f.update()}
	})
	h.e.Write([]byte("\a\a"))
	h.e.Write([]byte("x"))
	h.wantKill(ipc.KillViolation)
	if g := h.snapshot(); g.Bell != 2 {
		t.Errorf("bell %d, want 2", g.Bell)
	}
}

func TestAWriteWaitsForTheNextEmuAndThenCarriesOn(t *testing.T) {
	h := newEmuHarness(t, 20, 5)
	h.link(ipc.EmuFirst, func(*fakeEmu, ipc.Message) []ipc.Message {
		return []ipc.Message{ipc.Update{Fragment: []byte{0xff}}}
	})
	h.e.Write([]byte("bad"))
	h.wantKill(ipc.KillViolation)

	done := make(chan struct{})
	go func() {
		h.e.Write([]byte("hello"))
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("Write did not wait for a new emu")
	case <-time.After(50 * time.Millisecond):
	}
	// A resize while emu is down does not wait, so keystrokes behind it in
	// the client's stream still reach the pty.
	h.e.Resize(30, 6)
	h.link(ipc.EmuKilled, draw("hello", ""))
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Write is still waiting")
	}
	got := h.snapshot()
	if c, r := got.Size(); c != 30 || r != 6 {
		t.Errorf("the new emu is %dx%d, want the size set while it was down, 30x6", c, r)
	}
	if !strings.HasPrefix(text(got, 0), "hello") {
		t.Errorf("row 0 is %q", text(got, 0))
	}
}

// Synchronised output (screen.md §6.3): emu's HELD answer is reported by
// Held after the Snapshot, and Flush asks for the released screen.
func TestAHeldAnswerIsReportedAndFlushReleasesIt(t *testing.T) {
	h := newEmuHarness(t, 20, 5)
	flushes := make(chan struct{}, 4)
	h.link(ipc.EmuFirst, func(f *fakeEmu, req ipc.Message) []ipc.Message {
		if _, ok := req.(ipc.Flush); ok {
			flushes <- struct{}{}
			f.mu.Lock()
			f.screen.SetCell(0, 0, screen.Cell{Text: "z", Width: 1})
			f.mu.Unlock()
			return []ipc.Message{f.update()}
		}
		u := f.update().(ipc.Update)
		u.Held = true
		return []ipc.Message{u}
	})
	h.e.Write([]byte("\x1b[?2026h"))
	if !snapshot(h.e, screen.NewGrid(0, 0)) {
		t.Fatal("the held answer was not reported")
	}
	h.e.Flush()
	g := screen.NewGrid(0, 0)
	if snapshot(h.e, g) {
		t.Error("still held after the flush")
	}
	if len(flushes) != 1 || !strings.HasPrefix(text(g, 0), "z") {
		t.Errorf("flushes %d, row 0 %q", len(flushes), text(g, 0))
	}
}
