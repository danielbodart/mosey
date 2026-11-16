package server

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielbodart/mosey/internal/ipc"
	"github.com/danielbodart/mosey/internal/screen"
)

// fakeEmu is the emu end of one generation's socketpair, answering each
// request with whatever the test's answer function says, so proto's side of
// server.md §3.5 can be driven message by message.
type fakeEmu struct {
	conn *ipc.Conn
	reqs chan ipc.Message
	// screen is what the fake "displays"; answer functions diff from sent.
	mu     sync.Mutex
	screen *screen.Grid
	sent   *screen.Grid
}

// answerFunc is a fake emu's answer to one request.
type answerFunc func(f *fakeEmu, req ipc.Message) []ipc.Message

// honest answers like a real emu: replies (if any), then the diff from
// what it last sent to its screen.
func honest(replies string) answerFunc {
	return func(f *fakeEmu, req ipc.Message) []ipc.Message {
		var out []ipc.Message
		if _, ok := req.(ipc.Output); ok && replies != "" {
			out = append(out, ipc.Replies{Data: []byte(replies)})
		}
		return append(out, f.update())
	}
}

// update is the diff from what the fake last sent to its screen, applying
// any size change a Resize asked for.
func (f *fakeEmu) update() ipc.Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	d := f.screen.Diff(f.sent)
	f.sent = f.screen.Clone()
	return ipc.Update{Fragment: d}
}

type killCall struct {
	gen uint32
	why ipc.KillReason
}

type emuHarness struct {
	t     *testing.T
	e     *ipcEmulator
	kills chan killCall
	gen   uint32
}

func newEmuHarness(t *testing.T, cols, rows int) *emuHarness {
	needs(t, "screen", func() { screen.NewGrid(1, 1) })
	h := &emuHarness{t: t, kills: make(chan killCall, 16)}
	h.e = newIPCEmulator(cols, rows, defaultInit(), func(gen uint32, why ipc.KillReason) {
		h.kills <- killCall{gen, why}
	}, slog.New(slog.DiscardHandler))
	t.Cleanup(func() { h.e.Close() })
	return h
}

// link starts the next generation's fake and attaches it, as an EmuLink
// would. The fake answers Init honestly and every later request with
// answer.
func (h *emuHarness) link(reason ipc.EmuEnd, answer answerFunc) *fakeEmu {
	h.t.Helper()
	ours, theirs, err := ipc.Pair()
	if err != nil {
		h.t.Fatal(err)
	}
	conn, err := ipc.NewConn(theirs, ipc.Emu, ipc.Proto)
	if err != nil {
		h.t.Fatal(err)
	}
	f := &fakeEmu{conn: conn, reqs: make(chan ipc.Message, 64)}
	h.t.Cleanup(func() { conn.Close() })
	go func() {
		for {
			m, err := conn.Recv()
			if err != nil {
				return
			}
			f.reqs <- m
			var out []ipc.Message
			switch m := m.(type) {
			case ipc.Init:
				f.mu.Lock()
				f.screen = screen.NewGrid(int(m.Cols), int(m.Rows))
				f.sent = f.screen.Clone()
				f.mu.Unlock()
				out = []ipc.Message{f.update()}
			case ipc.Resize:
				f.mu.Lock()
				f.screen.Resize(int(m.Cols), int(m.Rows))
				f.mu.Unlock()
				out = answer(f, m)
			default:
				out = answer(f, m)
			}
			for _, o := range out {
				if conn.Send(o) != nil {
					return
				}
			}
		}
	}()
	h.gen++
	status := int32(0)
	if reason != ipc.EmuFirst {
		status = 1
	}
	if err := h.e.attach(ipc.EmuLink{Generation: h.gen, Reason: reason, Status: status, Conn: ours}); err != nil {
		h.t.Fatal(err)
	}
	return f
}

func (h *emuHarness) wantKill(why ipc.KillReason) {
	h.t.Helper()
	select {
	case k := <-h.kills:
		if k.gen != h.gen || k.why != why {
			h.t.Fatalf("KillEmu{%d, %d}, want {%d, %d}", k.gen, k.why, h.gen, why)
		}
	case <-time.After(5 * time.Second):
		h.t.Fatalf("no KillEmu{%d, %d}", h.gen, why)
	}
}

func (h *emuHarness) wantNoKill() {
	h.t.Helper()
	select {
	case k := <-h.kills:
		h.t.Fatalf("unexpected KillEmu{%d, %d}", k.gen, k.why)
	default:
	}
}

func (h *emuHarness) snapshot() *screen.Grid {
	g := screen.NewGrid(0, 0)
	h.e.Snapshot(g)
	return g
}

// text is row y as it would be drawn, blanks as spaces, trailing ones
// dropped.
func text(g *screen.Grid, y int) string {
	cols, _ := g.Size()
	var b strings.Builder
	for x := range cols {
		c := g.Cell(x, y)
		if c.Text == "" && c.Width != 0 {
			b.WriteByte(' ')
		}
		b.WriteString(c.Text)
	}
	return strings.TrimRight(b.String(), " ")
}

// draw is an answer that writes s at the top left, then answers honestly.
func draw(s string, replies string) answerFunc {
	return func(f *fakeEmu, req ipc.Message) []ipc.Message {
		f.mu.Lock()
		for i, r := range s {
			f.screen.SetCell(i, 0, screen.Cell{Text: string(r), Width: 1})
		}
		f.mu.Unlock()
		return honest(replies)(f, req)
	}
}

func TestOutputReachesTheMirrorThroughTheValidatingDecoder(t *testing.T) {
	h := newEmuHarness(t, 20, 5)
	h.link(ipc.EmuFirst, draw("hello", ""))
	h.e.Write([]byte("hello"))
	if got := text(h.snapshot(), 0); !strings.HasPrefix(got, "hello") {
		t.Errorf("row 0 is %q", got)
	}
	h.wantNoKill()
}

// Each of server.md §3.5's and screen.md §7.3's violations ends with
// KillEmu{violation}, and changes neither the mirror nor the reply queue.
func TestEveryViolationKillsEmuAndChangesNothing(t *testing.T) {
	big := make([]byte, ipc.MaxFragment)
	for _, c := range []struct {
		name   string
		answer answerFunc
		req    func(e *ipcEmulator)
	}{
		{"a second Replies", func(f *fakeEmu, req ipc.Message) []ipc.Message {
			return []ipc.Message{ipc.Replies{Data: []byte("\x1b[1;1R")}, ipc.Replies{Data: []byte("\x1b[1;1R")}, f.update()}
		}, nil},
		{"Replies after an Update fragment", func(f *fakeEmu, req ipc.Message) []ipc.Message {
			return []ipc.Message{ipc.Update{More: true}, ipc.Replies{Data: []byte("\x1b[1;1R")}, ipc.Update{}}
		}, nil},
		{"replies that do not split", func(f *fakeEmu, req ipc.Message) []ipc.Message {
			return []ipc.Message{ipc.Replies{Data: []byte("\x1b[1;1Rtouch /tmp/x\n")}, f.update()}
		}, nil},
		{"a diff Apply refuses", func(f *fakeEmu, req ipc.Message) []ipc.Message {
			return []ipc.Message{ipc.Update{Fragment: []byte{0xff, 0xff, 0xff}}}
		}, nil},
		{"a SIZE outside an answer to Resize", func(f *fakeEmu, req ipc.Message) []ipc.Message {
			f.mu.Lock()
			f.screen.Resize(30, 5)
			f.mu.Unlock()
			return []ipc.Message{f.update()}
		}, nil},
		{"a resize to a size proto did not ask for", func(f *fakeEmu, req ipc.Message) []ipc.Message {
			f.mu.Lock()
			f.screen.Resize(40, 10)
			f.mu.Unlock()
			return []ipc.Message{f.update()}
		}, func(e *ipcEmulator) { e.Resize(30, 5) }},
		{"EchoOff set", func(f *fakeEmu, req ipc.Message) []ipc.Message {
			f.mu.Lock()
			f.screen.EchoOff = true
			f.mu.Unlock()
			return []ipc.Message{f.update()}
		}, nil},
		{"EchoAck set", func(f *fakeEmu, req ipc.Message) []ipc.Message {
			f.mu.Lock()
			f.screen.EchoAck = 7
			f.mu.Unlock()
			return []ipc.Message{f.update()}
		}, nil},
		{"Rebuilt set", func(f *fakeEmu, req ipc.Message) []ipc.Message {
			f.mu.Lock()
			f.screen.Rebuilt = screen.Rebuilt{Seq: 1, Reason: screen.RebuiltCrash}
			f.mu.Unlock()
			return []ipc.Message{f.update()}
		}, nil},
		{"InputConsumed set", func(f *fakeEmu, req ipc.Message) []ipc.Message {
			f.mu.Lock()
			f.screen.InputConsumed = 9
			f.mu.Unlock()
			return []ipc.Message{f.update()}
		}, nil},
		{"a diff over MaxDiff", func(f *fakeEmu, req ipc.Message) []ipc.Message {
			var out []ipc.Message
			for range screen.MaxDiff/len(big) + 2 {
				out = append(out, ipc.Update{More: true, Fragment: big})
			}
			return append(out, ipc.Update{})
		}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newEmuHarness(t, 20, 5)
			h.link(ipc.EmuFirst, c.answer)
			before := h.snapshot()
			if c.req != nil {
				c.req(h.e)
			} else {
				h.e.Write([]byte("\x1b[6n"))
			}
			h.wantKill(ipc.KillViolation)
			after := h.snapshot()
			if !after.Equal(before) {
				t.Error("the mirror changed")
			}
			if r := h.e.TakeReplies(); len(r) != 0 {
				t.Errorf("replies queued: %q", r)
			}
		})
	}
}

// A Resize that arrives while an Output is in flight waits for it, and the
// Output's answer, at the old size, is no violation: each answer is held
// to the size its own request implies (found by the KILL soak, where emu
// was killed for "screen 80x24, not 80x30").
func TestAnOutputAnsweredWhileAResizeWaitsIsNoViolation(t *testing.T) {
	h := newEmuHarness(t, 80, 24)
	release := make(chan struct{})
	h.link(ipc.EmuFirst, func(f *fakeEmu, req ipc.Message) []ipc.Message {
		if _, ok := req.(ipc.Output); ok {
			<-release
		}
		return honest("")(f, req)
	})
	wrote := make(chan struct{})
	go func() { h.e.Write([]byte("x")); close(wrote) }()
	// The Output is with emu (it holds reqMu until answered); now the
	// window changes.
	for deadline := time.Now().Add(5 * time.Second); h.e.reqMu.TryLock(); {
		h.e.reqMu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("the Output never went out")
		}
		time.Sleep(time.Millisecond)
	}
	resized := make(chan struct{})
	go func() { h.e.Resize(80, 30); close(resized) }()
	for {
		h.e.mu.Lock()
		rows := h.e.rows
		h.e.mu.Unlock()
		if rows == 30 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	for _, done := range []chan struct{}{wrote, resized} {
		select {
		case k := <-h.kills:
			t.Fatalf("emu was killed (KillEmu{%d, %d}) for answering at the old size", k.gen, k.why)
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("the Output or the Resize never finished")
		}
	}
	h.wantNoKill()
	if c, r := h.snapshot().Size(); c != 80 || r != 30 {
		t.Errorf("the mirror is %dx%d after the resize", c, r)
	}
}

// scroll is an answer that puts n new lines, named from at, into the fake
// emu's history, then answers honestly.
func scroll(at *int, n int) answerFunc {
	return func(f *fakeEmu, req ipc.Message) []ipc.Message {
		f.mu.Lock()
		var lines [][]screen.Cell
		for range n {
			l := screen.NewGrid(10, 1)
			for i, r := range fmt.Sprintf("L%d", *at) {
				l.SetCell(i, 0, screen.Cell{Text: string(r), Width: 1})
			}
			lines = append(lines, l.Row(0))
			*at++
		}
		f.screen.History = f.screen.History.Add(f.screen.History.Next+uint64(n), lines)
		f.mu.Unlock()
		return honest("")(f, req)
	}
}

// proto numbers the session's history itself: a rebuilt emu numbers its
// own from 0 again, and the client's numbers carry on (screen.md §7.2).
func TestProtoNumbersTheHistoryAcrossARebuild(t *testing.T) {
	h := newEmuHarness(t, 20, 5)
	at := 0
	h.link(ipc.EmuFirst, scroll(&at, 3))
	h.e.Write([]byte("x"))
	if g := h.snapshot(); g.History.Next != 3 {
		t.Fatalf("next %d after the first emu's lines", g.History.Next)
	}
	h.link(ipc.EmuSignalled, scroll(&at, 2))
	h.e.Write([]byte("y"))
	g := h.snapshot()
	if g.History.Next != 5 || len(g.History.Lines) != 5 {
		t.Fatalf("next %d with %d lines after the rebuild", g.History.Next, len(g.History.Lines))
	}
	for i, l := range g.History.Lines {
		if got, want := l[0].Text+l[1].Text, fmt.Sprintf("L%d", i); got != want {
			t.Errorf("line %d starts %q, want %q", i, got, want)
		}
	}
	h.wantNoKill()
}

// A rise in emu's history that would wrap proto's numbering is a
// violation, and changes nothing.
func TestAHistoryThatWouldWrapTheNumberingIsAViolation(t *testing.T) {
	h := newEmuHarness(t, 20, 5)
	at := 0
	h.link(ipc.EmuFirst, scroll(&at, 1500))
	h.e.Write([]byte("x"))
	h.link(ipc.EmuSignalled, func(f *fakeEmu, req ipc.Message) []ipc.Message {
		f.mu.Lock()
		f.screen.History = f.screen.History.Add(^uint64(0)-screen.HistoryLines, nil)
		f.mu.Unlock()
		return honest("")(f, req)
	})
	before := h.snapshot()
	go h.e.Write([]byte("y"))
	h.wantKill(ipc.KillViolation)
	if after := h.snapshot(); !after.History.Equal(before.History) {
		t.Errorf("a refused update changed the history: next %d, was %d", after.History.Next, before.History.Next)
	}
}
