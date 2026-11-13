package predict

import (
	"strings"
	"testing"
	"time"

	"mosey.spike/s6-prediction/screen"
)

// srv builds a server screen with the given rows and cursor.
func srv(w, h, cx, cy int, rows ...string) *screen.Screen {
	s := screen.New(w, h)
	for y, r := range rows {
		x := 0
		for _, ch := range r {
			s.Set(x, y, screen.Cell{Text: string(ch), Width: 1})
			x++
		}
	}
	s.CurX, s.CurY = cx, cy
	return s
}

func shownText(e *Engine, w int) string {
	cells, _, _, _ := e.Display()
	row := make([]string, w)
	for i := range row {
		row[i] = "."
	}
	for _, c := range cells {
		if c.Y == 0 {
			if c.Cell.Width == 0 {
				row[c.X] = "_"
			} else {
				row[c.X] = c.Cell.Text
			}
		}
	}
	return strings.TrimRight(strings.Join(row, ""), ".")
}

func TestTentativeThenConfirmed(t *testing.T) {
	e := New(Mosey(), srv(20, 2, 2, 0, "$ "))
	e.Input([]byte("l"))
	if got := shownText(e, 20); got != "" {
		t.Fatalf("tentative epoch should be hidden, shown %q", got)
	}
	// server echoes "l" and acks key 1
	e.Frame(time.Second, srv(20, 2, 3, 0, "$ l"), 1, 1)
	e.Input([]byte("s"))
	if got := shownText(e, 20); got != "...s" {
		t.Fatalf("confirmed epoch should show next key, got %q", got)
	}
	_, cx, _, _ := e.Display()
	if cx != 4 {
		t.Fatalf("cursor %d want 4", cx)
	}
}

func TestMispredictionKills(t *testing.T) {
	e := New(Mosey(), srv(20, 2, 2, 0, "$ "))
	e.Input([]byte("a"))
	e.Frame(time.Second, srv(20, 2, 3, 0, "$ a"), 1, 1)
	e.Input([]byte("b")) // displayed
	if shownText(e, 20) != "...b" {
		t.Fatal("expected b displayed")
	}
	// the application did something else
	e.Frame(2*time.Second, srv(20, 2, 3, 0, "$ aX"), 2, 2)
	if got := shownText(e, 20); got != "" {
		t.Fatalf("wrong prediction must be removed, got %q", got)
	}
	if e.VisibleWrong != 1 {
		t.Fatalf("VisibleWrong=%d", e.VisibleWrong)
	}
}

func TestPasswordNeverShown(t *testing.T) {
	e := New(Mosey(), srv(20, 2, 4, 0, "pw: "))
	for i, c := range "secret" {
		e.Input([]byte(string(c)))
		// server never echoes; cursor stays
		e.Frame(time.Duration(i+1)*time.Second, srv(20, 2, 4, 0, "pw: "), uint64(i+1), uint64(i+1))
		if got := shownText(e, 20); got != "" {
			t.Fatalf("password char displayed: %q", got)
		}
	}
}

func TestWideChar(t *testing.T) {
	e := New(Mosey(), srv(20, 2, 2, 0, "$ "))
	e.Input([]byte("a"))
	e.Frame(time.Second, srv(20, 2, 3, 0, "$ a"), 1, 1)
	e.Input([]byte("日"))
	if got := shownText(e, 20); got != "...日_" {
		t.Fatalf("got %q", got)
	}
	_, cx, _, _ := e.Display()
	if cx != 5 {
		t.Fatalf("cursor %d want 5", cx)
	}
	// with wide chars off, the key is unpredictable
	c := Mosey()
	c.WideChars = false
	e2 := New(c, srv(20, 2, 3, 0, "$ a"))
	e2.Input([]byte("b"))
	e2.Frame(time.Second, srv(20, 2, 4, 0, "$ ab"), 1, 1)
	e2.Input([]byte("日"))
	if e2.Predicted(2) {
		t.Fatal("wide char predicted with WideChars=false")
	}
}

func TestHostileLimits(t *testing.T) {
	e := New(Mosey(), srv(80, 2, 2, 0, "$ "))
	e.Input([]byte(strings.Repeat("x", 500))) // a paste
	if e.Predicted(1) {
		t.Fatal("paste must not be predicted")
	}
	e = New(Mosey(), srv(80, 2, 2, 0, "$ "))
	e.Input([]byte("e" + strings.Repeat("́", 20))) // zalgo cluster
	if e.Predicted(1) {
		t.Fatal("oversized grapheme cluster predicted")
	}
	e = New(Mosey(), srv(80, 2, 2, 0, "$ "))
	e.Input([]byte("‮")) // RLO
	if e.Predicted(1) {
		t.Fatal("bidi control predicted")
	}
	// pending cells are bounded even with a server that never acks
	c := Mosey()
	c.MaxPendingCells = 64
	c.Recovery = RecoverBlind
	e = New(c, srv(200, 50, 0, 0))
	for i := 0; i < 10000; i++ {
		e.Input([]byte("z"))
	}
	if e.Pending() > 64+200 {
		t.Fatalf("pending=%d", e.Pending())
	}
}

func TestGhostSuffixConsumed(t *testing.T) {
	// "$ g" typed, autosuggestion "it status" in grey after the cursor
	s := srv(30, 2, 3, 0, "$ git status")
	for x := 3; x < 12; x++ {
		c := s.At(x, 0)
		c.Style.Fg = 8 + 1
		s.Set(x, 0, c)
	}
	e := New(Mosey(), srv(30, 2, 2, 0, "$ "))
	e.Input([]byte("g"))
	e.Frame(time.Second, s, 1, 1)
	e.Input([]byte("i"))
	// only the typed cell is predicted; the ghost is not shifted
	if got := shownText(e, 30); got != "...i" {
		t.Fatalf("got %q", got)
	}
	// naive insert model: the predicted blanks right of "g" are refuted by
	// the ghost text appearing, so the epoch dies and nothing is shown
	c := Mosey()
	c.Shift = ShiftRow
	c.GhostAware = false
	e2 := New(c, srv(30, 2, 2, 0, "$ "))
	e2.Input([]byte("g"))
	e2.Frame(time.Second, s, 1, 1)
	e2.Input([]byte("i"))
	if got := shownText(e2, 30); got != "" || e2.Kills != 1 {
		t.Fatalf("got %q kills=%d", got, e2.Kills)
	}
}

func TestRebaseAfterKill(t *testing.T) {
	c := Mosey()
	c.Recovery = RecoverRebase
	e := New(c, srv(30, 2, 2, 0, "$ "))
	e.Input([]byte("i"))  // 1: (vi-like) not echoed
	e.Input([]byte("ab")) // 2: actually two keys in one event
	// server: key 1 swallowed, key 2 typed "ab" at col 2; echoAck 1, received 2
	e.Frame(time.Second, srv(30, 2, 4, 0, "$ ab"), 1, 2)
	e.Input([]byte("c")) // 3: rebased chain predicts at col 4
	e.Frame(2*time.Second, srv(30, 2, 5, 0, "$ abc"), 3, 3)
	e.Input([]byte("d"))
	if got := shownText(e, 30); got != ".....d" {
		t.Fatalf("got %q", got)
	}
}

// Type-ahead at a no-echo prompt plus a coincidental match (another process
// writes the same glyph at the cursor). Without the echo-off bit the epoch
// confirms and the next password key is drawn; with it nothing is drawn and
// nothing is logged.
func TestEchoOffCoincidentalMatch(t *testing.T) {
	for _, use := range []bool{false, true} {
		c := Mosey()
		c.UseEchoOff = use
		e := New(c, srv(20, 2, 4, 0, "pw: "))
		// the frame that shows the prompt says echo is off
		e.FrameEx(time.Second, srv(20, 2, 4, 0, "pw: "), FrameInfo{EchoOff: true})
		e.Input([]byte("x"))
		// `wall` (or another writer) happens to put an "x" at the cursor
		e.FrameEx(2*time.Second, srv(20, 2, 5, 0, "pw: x"), FrameInfo{EchoAck: 1, Received: 1, EchoOff: true})
		e.Input([]byte("y"))
		got := shownText(e, 20)
		if use && (got != "" || e.LogLen() != 0) {
			t.Fatalf("echo-off honoured: shown %q, log %d", got, e.LogLen())
		}
		if !use && got == "" {
			t.Fatal("expected the no-echo-bit engine to leak here; the test no longer demonstrates the risk")
		}
		if !use && got != "" {
			t.Logf("without echo-off bit: password key drawn as %q (the risk the bit removes)", got)
		}
	}
}

func TestLogCopiesInput(t *testing.T) {
	c := Mosey()
	c.Recovery = RecoverRebase
	e := New(c, srv(20, 2, 2, 0, "$ "))
	buf := []byte("a")
	e.Input(buf)
	buf[0] = 'Z' // a terminal read loop reuses its buffer
	if string(e.log[1]) != "a" {
		t.Fatalf("log aliases caller buffer: %q", e.log[1])
	}
}

// More than LogSize keys during an outage: rebase must not replay a log with
// holes; it waits until the server has everything (gate behaviour).
func TestRebaseLogOverflow(t *testing.T) {
	c := Mosey()
	c.Recovery = RecoverRebase
	e := New(c, srv(80, 2, 2, 0, "$ "))
	e.Input([]byte("\r")) // bump: unfounded
	for i := 0; i < LogSize+50; i++ {
		e.Input([]byte("a"))
	}
	if e.LogLen() > LogSize {
		t.Fatalf("log %d > %d", e.LogLen(), LogSize)
	}
	e.Frame(time.Second, srv(80, 2, 2, 1, "$", "$ "), 1, 1) // server has only the Enter
	if e.founded {
		t.Fatal("rebased over a log with holes")
	}
	e.Frame(2*time.Second, srv(80, 2, 2, 1, "$", "$ "), e.Seq(), e.Seq())
	if !e.founded {
		t.Fatal("should found once the server has every key")
	}
}

// The display rule is the exact set of confirmed epochs, not a high-water
// mark: leftovers of an unconfirmed older epoch stay hidden.
func TestExactConfirmedEpochs(t *testing.T) {
	c := Mosey()
	c.Recovery = RecoverBlind
	e := New(c, srv(20, 2, 2, 0, "$ "))
	e.Input([]byte("a")) // epoch 1
	e.bump(e.seq)        // epoch 2
	e.Input([]byte("b")) // epoch 2
	e.confirmed[2] = true
	cells, _, _, _ := e.Display()
	for _, cc := range cells {
		if cc.Seq == 1 {
			t.Fatal("cell of unconfirmed epoch 1 displayed after epoch 2 confirmed")
		}
	}
	if len(cells) == 0 {
		t.Fatal("epoch 2 cell should be displayed")
	}
}

func TestBracketedPaste(t *testing.T) {
	e := New(Mosey(), srv(80, 2, 2, 0, "$ "))
	e.Input([]byte("a"))
	e.Frame(time.Second, srv(80, 2, 3, 0, "$ a"), 1, 1)
	// a short paste delivered in several reads
	for _, b := range []string{"\x1b[200~ls", " -la", "\x1b[201~"} {
		seq := e.Input([]byte(b))
		if e.Predicted(seq) {
			t.Fatalf("paste fragment %q predicted", b)
		}
	}
	e.Frame(2*time.Second, srv(80, 2, 9, 0, "$ als -la"), 4, 4)
	if seq := e.Input([]byte("x")); !e.Predicted(seq) {
		t.Fatal("typing after the paste should be predicted again")
	}
}

// Replays are deterministic: same inputs give identical Display output.
func TestDeterministicDisplay(t *testing.T) {
	run := func() string {
		e := New(Mosey(), srv(40, 2, 2, 0, "$ "))
		e.Input([]byte("a"))
		e.Frame(time.Second, srv(40, 2, 3, 0, "$ a"), 1, 1)
		for _, k := range "bcdefgh" {
			e.Input([]byte(string(k)))
		}
		e.Input([]byte("\x1b[D"))
		e.Input([]byte("\x7f"))
		cells, _, _, _ := e.Display()
		var b strings.Builder
		for _, c := range cells {
			b.WriteString(c.Cell.Text)
		}
		return b.String()
	}
	want := run()
	for i := 0; i < 50; i++ {
		if got := run(); got != want {
			t.Fatalf("nondeterministic: %q vs %q", got, want)
		}
	}
}

// FuzzEngine drives every recovery mode with arbitrary keys AND an arbitrary
// (hostile or buggy) server: random screen sizes, resizes, echo acks and
// received counts that jump, decrease or exceed what was sent, random cell
// contents including reverse-video and ghost-styled cells, and the echo-off
// bit. It checks the resource limits and the core safety property: no cell
// is displayed unless its epoch had a confirmation.
func FuzzEngine(f *testing.F) {
	f.Add([]byte("hello\x7f\x1b[Dworld\r"), []byte{3, 9, 1, 0, 200, 7})
	f.Add([]byte("日本‮\x1b[C"), []byte{9, 1, 2, 3, 4, 5, 6})
	f.Add([]byte("\x1b[200~paste\x1b[201~ab"), []byte{0, 0, 255, 255})
	f.Fuzz(func(t *testing.T, in []byte, srvb []byte) {
		if len(srvb) == 0 {
			srvb = []byte{1}
		}
		sb := func(i int) int { return int(srvb[i%len(srvb)]) }
		for _, rec := range []Recovery{RecoverBlind, RecoverGate, RecoverRebase} {
			c := Mosey()
			c.Recovery = rec
			c.MaxPendingCells = 64 + sb(0) // small enough to bind on big screens
			W, H := 1+sb(1)%120, 1+sb(2)%40
			e := New(c, screen.New(W, H))
			s := screen.New(W, H)
			st := sb(3)%7 + 1
			ix := 0
			for i := 0; i < len(in); i += st {
				j := min(i+st, len(in))
				e.Input(in[i:j])
				ix++
				op := sb(ix)
				// server mutations
				if op%17 == 0 { // resize
					W, H = 1+sb(ix+1)%120, 1+sb(ix+2)%40
					s = screen.New(W, H)
				}
				for _, b := range in[i:j] {
					if b >= 0x20 && b < 0x7f && W > 0 {
						cell := screen.Cell{Text: string(rune(b)), Width: 1}
						switch op % 5 {
						case 1:
							cell.Style.Attrs = screen.AttrReverse
						case 2:
							cell.Style.Fg = 9 // ghost grey
						}
						s.Set(s.CurX, s.CurY, cell)
						s.CurX = (s.CurX + 1) % W
					}
				}
				s.CursorVisible = op%3 != 0
				seq := e.Seq()
				var ack, recv uint64
				switch op % 6 {
				case 0:
					ack, recv = seq, seq
				case 1:
					ack, recv = seq-min(seq, 1), seq
				case 2:
					ack, recv = seq+uint64(sb(ix+3)), seq+uint64(sb(ix+4)) // beyond what was sent
				case 3:
					ack, recv = uint64(sb(ix+3)), uint64(sb(ix+4)) // arbitrary, maybe decreasing
				case 4:
					ack, recv = seq, seq/2 // received < echoAck
				case 5:
					ack, recv = 0, 0
				}
				e.FrameEx(time.Duration(i), s, FrameInfo{EchoAck: ack, Received: recv, EchoOff: op%11 == 0})
				cells, cx, cy, _ := e.Display()
				for _, cc := range cells {
					if cc.X < 0 || cc.X >= W || cc.Y < 0 || cc.Y >= H {
						t.Fatalf("cell out of bounds %+v (%dx%d)", cc, W, H)
					}
				}
				if cx < 0 || cx > W || cy < 0 || cy >= H {
					t.Fatalf("cursor out of bounds %d,%d (%dx%d)", cx, cy, W, H)
				}
				if e.Pending() > c.MaxPendingCells+W {
					t.Fatalf("pending %d > %d+%d", e.Pending(), c.MaxPendingCells, W)
				}
				if e.LogLen() > LogSize {
					t.Fatalf("log %d", e.LogLen())
				}
				if e.CursorPreds() > 1024 || e.Bumps() > 4096 || len(e.confirmed) > 1024 {
					t.Fatalf("unbounded state: curs %d bumps %d confirmed %d", e.CursorPreds(), e.Bumps(), len(e.confirmed))
				}
				if e.shownWithoutConfirmation() {
					t.Fatal("displayed a cell whose epoch was never confirmed")
				}
			}
		}
	})
}
