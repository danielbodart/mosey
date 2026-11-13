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

func FuzzEngine(f *testing.F) {
	f.Add([]byte("hello\x7f\x1b[Dworld\r"), uint8(3))
	f.Add([]byte("日本‮\x1b[C"), uint8(9))
	f.Fuzz(func(t *testing.T, in []byte, step uint8) {
		for _, rec := range []Recovery{RecoverBlind, RecoverGate, RecoverRebase} {
			c := Mosey()
			c.Recovery = rec
			e := New(c, srv(10, 3, 0, 0))
			s := srv(10, 3, 0, 0)
			st := int(step%7) + 1
			for i := 0; i < len(in); i += st {
				j := min(i+st, len(in))
				e.Input(in[i:j])
				// a server that echoes raw bytes into a tiny screen
				for _, b := range in[i:j] {
					if b >= 0x20 && b < 0x7f {
						s.Set(s.CurX, s.CurY, screen.Cell{Text: string(rune(b)), Width: 1})
						s.CurX = (s.CurX + 1) % s.W
					}
				}
				e.Frame(time.Duration(i), s, e.Seq()-uint64(step%2), e.Seq())
				cells, cx, cy, _ := e.Display()
				for _, cc := range cells {
					if cc.X < 0 || cc.X >= 10 || cc.Y < 0 || cc.Y >= 3 {
						t.Fatalf("cell out of bounds %+v", cc)
					}
				}
				if cx < 0 || cx > 10 || cy < 0 || cy >= 3 {
					t.Fatalf("cursor out of bounds %d,%d", cx, cy)
				}
			}
		}
	})
}
