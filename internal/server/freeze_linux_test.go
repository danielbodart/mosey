package server

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/danielbodart/mosey/internal/emu"
	"github.com/danielbodart/mosey/internal/handshake"
	"github.com/danielbodart/mosey/internal/pty"
	"github.com/danielbodart/mosey/internal/screen"
	"github.com/danielbodart/mosey/internal/transport"
)

// textOf is a grid's text, row by row.
func textOf(g *screen.Grid) string {
	var b strings.Builder
	_, rows := g.Size()
	for y := range rows {
		for _, c := range g.Row(y) {
			if c.Text == "" && c.Width == 1 {
				b.WriteByte(' ') // a blank cell
			}
			b.WriteString(c.Text)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// eventually polls cond until it holds or a generous deadline passes; it
// asserts nothing about how long that took.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Freeze, for a live upgrade (server.md §2.8 step 4), returns the screen
// with everything the shell had written, then holds the reader off the
// pty: output written meanwhile stays in the pty, and after Thaw it is
// read and drawn, none of it lost.
func TestFreezeHoldsThePTYAndThawLosesNothing(t *testing.T) {
	master, slave, err := pty.Open(pty.Size{Cols: 80, Rows: 24})
	if err != nil {
		t.Skip(err)
	}
	defer slave.Close()
	em, err := emu.New(80, 24, emu.Options{})
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	s := &Session{
		Listener: transport.Listen(udp, handshake.NewCredentials(nil), nil),
		Terminal: ptyTerminal{master},
		Emulator: em,
		Adopted:  true,
	}
	s.init() // so the test can look at s.em before Run has started
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	defer func() { cancel(); <-done }()

	shows := func(text string) bool {
		select {
		case err := <-done:
			t.Fatalf("the session ended: %v", err)
		default:
		}
		g := screen.NewGrid(0, 0)
		snapshot(s.em, g)
		return strings.Contains(textOf(g), text)
	}
	slave.Write([]byte("before the freeze\r\n"))
	eventually(t, "the output to reach the emulator", func() bool { return shows("before the freeze") })

	g, err := s.Freeze()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(textOf(g), "before the freeze") {
		t.Fatalf("the frozen screen lacks the output before it:\n%s", textOf(g))
	}
	slave.Write([]byte("while frozen\r\n"))
	// Nothing draws it while frozen: the reader is parked. (A short
	// look, not a measurement: it only has to see the reader is not
	// reading.)
	time.Sleep(200 * time.Millisecond)
	if shows("while frozen") {
		t.Fatal("a frozen session read the pty")
	}
	if _, err := s.Freeze(); err == nil {
		t.Error("a second Freeze succeeded")
	}
	s.Thaw()
	eventually(t, "the output written while frozen", func() bool { return shows("while frozen") })
	// And it carries on as before.
	slave.Write([]byte("after the thaw\r\n"))
	eventually(t, "the output after the thaw", func() bool { return shows("after the thaw") })
}
