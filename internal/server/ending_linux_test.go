package server

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	"github.com/danielbodart/mosey/internal/emu"
	"github.com/danielbodart/mosey/internal/handshake"
	"github.com/danielbodart/mosey/internal/pty"
	"github.com/danielbodart/mosey/internal/transport"
)

// closeWatch is an emulator that says whether it has been closed.
type closeWatch struct {
	emu.Emulator
	closed atomic.Bool
}

func (c *closeWatch) Close() error {
	c.closed.Store(true)
	return c.Emulator.Close()
}

// A session tells Ending how it ended while the emulator is still open:
// proto sends Exit then, so the spawner hears the session is over before
// emu's socket closes, and never takes emu's exit at the end for a death
// to restart (server.md §2.4, §5.2).
func TestASessionSaysItIsEndingBeforeItClosesTheEmulator(t *testing.T) {
	master, slave, err := pty.Open(pty.Size{Cols: 80, Rows: 24})
	if err != nil {
		t.Skip(err)
	}
	inner, err := emu.New(80, 24, emu.Options{})
	if err != nil {
		t.Fatal(err)
	}
	em := &closeWatch{Emulator: inner}
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	var calls atomic.Int32
	var closedWhenEnding atomic.Bool
	var ended atomic.Value
	s := &Session{
		Listener: transport.Listen(udp, handshake.NewCredentials(nil), nil),
		Terminal: ptyTerminal{master},
		Emulator: em,
		Ending: func(err error) {
			calls.Add(1)
			closedWhenEnding.Store(em.closed.Load())
			ended.Store(errBox{err})
		},
	}
	done := make(chan error, 1)
	go func() { done <- s.Run(context.Background()) }()
	// The last slave closing is the shell exiting: the reader sees EIO.
	slave.Close()
	err = <-done
	s.Listener.Close()
	if err != nil {
		t.Fatalf("Run returned %v for a shell that exited", err)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("Ending was called %d times", n)
	}
	if closedWhenEnding.Load() {
		t.Error("the emulator was closed before Ending was called")
	}
	if got := ended.Load().(errBox).err; got != nil {
		t.Errorf("Ending was told %v, not what Run returned", got)
	}
	if !em.closed.Load() {
		t.Error("Run returned without closing the emulator")
	}
}

// errBox lets atomic.Value hold a nil error.
type errBox struct{ err error }
