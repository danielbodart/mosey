package server

import (
	"context"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/danielbodart/mosey/internal/screen"
	"github.com/danielbodart/mosey/internal/ssp"
	"github.com/danielbodart/mosey/internal/transport"
	"github.com/danielbodart/mosey/internal/userinput"
)

// pipeDatagrams is one end of a lossless in-memory path for SSP.
type pipeDatagrams struct {
	out, in chan []byte
}

func datagramPair() (a, b pipeDatagrams) {
	ab, ba := make(chan []byte, 64), make(chan []byte, 64)
	return pipeDatagrams{out: ab, in: ba}, pipeDatagrams{out: ba, in: ab}
}

func (p pipeDatagrams) Send(b []byte) error {
	select {
	case p.out <- append([]byte(nil), b...):
	default: // full: lost, as a datagram may be
	}
	return nil
}

func (p pipeDatagrams) Recv(ctx context.Context) ([]byte, error) {
	select {
	case b := <-p.in:
		return b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// silentPrompt is a program that has printed its password prompt and
// then, with no further output, turns echo off: the termios change came
// after the screen with the prompt was taken (prediction.md §3.1 rule 6).
// It records what had been published when each key reached it.
type silentPrompt struct {
	s  *Session
	mu sync.Mutex
	// off is the pty's echo-off bit.
	off bool
	// atWrite is the last published grid's EchoOff and EchoApplied when
	// each key was written.
	atWrite []screen.Grid
}

func (p *silentPrompt) Read([]byte) (int, error) { select {} }

func (p *silentPrompt) Write(b []byte) (int, error) {
	p.s.mu.Lock()
	g := *p.s.published
	p.s.mu.Unlock()
	p.mu.Lock()
	p.atWrite = append(p.atWrite, screen.Grid{EchoOff: g.EchoOff, EchoApplied: g.EchoApplied})
	p.mu.Unlock()
	return len(b), nil // echo is off: nothing is printed
}

func (p *silentPrompt) Resize(int, int) error { return nil }

func (p *silentPrompt) EchoOff() (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.off, nil
}

// promptEmu is an emulator whose screen is always the prompt.
type promptEmu struct{}

func (promptEmu) Write([]byte)        {}
func (promptEmu) Resize(int, int)     {}
func (promptEmu) TakeReplies() []byte { return nil }
func (promptEmu) Close() error        { return nil }
func (promptEmu) Snapshot(g *screen.Grid) {
	g.Resize(20, 2)
	g.SetCell(0, 0, screen.Cell{Text: "P", Width: 1})
	g.SetCell(1, 0, screen.Cell{Text: ":", Width: 1})
}

func TestEchoTurnedOffSilentlyIsPublishedBeforeTheNextKeyIsWritten(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		sd, cd := datagramPair()
		server := ssp.NewEndpoint(sd, ssp.Config{
			Role: ssp.Server, MaxPayload: transport.MaxPayload, FrameOverhead: transport.FrameOverhead,
			MaxRemoteBytes: userinput.MaxDiffBytes,
		}, screen.NewGrid(0, 0), userinput.NewStream())
		client := ssp.NewEndpoint(cd, ssp.Config{
			Role: ssp.Client, MaxPayload: transport.MaxPayload, FrameOverhead: transport.FrameOverhead,
			MaxRemoteBytes: screen.MaxDiff,
		}, userinput.NewStream(), screen.NewGrid(0, 0))

		prog := &silentPrompt{}
		s := &Session{Terminal: prog, Emulator: promptEmu{}}
		prog.s = s
		s.init()
		s.mu.Lock()
		s.ep = server
		s.mu.Unlock()

		var wg sync.WaitGroup
		defer wg.Wait()
		defer cancel()
		wg.Go(func() { server.Run(ctx) })
		wg.Go(func() { client.Run(ctx) })
		wg.Go(func() { s.writePTY(ctx) })
		// The client's view: every screen it is given, in order.
		var seen []screen.Grid
		var seenMu sync.Mutex
		wg.Go(func() {
			for {
				select {
				case <-client.RemoteChanged():
					g, _ := client.Remote()
					seenMu.Lock()
					seen = append(seen, screen.Grid{EchoOff: g.EchoOff, EchoApplied: g.EchoApplied})
					seenMu.Unlock()
				case <-ctx.Done():
					return
				}
			}
		})

		// The prompt's screen is published while echo is still on.
		s.publish()
		time.Sleep(time.Second)
		// Then the program turns echo off and prints nothing.
		prog.mu.Lock()
		prog.off = true
		prog.mu.Unlock()
		time.Sleep(time.Second)

		input := userinput.NewStream()
		input.Type([]byte("s"))
		client.Set(input.Clone())
		time.Sleep(time.Second)

		prog.mu.Lock()
		atWrite := prog.atWrite
		prog.mu.Unlock()
		if len(atWrite) != 1 {
			t.Fatalf("%d keys reached the program, want 1", len(atWrite))
		}
		if !atWrite[0].EchoOff || atWrite[0].EchoApplied != 0 {
			t.Fatalf("when the key was written the screen published had echo-off %v and applied %d, want true and 0",
				atWrite[0].EchoOff, atWrite[0].EchoApplied)
		}
		// The client learns echo is off from a frame that does not yet
		// count the key: it stops predicting before the password.
		seenMu.Lock()
		defer seenMu.Unlock()
		for _, g := range seen {
			if g.EchoOff {
				if g.EchoApplied != 0 {
					t.Fatalf("the client first saw echo off in a frame with applied %d, after the key", g.EchoApplied)
				}
				return
			}
		}
		t.Fatalf("the client never saw echo off; it saw %d screens", len(seen))
	})
}
