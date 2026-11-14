//go:build linux

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/danielbodart/mosey/internal/netsim"
	"github.com/danielbodart/mosey/internal/screen"
	"github.com/danielbodart/mosey/internal/ssp"
	"github.com/danielbodart/mosey/internal/transport"
	"github.com/danielbodart/mosey/internal/userinput"
)

// stubborn is a program that does not read its pty until told to: every
// write the server makes waits on a channel (not a mutex, so the synctest
// bubble sees it durably blocked and time moves on). It prints nothing.
type stubborn struct {
	reading chan struct{} // closed when the program starts reading
	closed  chan struct{}
	once    sync.Once
	mu      sync.Mutex
	got     bytes.Buffer
}

func newStubborn() *stubborn {
	return &stubborn{reading: make(chan struct{}), closed: make(chan struct{})}
}

func (p *stubborn) Read([]byte) (int, error) {
	<-p.closed
	return 0, io.EOF
}

func (p *stubborn) Write(b []byte) (int, error) {
	select {
	case <-p.reading:
	case <-p.closed:
		return 0, io.ErrClosedPipe
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.got.Write(b)
}

func (p *stubborn) read() { close(p.reading) }

func (p *stubborn) received() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return bytes.Clone(p.got.Bytes())
}

func (p *stubborn) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}

func (p *stubborn) Resize(cols, rows int) error { return nil }
func (p *stubborn) EchoOff() (bool, error)      { return false, nil }

// pasteTerminal is the user's terminal holding a paste: the client reads
// it at its own pace, and the test sees how much it has taken.
type pasteTerminal struct {
	mu    sync.Mutex
	paste []byte
	taken int
	quit  chan struct{}
}

func (u *pasteTerminal) Read(p []byte) (int, error) {
	u.mu.Lock()
	if u.taken < len(u.paste) {
		n := copy(p, u.paste[u.taken:])
		u.taken += n
		u.mu.Unlock()
		return n, nil
	}
	u.mu.Unlock()
	<-u.quit
	return 0, io.EOF
}

func (u *pasteTerminal) read() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.taken
}

func (u *pasteTerminal) Write(p []byte) (int, error) { return len(p), nil }
func (u *pasteTerminal) Size() (int, int, error)     { return 80, 24, nil }
func (u *pasteTerminal) Resized() <-chan struct{}    { return nil }
func (u *pasteTerminal) Raw() error                  { return nil }
func (u *pasteTerminal) Restore() error              { return nil }

// paste is n bytes of numbered words, so a byte out of order, lost or
// doubled shows.
func paste(n int) []byte {
	var b bytes.Buffer
	for i := 0; b.Len() < n; i++ {
		fmt.Fprintf(&b, "%07d ", i)
	}
	return b.Bytes()[:n]
}

// Input flow control (ssp.md §10.1, §12): a 1 MB paste into a program that
// does not read its pty stops the client reading its terminal with at most
// MaxPendingInput and one read taken; the server, which would end the
// connection if its stream ran more than RetainBytes past what the pty
// took, carries on; and once the program reads, the whole paste arrives in
// order and the client reads the rest.
func TestAPasteWaitsInTheTerminalWhileTheProgramIsNotReading(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	synctest.Test(t, func(t *testing.T) {
		n := newSimNet(t, netsim.LAN())
		prog := newStubborn()
		user := &pasteTerminal{paste: paste(1 << 20), quit: make(chan struct{})}
		ctx, cancel := context.WithCancel(context.Background())
		served := n.serve(t, ctx, prog)
		ended := n.connect(ctx, user)
		// End both, and wait for them, so the bubble is left with nothing
		// blocked.
		t.Cleanup(func() {
			cancel()
			close(user.quit)
			prog.Close()
			<-served
			<-ended
		})

		// Ten virtual seconds is many round trips on the LAN: whatever the
		// client was going to read without the program reading, it has.
		time.Sleep(10 * time.Second)
		synctest.Wait()
		if got, most := user.read(), userinput.MaxPendingInput+userinput.MaxRead; got > most || got == 0 {
			t.Fatalf("the client read %d bytes of the paste while the program read none; want 1 to %d", got, most)
		}
		select {
		case err := <-served:
			t.Fatalf("the server ended while the program was not reading: %v", err)
		case err := <-ended:
			t.Fatalf("the client ended while the program was not reading: %v", err)
		default:
		}

		prog.read()
		for deadline := time.Now().Add(5 * time.Minute); len(prog.received()) < len(user.paste); {
			if time.Now().After(deadline) {
				t.Fatalf("the program got %d of %d bytes; the client read %d", len(prog.received()), len(user.paste), user.read())
			}
			time.Sleep(100 * time.Millisecond)
		}
		if got := prog.received(); !bytes.Equal(got, user.paste) {
			i := 0
			for i < len(got) && got[i] == user.paste[i] {
				i++
			}
			t.Fatalf("the paste arrived changed from byte %d of %d", i, len(got))
		}
	})
}

// A client that ignores InputConsumed (D4) gains nothing: it can push its
// stream on as fast as the server acknowledges, but the server keeps only
// RetainBytes of it, and once the program reads and the server finds
// input forgotten before it was written, it drops that client's
// connection rather than skip it (ssp.md §10.1). The session itself runs
// on for a resume (bootstrap.md §9.3): a broken client is one that left.
func TestAClientThatIgnoresFlowControlIsCutOff(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	synctest.Test(t, func(t *testing.T) {
		n := newSimNet(t, netsim.LAN())
		prog := newStubborn()
		ctx, cancel := context.WithCancel(context.Background())
		served := n.serve(t, ctx, prog)
		t.Cleanup(func() {
			cancel()
			prog.Close()
			<-served
		})

		conn, err := transport.Dial(ctx, n.cc, serverAddr, n.cred, n.key, n.log)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		input := userinput.NewStream()
		ep := ssp.NewEndpoint(conn, ssp.Config{
			Role: ssp.Client, MaxPayload: transport.MaxPayload, FrameOverhead: transport.FrameOverhead, MaxRemoteBytes: screen.MaxDiff,
		}, input.Clone(), screen.NewGrid(0, 0))
		go ep.Run(ctx)
		acked := func(within time.Duration) bool {
			for deadline := time.Now().Add(within); ; {
				if a, _ := ep.Acked(); a.Len() == input.Len() {
					return true
				}
				if time.Now().After(deadline) {
					return false
				}
				time.Sleep(10 * time.Millisecond)
			}
		}

		// Keystrokes in diffs well under MaxDiffBytes, each sent once the
		// last is acknowledged, so SSP itself has nothing to refuse; only
		// consumption is ignored.
		chunk := bytes.Repeat([]byte("x"), 32<<10)
		for sent := 0; sent < 4*userinput.RetainBytes; sent += len(chunk) {
			input.Type(chunk)
			ep.Set(input.Clone())
			if !acked(time.Minute) {
				t.Fatalf("the server stopped acknowledging after %d bytes", sent)
			}
		}

		prog.read()
		// Dropped: what it sends now is never acknowledged.
		time.Sleep(time.Second)
		input.Type([]byte("more"))
		ep.Set(input.Clone())
		if acked(time.Minute) {
			t.Fatal("the server carried on with a client whose input it had forgotten")
		}
		select {
		case end := <-served:
			t.Fatalf("the session ended (%v): only the client should have gone", end)
		default:
		}
		if got := len(prog.received()); got > userinput.RetainBytes {
			t.Errorf("the program got %d bytes, more than the server could have kept", got)
		}
	})
}
