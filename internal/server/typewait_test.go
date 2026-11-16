package server

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"testing/synctest"
)

// chunkTerminal is a pty whose reads return what the test feeds it, one
// chunk at a time, and EOF once the feed closes.
type chunkTerminal struct{ feed chan []byte }

func (c chunkTerminal) Read(p []byte) (int, error) {
	b, ok := <-c.feed
	if !ok {
		return 0, io.EOF
	}
	return copy(p, b), nil
}

func (chunkTerminal) Write(b []byte) (int, error) { return len(b), nil }
func (chunkTerminal) Resize(int, int) error       { return nil }
func (chunkTerminal) EchoOff() (bool, error)      { return false, nil }

// The pty reader says the shell has written only once it has read bytes
// from the pty, and says it once however much more the shell writes: what
// the spawner waits for before it types -type's text (bootstrap.md
// §9.2.3).
func TestFirstOutputIsReportedOnceAfterTheShellWrites(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		term := chunkTerminal{feed: make(chan []byte)}
		var calls atomic.Int32
		s := &Session{Terminal: term, Emulator: promptEmu{}, FirstOutput: func() { calls.Add(1) }}
		s.init()
		done := make(chan struct{})
		go func() {
			s.readPTY(context.Background())
			close(done)
		}()

		synctest.Wait()
		if n := calls.Load(); n != 0 {
			t.Fatalf("FirstOutput called %d times before the shell wrote anything", n)
		}
		term.feed <- []byte("$ ")
		synctest.Wait()
		if n := calls.Load(); n != 1 {
			t.Fatalf("FirstOutput called %d times after the prompt, want 1", n)
		}
		term.feed <- []byte("more")
		term.feed <- []byte("and more")
		close(term.feed)
		<-done
		if n := calls.Load(); n != 1 {
			t.Errorf("FirstOutput called %d times in all, want 1", n)
		}
	})
}

// T3 for the credential and then TypeWait for the shell's first output
// both come before Ready, so together they stay inside the launcher's T2.
func TestTheTypeWaitLeavesReadyInsideT2(t *testing.T) {
	if T3+TypeWait >= T2 {
		t.Errorf("T3 %v + TypeWait %v is not inside T2 %v", T3, TypeWait, T2)
	}
}
