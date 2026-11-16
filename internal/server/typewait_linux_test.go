package server

import (
	"context"
	"io"
	"os"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/danielbodart/mosey/internal/ipc"
)

// typing runs typeInto("echo hi") on a spawner whose master is a pipe,
// and reports whether it has returned and what reached the pipe.
type typing struct {
	s        *spawner
	returned atomic.Bool
	got      chan string
}

func startTyping(t *testing.T, ctx context.Context) *typing {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	ty := &typing{s: &spawner{master: w, spoke: make(chan struct{}), log: discardLog()}, got: make(chan string, 1)}
	go func() {
		ty.s.typeInto(ctx, "echo hi")
		ty.returned.Store(true)
		w.Close()
		b, _ := io.ReadAll(r)
		ty.got <- string(b)
	}()
	return ty
}

// -type's text waits for the shell's first output, so it is typed after
// the prompt and shows once; then it goes in one write with Enter's CR.
func TestTheTextIsTypedOnceTheShellHasWritten(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ty := startTyping(t, t.Context())
		synctest.Wait()
		if ty.returned.Load() {
			t.Fatal("typed before the shell wrote anything")
		}
		close(ty.s.spoke)
		if got := <-ty.got; got != "echo hi\r" {
			t.Errorf("typed %q, want %q", got, "echo hi\r")
		}
	})
}

// A shell that writes nothing, or whose rc files take longer than
// TypeWait, still gets the text, TypeWait late: the wait only delays it.
func TestTheTextIsTypedAnywayAfterTypeWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ty := startTyping(t, t.Context())
		time.Sleep(TypeWait - time.Nanosecond)
		synctest.Wait()
		if ty.returned.Load() {
			t.Fatal("typed before TypeWait with no output from the shell")
		}
		time.Sleep(time.Nanosecond)
		if got := <-ty.got; got != "echo hi\r" {
			t.Errorf("typed %q, want %q", got, "echo hi\r")
		}
	})
}

// A session cancelled while waiting types nothing.
func TestACancelledSessionTypesNothing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		ty := startTyping(t, ctx)
		synctest.Wait()
		cancel()
		if got := <-ty.got; got != "" {
			t.Errorf("typed %q after the session was cancelled", got)
		}
	})
}

// No text, no wait: a session without -type never waits for its shell.
func TestNoTextMeansNoWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := &spawner{log: discardLog()}
		s.typeInto(t.Context(), "")
	})
}

// proto's FirstOutput ends typeInto's wait and goes no further: the
// supervision loop, which takes any other type after the bootstrap for a
// violation, never sees it, and a second one changes nothing (server.md
// §3.4).
func TestFirstOutputClosesSpokeAndNeverReachesTheSupervisionLoop(t *testing.T) {
	local, remote, err := ipc.Pair()
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	proto, err := ipc.NewConn(remote, ipc.Proto, ipc.Spawner)
	if err != nil {
		t.Fatal(err)
	}
	s := &spawner{log: discardLog()}
	if s.ctl, err = ipc.NewConn(local, ipc.Spawner, ipc.Proto); err != nil {
		t.Fatal(err)
	}
	defer s.ctl.Close()
	s.readCtl()
	for _, m := range []ipc.Message{ipc.FirstOutput{}, ipc.FirstOutput{}, ipc.Detached{}} {
		if err := proto.Send(m); err != nil {
			t.Fatal(err)
		}
	}
	<-s.spoke
	if ev := <-s.ctlMsgs; ev.err != nil || ev.m != (ipc.Detached{}) {
		t.Errorf("the supervision loop got %#v, %v; want Detached", ev.m, ev.err)
	}
}
