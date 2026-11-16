package server

import (
	"context"
	"io"
	"os"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/sys/unix"

	"github.com/danielbodart/mosey/internal/ipc"
	"github.com/danielbodart/mosey/internal/pty"
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

// No text, no wait: a session without -type never waits for its shell,
// whose silence would otherwise hold its Ready for TypeWait, and types
// nothing, not even Enter.
func TestNoTextMeansNoWaitAndNothingTyped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		s := &spawner{master: w, spoke: make(chan struct{}), log: discardLog()}
		start := time.Now()
		s.typeInto(t.Context(), "")
		if waited := time.Since(start); waited != 0 {
			t.Errorf("waited %v with no text to type", waited)
		}
		w.Close()
		if b, _ := io.ReadAll(r); len(b) != 0 {
			t.Errorf("typed %q with no text to type", b)
		}
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

// typingOnAPTY runs typeInto("echo hi") on a spawner whose shell has
// spoken and whose tty has lflag, and reports when it has returned.
func typingOnAPTY(t *testing.T, lflag uint32) (slave *os.File, returned *atomic.Bool) {
	t.Helper()
	m, sl, err := pty.Open(pty.Size{Cols: 80, Rows: 24})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close(); sl.Close() })
	setLflag(t, sl, lflag)
	s := &spawner{master: m, spoke: make(chan struct{}), log: discardLog()}
	close(s.spoke)
	returned = new(atomic.Bool)
	go func() {
		s.typeInto(t.Context(), "echo hi")
		returned.Store(true)
	}()
	return sl, returned
}

func setLflag(t *testing.T, slave *os.File, lflag uint32) {
	t.Helper()
	tio, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	tio.Lflag = tio.Lflag&^(unix.ECHO|unix.ICANON) | lflag
	if err := unix.IoctlSetTermios(int(slave.Fd()), unix.TCSETS, tio); err != nil {
		t.Fatal(err)
	}
}

// The shell's first output may come before its line editor has turned
// the tty's echo off, from a profile that sets a window title, say: the
// text waits for the echo to go off, so it shows once, after the prompt.
func TestTheTextWaitsForTheTTYToStopEchoing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		slave, returned := typingOnAPTY(t, unix.ECHO|unix.ICANON)
		time.Sleep(TypeWait / 2)
		synctest.Wait()
		if returned.Load() {
			t.Fatal("typed while the tty still echoed")
		}
		setLflag(t, slave, 0) // readline at its prompt
		time.Sleep(echoPoll)
		synctest.Wait()
		if !returned.Load() {
			t.Fatal("not typed once the tty stopped echoing")
		}
	})
}

// A shell with no line editor echoes through the tty for good: it gets
// its text when TypeWait passes, and the tty's echo is its only one.
func TestATTYThatKeepsEchoingGetsTheTextAtTypeWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, returned := typingOnAPTY(t, unix.ECHO|unix.ICANON)
		time.Sleep(TypeWait - time.Nanosecond)
		synctest.Wait()
		if returned.Load() {
			t.Fatal("typed before TypeWait while the tty echoed")
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		if !returned.Load() {
			t.Fatal("not typed at TypeWait")
		}
	})
}
