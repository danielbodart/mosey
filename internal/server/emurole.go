package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/danielbodart/mosey/internal/emu"
	"github.com/danielbodart/mosey/internal/ipc"
	"github.com/danielbodart/mosey/internal/sandbox"
	"github.com/danielbodart/mosey/internal/screen"
)

// RunEmu is the emu role's main (server.md §6.1): it wraps the socket it
// was started with, enters the sandbox, and only then reads, answering
// Output, Resize and Flush with Replies and Update until proto closes the
// socket. Its memory limit was set by the spawner before proto got the
// other end.
func RunEmu(ctx context.Context, ipcFD *os.File, log *slog.Logger) error {
	if err := sandbox.NotDumpable(); err != nil {
		return err
	}
	conn, err := wrapRoleSocket(ipcFD, ipc.Emu, ipc.Proto)
	if err != nil {
		return err
	}
	// The emulator is made after Init arrives, inside the sandbox, so any
	// syscall it makes is one the soak sees.
	settleLazyInit()
	if err := sandbox.Enter(sandbox.Emu, sandbox.DefaultAction(), sandbox.Params{}, func(w string) { log.Warn(w) }); err != nil {
		return fmt.Errorf("entering the sandbox: %w", err)
	}
	churn()
	return serveEmu(ctx, conn, newEmulator, log)
}

// settleLazyInit does, before the sandbox, the work the standard library
// otherwise does lazily on first use, which would be a syscall the policy
// lacks. The one found so far: the first log timestamp loads the local time
// zone by opening /etc/localtime (found under Kill by TestASessionRunsUnderKill).
// The roles have no TZ and log to the spawner, so they log in UTC.
func settleLazyInit() {
	time.Local = time.UTC
}

// wrapRoleSocket checks that fd is the seqpacket socket a role is started
// with and wraps it; before the sandbox, which denies getsockopt.
//
// f was made by os.NewFile on an fd that exec.Cmd.ExtraFiles left in
// blocking mode, so it cannot be polled and has no deadlines. Rather than
// make a second *os.File on the same fd (whose finalizer would close it
// under the first), the fd is duplicated, close-on-exec, the duplicate is
// made pollable, and f is closed.
func wrapRoleSocket(f *os.File, self, peer ipc.Peer) (*ipc.Conn, error) {
	defer f.Close()
	raw, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}
	var fd int
	var derr error
	if err := raw.Control(func(x uintptr) {
		if derr = ipc.CheckSeqpacket(int(x)); derr == nil {
			fd, derr = unix.FcntlInt(x, unix.F_DUPFD_CLOEXEC, 0)
		}
	}); err != nil {
		return nil, err
	}
	if derr != nil {
		return nil, fmt.Errorf("taking over the IPC socket: %w", derr)
	}
	w, err := ipc.Wrap(fd, "ipc")
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	return ipc.NewConn(w, self, peer)
}

func newEmulator(m ipc.Init) (emu.Emulator, error) {
	opts := emu.Options{
		ScrollbackCells: int(m.ScrollbackCells),
		Foreground:      screen.Color(m.Foreground),
		Background:      screen.Color(m.Background),
	}
	for i, c := range m.Palette {
		opts.Palette[i] = screen.Color(c)
	}
	return emu.New(int(m.Cols), int(m.Rows), opts)
}

// errEmuProtocol is emu's refusal of what proto sent: proto is more trusted
// than emu, so it only fires on a bug, and emu exits for the spawner to
// restart it (server.md §3.5).
var errEmuProtocol = errors.New("emu: protocol error from proto")

// serveEmu is emu's loop: strictly request and response, never speaking
// unasked. Each answer is at most one Replies, then the diff from the last
// screen it sent to now, in Update fragments.
func serveEmu(ctx context.Context, conn *ipc.Conn, newEmu func(ipc.Init) (emu.Emulator, error), log *slog.Logger) error {
	defer conn.Close()
	first, err := conn.Recv()
	if err != nil {
		if ipc.IsEOF(err) {
			return nil
		}
		return err
	}
	init, ok := first.(ipc.Init)
	if !ok {
		return fmt.Errorf("%w: first message %T, not Init", errEmuProtocol, first)
	}
	em, err := newEmu(init)
	if err != nil {
		return err
	}
	defer em.Close()
	// The first answer is a diff from a blank grid at Init's size
	// (screen.md §7.1), which is what proto's fresh mirror is.
	sent := screen.NewGrid(int(init.Cols), int(init.Rows))
	answer := func(replies bool) error {
		if replies {
			if r := em.TakeReplies(); len(r) > ipc.MaxReplies {
				// More than any honest program asks for at once: drop it
				// all rather than send a cut answer.
				log.Warn("replies over the limit dropped", "bytes", len(r))
			} else if len(r) > 0 {
				if err := conn.Send(ipc.Replies{Data: r}); err != nil {
					return err
				}
			}
		}
		// While a program holds a synchronised update open, the snapshot is
		// the screen from before it, so the diff is empty and the answer
		// says HELD; proto asks again with Flush (screen.md §6.3).
		now := screen.NewGrid(0, 0)
		held := snapshot(em, now)
		diff := now.Diff(sent)
		sent = now
		return sendDiff(conn, diff, held)
	}
	if err := answer(false); err != nil {
		return err
	}
	for ctx.Err() == nil {
		m, err := conn.Recv()
		if err != nil {
			if ipc.IsEOF(err) {
				return nil
			}
			return err
		}
		switch m := m.(type) {
		case ipc.Output:
			em.Write(m.Data)
			err = answer(true)
		case ipc.Resize:
			em.Resize(int(m.Cols), int(m.Rows))
			err = answer(false)
		case ipc.Flush:
			err = answer(false)
		default:
			return fmt.Errorf("%w: %T", errEmuProtocol, m)
		}
		if err != nil {
			return err
		}
	}
	return ctx.Err()
}

// sendDiff sends diff as a run of Update fragments, the last with MORE
// clear; an empty diff is one empty fragment.
func sendDiff(conn *ipc.Conn, diff []byte, held bool) error {
	for {
		n := min(len(diff), ipc.MaxFragment)
		more := n < len(diff)
		if err := conn.Send(ipc.Update{More: more, Held: held && !more, Fragment: diff[:n]}); err != nil {
			return err
		}
		diff = diff[n:]
		if !more {
			return nil
		}
	}
}
