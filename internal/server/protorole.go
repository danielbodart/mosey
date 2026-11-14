package server

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/danielbodart/mosey/internal/bootstrap"
	"github.com/danielbodart/mosey/internal/emu"
	"github.com/danielbodart/mosey/internal/handshake"
	"github.com/danielbodart/mosey/internal/ipc"
	"github.com/danielbodart/mosey/internal/pty"
	"github.com/danielbodart/mosey/internal/sandbox"
	"github.com/danielbodart/mosey/internal/screen"
	"github.com/danielbodart/mosey/internal/transport"
)

// T3 bounds the bootstrap's inner steps: the spawner waiting for proto's
// Credential, and proto waiting for Start (server.md §8) [derived].
const T3 = 10 * time.Second

// RunProto is the proto role's main (server.md §6.1): it wraps the socket
// it was started with, receives the UDP socket and the pty master, enters
// the sandbox, and only then talks to emu, mints the credential and serves
// the Session. version is this binary's, which the credential line
// carries.
func RunProto(ctx context.Context, ipcFD *os.File, version string, log *slog.Logger) error {
	// First of all, before anything holds a key: with dumpable left at 1 a
	// seccomp kill writes a core holding the keys (S4 §3.5).
	if err := sandbox.NotDumpable(); err != nil {
		return err
	}
	ctl, err := wrapRoleSocket(ipcFD, ipc.Proto, ipc.Spawner)
	if err != nil {
		return err
	}
	defer ctl.Close()

	ctl.File().SetReadDeadline(time.Now().Add(T3))
	m, err := ctl.Recv()
	if err != nil {
		return fmt.Errorf("waiting for Start: %w", err)
	}
	start, ok := m.(ipc.Start)
	if !ok {
		return fmt.Errorf("the spawner's first message is %T, not Start", m)
	}
	m, err = ctl.Recv()
	if err != nil {
		return fmt.Errorf("waiting for EmuLink: %w", err)
	}
	link, ok := m.(ipc.EmuLink)
	if !ok || link.Generation != 1 {
		return fmt.Errorf("the spawner's second message is %T, not the first EmuLink", m)
	}
	ctl.File().SetReadDeadline(time.Time{})

	// net.FilePacketConn needs getsockopt, getsockname and getpeername,
	// which the policy does not have: wrap the socket now (S4 §3.3).
	pc, err := net.FilePacketConn(start.UDP)
	start.UDP.Close()
	if err != nil {
		return fmt.Errorf("wrapping the UDP socket: %w", err)
	}
	master := start.PTY
	var ptyFD int
	if raw, err := master.SyscallConn(); err == nil {
		raw.Control(func(fd uintptr) { ptyFD = int(fd) })
	}

	warn := func(w string) { log.Warn(w) }
	settleLazyInit()
	if err := sandbox.Enter(sandbox.Proto, sandbox.DefaultAction(), sandbox.Params{PTY: ptyFD}, warn); err != nil {
		return fmt.Errorf("entering the sandbox: %w", err)
	}
	churn()

	cols, rows := int(start.Cols), int(start.Rows)
	em := newIPCEmulator(cols, rows, defaultInit(), func(gen uint32, why ipc.KillReason) {
		if err := ctl.Send(ipc.KillEmu{Generation: gen, Why: why}); err != nil {
			log.Warn("asking for emu to be killed", "err", err)
		}
	}, log)
	if err := em.attach(link); err != nil {
		return fmt.Errorf("starting emu: %w", err)
	}

	creds := handshake.NewCredentials(log)
	// crypto/rand never fails: the runtime crashes instead (Go 1.24).
	var session [16]byte
	rand.Read(session[:])
	cred, err := creds.Mint(session, start.ClientPublic)
	if err != nil {
		return fmt.Errorf("minting the credential: %w", err)
	}
	line := bootstrap.MarshalCredentialLine(bootstrap.CredentialLine{
		SoftwareVersion: version,
		Addr:            start.Addr,
		Port:            start.Port,
		CredentialID:    cred.ID,
		SessionID:       cred.SessionID,
		PSK:             cred.PSK,
		Public:          cred.ServerPublic,
	})
	if err := ctl.Send(ipc.Credential{Line: line}); err != nil {
		return fmt.Errorf("sending the credential: %w", err)
	}

	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	sess := &Session{
		Listener: transport.Listen(pc, creds, log),
		Terminal: ptyTerminal{master},
		Emulator: em,
		Log:      log,
		Attached: func() {
			if err := ctl.Send(ipc.Attached{}); err != nil {
				log.Warn("telling the spawner a client attached", "err", err)
			}
		},
	}
	em.repaint = sess.Repaint
	go readControl(ctl, em, sess, cancel, log)

	err = sess.Run(ctx)
	sess.Listener.Close()
	exit := ipc.Exit{Code: ipc.ShellExited}
	switch {
	case err == nil:
	case errors.Is(err, ErrNoClient):
		exit = ipc.Exit{Code: ipc.NoClient}
	case errors.Is(err, ErrClientClosed):
		exit = ipc.Exit{Code: ipc.ClientClosed}
	case errors.Is(context.Cause(ctx), errSpawnerGone):
		return nil
	default:
		exit = ipc.Exit{Code: ipc.ExitError, Reason: printableASCII(err.Error(), ipc.MaxExitReason)}
	}
	if serr := ctl.Send(exit); serr != nil {
		log.Warn("telling the spawner the session ended", "err", serr)
	}
	return nil
}

// errSpawnerGone is EOF on C: the spawner ends the session, so proto ends
// at once (server.md §7).
var errSpawnerGone = errors.New("the spawner closed the control socket")

// readControl is proto's C reader: EmuLink, EmuPaused and ShellExit from
// the spawner. A malformed message is a bug in a more trusted process, so
// proto logs it and ends (server.md §5.3).
func readControl(ctl *ipc.Conn, em *ipcEmulator, sess *Session, cancel context.CancelCauseFunc, log *slog.Logger) {
	gen := uint32(1)
	for {
		m, err := ctl.Recv()
		if err != nil {
			if !ipc.IsEOF(err) {
				log.Error("control socket", "err", err)
				cancel(err)
				return
			}
			cancel(errSpawnerGone)
			return
		}
		switch m := m.(type) {
		case ipc.EmuLink:
			if m.Generation != gen+1 {
				m.Conn.Close()
				log.Error("EmuLink out of sequence", "generation", m.Generation, "want", gen+1)
				cancel(fmt.Errorf("EmuLink generation %d after %d", m.Generation, gen))
				return
			}
			gen = m.Generation
			go func() {
				if err := em.attach(m); err != nil {
					log.Warn("attaching emu", "generation", m.Generation, "err", err)
				}
			}()
		case ipc.EmuPaused:
			em.pause(m.Seconds)
		case ipc.ShellExit:
			// The pty reader normally sees EIO first; this ends the
			// session even if a job the shell left holds the slave open.
			log.Info("the shell exited", "status", m.Status)
			sess.ShellExited()
		default:
			log.Error("unexpected control message", "type", fmt.Sprintf("%T", m))
			cancel(fmt.Errorf("unexpected %T from the spawner", m))
			return
		}
	}
}

// defaultInit is Init's colours and budget: slice 1's ClientLine carries no
// colours, so emu answers colour queries with the default throughout
// (server.md §3.3, §11 item 6).
func defaultInit() ipc.Init {
	return ipc.Init{ScrollbackCells: emu.DefaultScrollbackCells}
}

// ptyTerminal is the pty master as a Session's Terminal.
type ptyTerminal struct{ master *os.File }

func (t ptyTerminal) Read(p []byte) (int, error)  { return t.master.Read(p) }
func (t ptyTerminal) Write(p []byte) (int, error) { return t.master.Write(p) }
func (t ptyTerminal) Close() error                { return t.master.Close() }
func (t ptyTerminal) EchoOff() (bool, error)      { return pty.EchoOff(t.master) }
func (t ptyTerminal) Resize(cols, rows int) error {
	return pty.SetSize(t.master, pty.Size{Cols: cols, Rows: rows})
}

// printableASCII replaces anything outside 0x20-0x7E with '?' and cuts to
// max bytes: what an Exit reason or a log line may hold.
func printableASCII(s string, max int) string {
	b := []byte(s)
	if len(b) > max {
		b = b[:max]
	}
	for i, c := range b {
		if c < 0x20 || c > 0x7e {
			b[i] = '?'
		}
	}
	return string(b)
}

// Clamp checks: ipc restates screen's bounds, since it imports nothing.
var _ = [1]struct{}{}[ipc.MaxCols-screen.MaxCols]
var _ = [1]struct{}{}[ipc.MaxRows-screen.MaxRows]
var _ = [1]struct{}{}[ipc.MaxScrollbackCells/10-emu.DefaultScrollbackCells]
