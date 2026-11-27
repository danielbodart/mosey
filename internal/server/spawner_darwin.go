package server

import (
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/danielbodart/mosey/internal/spawn"
)

// The spawner's macOS mechanisms (server.md §10). macOS has no
// PR_SET_DUMPABLE, no Pdeathsig, no systemd and no cgroup. A role whose
// spawner dies sees EOF on its IPC socket and ends. A setsid process
// started over ssh lives on after the connection closes [M], so the
// session needs no scope. emu's memory limit is jetsam's, set at its
// posix_spawn [D].

// serverRuns says whether the launcher starts a server on this system. On
// macOS it does: the darwin tests and the end-to-end run of server.md §10
// passed on dan-mac (macOS 15.7.4, 2026-11-27) [M]. proto and emu enter
// their Seatbelt profiles (internal/sandbox, D22), and a failure is fatal,
// as on Linux.
const serverRuns = true

func (cfg *SpawnerConfig) platformDefaults() {}

// joinSessionScope has nothing to do: a session needs no scope on macOS
// (server.md §10, "detach from ssh").
func (s *spawner) joinSessionScope() {}

// setNotDumpable has nothing to do on macOS: there is no PR_SET_DUMPABLE.
// RLIMIT_CORE 0 would go on to the user's login shell, as on Linux. So
// the launcher and the spawner read the credential line with no
// protection: a known gap (server.md §10, threat-model.md §4.10).
// PT_DENY_ATTACH does not close it yet: it is not known whether the login
// shell, which the spawner starts, keeps the flag, and the shell's own
// programs must stay open to the user's debugger. On dan-mac a user's
// process could not attach to another of the user's processes at all
// [M: EPERM, 2026-11-27], so the gap is open to root and to a user with
// developer rights.
func setNotDumpable() error { return nil }

// startProcess starts a role. emu is started with posix_spawn, so the
// kernel holds it to D23's limit from its first instruction; os/exec
// cannot pass the jetsam attribute (internal/spawn). proto needs no
// attribute, so os/exec starts it.
func startProcess(role string, cmd *exec.Cmd) (func() *os.ProcessState, error) {
	if role != "emu" {
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		return func() *os.ProcessState {
			cmd.Wait()
			return cmd.ProcessState
		}, nil
	}
	stderr, _ := cmd.Stderr.(*os.File)
	p, err := spawn.Start(spawn.Attr{
		Path: cmd.Path,
		Args: cmd.Args,
		Env:  cmd.Env,
		// stdin and stdout are /dev/null, as os/exec makes them; stderr
		// is the log's pipe; fd 3 is the IPC socket.
		Files:          append([]*os.File{nil, nil, stderr}, cmd.ExtraFiles...),
		MemoryLimitMiB: emuMemoryMax >> 20,
	})
	if err != nil {
		return nil, err
	}
	cmd.Process = p
	return func() *os.ProcessState {
		st, _ := p.Wait()
		return st
	}, nil
}

// limitEmu has nothing left to do: posix_spawn set the limit.
func (s *spawner) limitEmu(*child) error { return nil }

// limitHit says whether emu died of its jetsam limit. The kernel's kill
// is a SIGKILL, and wait4 then gives ru_maxrss at the limit or above: 513
// MiB for a 512 MiB limit [M: dan-mac, 2026-11-27]. A SIGKILL the spawner
// sent itself (proto's KillEmu) is not one. There is no watchdog [D].
//
// Jetsam counts the phys_footprint, which includes compressed memory, and
// ru_maxrss does not. Under memory pressure emu can die at the limit with
// a smaller RSS. The spawner then reports EmuSignalled, not EmuMemory: the
// client gets the wrong reason, but emu is still rebuilt. This false
// negative is accepted [D].
func (s *spawner) limitHit(c *child, st *os.ProcessState) bool {
	return jetsamKilled(st, emuMemoryMax) && !s.killAsked[c.gen]
}

// jetsamKilled says whether st is a SIGKILL of a process whose ru_maxrss,
// in bytes on macOS, reached limit.
func jetsamKilled(st *os.ProcessState, limit int64) bool {
	if st == nil {
		return false
	}
	ws, ok := st.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		return false
	}
	ru, ok := st.SysUsage().(*syscall.Rusage)
	return ok && ru.Maxrss >= limit
}

// socket makes a close-on-exec socket, non-blocking if asked. macOS's
// socket(2) takes no SOCK_CLOEXEC, so the flag is set under ForkLock, as
// Go's net package does.
func socket(family, typ int, nonblock bool) (int, error) {
	syscall.ForkLock.RLock()
	fd, err := unix.Socket(family, typ, 0)
	if err == nil {
		unix.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return -1, err
	}
	if nonblock {
		if err := unix.SetNonblock(fd, true); err != nil {
			unix.Close(fd)
			return -1, err
		}
	}
	return fd, nil
}

// accept accepts a connection on the listening socket fd, close-on-exec
// and non-blocking. macOS has no accept4.
func accept(fd int) (int, error) {
	syscall.ForkLock.RLock()
	nfd, _, err := unix.Accept(fd)
	if err == nil {
		unix.CloseOnExec(nfd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return -1, err
	}
	if err := unix.SetNonblock(nfd, true); err != nil {
		unix.Close(nfd)
		return -1, err
	}
	return nfd, nil
}
