package server

import (
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/danielbodart/mosey/internal/nocore"
)

// The spawner's Linux mechanisms (server.md §10): PR_SET_DUMPABLE,
// Pdeathsig, RLIMIT_DATA and a systemd scope for emu's memory, and
// SOCK_CLOEXEC.

// emuDataLimit is emu's RLIMIT_DATA, twice D23's MemoryMax, because it
// counts private writable mappings, which run ahead of what a cgroup
// charges [derived; TestEmuMemoryLimitRestartsEmu].
const emuDataLimit = 1 << 30

func (cfg *SpawnerConfig) platformDefaults() {
	if cfg.prlimit == nil {
		cfg.prlimit = limitData
	}
	if cfg.lingerDir == "" {
		cfg.lingerDir = lingerDir
	}
	if cfg.selfCgroup == "" {
		cfg.selfCgroup = "/proc/self/cgroup"
	}
}

// serverRuns says whether the launcher starts a server on this system
// (D22, server.md §10).
const serverRuns = true

// setNotDumpable is PR_SET_DUMPABLE 0 for the launcher and the spawner
// (threat-model.md §4.10). A failure is fatal.
func setNotDumpable() error { return nocore.NotDumpable() }

// startProcess starts a role. A spawner that is SIGKILLed takes its roles
// with it: EOF on the socket is the primary signal, Pdeathsig the
// backstop.
func startProcess(_ string, cmd *exec.Cmd) (func() *os.ProcessState, error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return func() *os.ProcessState {
		cmd.Wait()
		return cmd.ProcessState
	}, nil
}

// limitEmu bounds a new emu's memory: RLIMIT_DATA, which every host has
// and which must succeed, then D23's cgroup when the user has a systemd
// manager (server.md §6.3).
func (s *spawner) limitEmu(c *child) error {
	if err := s.cfg.prlimit(c.cmd.Process.Pid); err != nil {
		return err
	}
	c.cgroup = s.emuScope(c.cmd.Process.Pid, c.gen)
	return nil
}

func limitData(pid int) error {
	lim := unix.Rlimit{Cur: emuDataLimit, Max: emuDataLimit}
	return unix.Prlimit(pid, unix.RLIMIT_DATA, &lim, nil)
}

// limitHit says whether emu's scope saw the kernel kill it for memory.
func (s *spawner) limitHit(c *child, _ *os.ProcessState) bool { return oomKilled(c.cgroup) }

// oomKilled says whether the cgroup saw the kernel kill a process in it
// for memory.
func oomKilled(cgroup string) bool {
	if cgroup == "" {
		return false
	}
	b, err := os.ReadFile(cgroup + "/memory.events")
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(b), "\n") {
		if n, ok := strings.CutPrefix(l, "oom_kill "); ok {
			return n != "0"
		}
	}
	return false
}

// socket makes a close-on-exec socket, non-blocking if asked.
func socket(family, typ int, nonblock bool) (int, error) {
	typ |= unix.SOCK_CLOEXEC
	if nonblock {
		typ |= unix.SOCK_NONBLOCK
	}
	return unix.Socket(family, typ, 0)
}

// accept accepts a connection on the listening socket fd, close-on-exec
// and non-blocking.
func accept(fd int) (int, error) {
	nfd, _, err := unix.Accept4(fd, unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK)
	return nfd, err
}
