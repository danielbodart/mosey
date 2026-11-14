package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/danielbodart/mosey/internal/bootstrap"
	"github.com/danielbodart/mosey/internal/handshake"
	"github.com/danielbodart/mosey/internal/ipc"
	"github.com/danielbodart/mosey/internal/pty"
	"github.com/danielbodart/mosey/internal/screen"
)

// Teardown grace periods (server.md §8) [derived].
const (
	T7 = 2 * time.Second // proto, after C closes
	T8 = 5 * time.Second // the shell, after the hangup
	T9 = time.Second     // emu, after E closes
	// backstop ends a session no client attached to, should proto hang
	// before its own NoClient (bootstrap.md §4.5): CredentialTTL plus a
	// margin for teardown and clock granularity.
	backstop = handshake.CredentialTTL + 10*time.Second
	// emuDataLimit is emu's RLIMIT_DATA, twice D23's MemoryMax, because it
	// counts private writable mappings, which run ahead of what a cgroup
	// charges [derived; TestEmuMemoryLimitRestartsEmu].
	emuDataLimit = 1 << 30
	// emuMemoryMax is D23's cgroup limit on emu.
	emuMemoryMax = 512 << 20
)

// SpawnerConfig is how the spawner is set up; the zero values of the
// optional fields are production's.
type SpawnerConfig struct {
	// Self is this binary, re-executed as proto and emu.
	Self    string
	Version string
	// FirstPort and LastPort are the UDP port range; zero for both is
	// the package's FirstPort and LastPort.
	FirstPort, LastPort uint16
	// BindAddr, if valid, is bound and advertised instead of what
	// SSH_CONNECTION says, for tests.
	BindAddr netip.Addr
	// Environ is the spawner's environment, sshd's; nil is os.Environ().
	Environ []string
	// LogDir overrides where the session log goes.
	LogDir string
	// Passwd is read for the user's shell when $SHELL is unusable; empty
	// is /etc/passwd.
	Passwd string

	// prlimit sets emu's RLIMIT_DATA; a test hook.
	prlimit func(pid int) error
}

// RunSpawner is `mosey --serve=spawner`: the unsandboxed role that binds
// UDP, opens the pty, starts the login shell and the sandboxed roles, and
// supervises them for the life of the session (server.md §2). ipcFD is
// its end of the socketpair to the launcher.
func RunSpawner(ctx context.Context, ipcFD *os.File, cfg SpawnerConfig) error {
	if cfg.Environ == nil {
		cfg.Environ = os.Environ()
	}
	if cfg.prlimit == nil {
		cfg.prlimit = limitData
	}
	if cfg.Passwd == "" {
		cfg.Passwd = "/etc/passwd"
	}
	if cfg.FirstPort == 0 && cfg.LastPort == 0 {
		cfg.FirstPort, cfg.LastPort = FirstPort, LastPort
	}
	s := &spawner{cfg: cfg, start: newStarter(), log: slog.New(slog.DiscardHandler)}
	return s.run(ctx, ipcFD)
}

// child is a running role or shell.
type child struct {
	role string
	gen  uint32
	cmd  *exec.Cmd
	born time.Time
	done chan *os.ProcessState
	// oom is set when emu's stderr says Go ran out of memory.
	oom atomic.Bool
	// cgroup is emu's scope's cgroup directory, if it has one.
	cgroup string
}

type spawner struct {
	cfg     SpawnerConfig
	start   *starter
	log     *slog.Logger
	logFile *cappedWriter

	launcher   *ipc.Conn
	ctl        *ipc.Conn
	ctlMsgs    chan ctlEvent
	advertised netip.Addr
	port       uint16
	master     *os.File
	proto      *child
	emu        *child
	shell      *child
	gen        uint32
	killAsked  map[uint32]bool
	restarts   restarts
	ready      bool
}

type ctlEvent struct {
	m   ipc.Message
	err error
}

func (s *spawner) getenv(name string) string {
	for i := len(s.cfg.Environ) - 1; i >= 0; i-- {
		if k, v, ok := strings.Cut(s.cfg.Environ[i], "="); ok && k == name {
			return v
		}
	}
	return ""
}

func (s *spawner) run(ctx context.Context, ipcFD *os.File) error {
	launcher, err := wrapRoleSocket(ipcFD, ipc.Spawner, ipc.Launcher)
	if err != nil {
		return err
	}
	s.launcher = launcher
	if err := s.bootstrap(ctx); err != nil {
		if s.launcher != nil {
			s.launcher.Send(ipc.Failed{Text: printableASCII(err.Error(), ipc.MaxFailed)})
			s.launcher.Close()
		}
		s.log.Error("the session did not start", "err", err)
		s.teardown("bootstrap failed")
		return err
	}
	return s.supervise(ctx)
}

// bootstrap is server.md §2.1 step 4: each failure is reported to the
// launcher, and whatever started is torn down.
func (s *spawner) bootstrap(ctx context.Context) error {
	s.launcher.File().SetReadDeadline(time.Now().Add(T2))
	m, err := s.launcher.Recv()
	if err != nil {
		return fmt.Errorf("waiting for the client's line: %w", err)
	}
	lineMsg, ok := m.(ipc.ClientLine)
	if !ok {
		return fmt.Errorf("the launcher sent %T", m)
	}
	// The spawner trusts no other process's parse.
	if err := checkClientLine(lineMsg.Line, s.cfg.Version); err != nil {
		return err
	}
	cl, _ := bootstrap.ParseClientLine(lineMsg.Line)
	cols, rows := screen.ClampSize(int(cl.Cols), int(cl.Rows))

	// Pin no mount; outlive the ssh login's hangup; never die of a write
	// to a closed pipe.
	os.Chdir("/")
	signal.Ignore(syscall.SIGHUP, syscall.SIGPIPE)
	if err := s.openLog(); err != nil {
		return err
	}

	// The address the client's ssh reached is advertised and, unless it
	// is loopback or link-local, bound (server.md §2.2).
	var bindTo netip.Addr
	s.advertised, bindTo = addresses(s.getenv("SSH_CONNECTION"))
	if s.cfg.BindAddr.IsValid() {
		s.advertised, bindTo = s.cfg.BindAddr, s.cfg.BindAddr
	}
	udp, port, err := bindUDP(bindTo, s.cfg.FirstPort, s.cfg.LastPort)
	if err != nil {
		return err
	}
	defer udp.Close()
	s.port = port
	s.log.Info("bound", "advertised", s.advertised, "bind", bindTo, "port", port)

	master, slave, err := pty.Open(pty.Size{Cols: cols, Rows: rows})
	if err != nil {
		return fmt.Errorf("opening the pty: %w", err)
	}
	s.master = master
	defer slave.Close()

	emuEnd, err := s.startEmu()
	if err != nil {
		return err
	}
	defer emuEnd.Close()

	local, remote, err := ipc.Pair()
	if err != nil {
		return err
	}
	s.proto, err = s.startRole("proto", remote, 0)
	remote.Close()
	if err != nil {
		local.Close()
		return fmt.Errorf("starting proto: %w", err)
	}
	if s.ctl, err = ipc.NewConn(local, ipc.Spawner, ipc.Proto); err != nil {
		return err
	}
	s.ctlMsgs = make(chan ctlEvent, 8)
	go func() {
		for {
			m, err := s.ctl.Recv()
			s.ctlMsgs <- ctlEvent{m, err}
			if err != nil {
				return
			}
		}
	}()
	err = s.ctl.Send(ipc.Start{
		Cols: uint16(cols), Rows: uint16(rows), Port: port, Addr: s.advertised,
		ClientPublic: cl.Public, UDP: udp, PTY: master,
	})
	if err == nil {
		err = s.ctl.Send(ipc.EmuLink{Generation: 1, Reason: ipc.EmuFirst, Conn: emuEnd})
	}
	if err != nil {
		return fmt.Errorf("handing proto its fds: %w", err)
	}

	var line []byte
	timeout := time.After(T3)
	for line == nil {
		select {
		case ev := <-s.ctlMsgs:
			if ev.err != nil {
				return fmt.Errorf("proto: %w", ev.err)
			}
			switch m := ev.m.(type) {
			case ipc.Credential:
				if err := checkCredential(m.Line, s.advertised, port, s.cfg.Version); err != nil {
					s.violation(err)
					return errors.New("proto sent a bad credential")
				}
				line = m.Line
			case ipc.Exit:
				return fmt.Errorf("proto: %s", m.Reason)
			case ipc.KillEmu:
				// Before the session starts there is nothing to rebuild for.
				return errors.New("emu failed at start")
			default:
				s.violation(fmt.Errorf("%T before the credential", m))
				return errors.New("proto broke the protocol")
			}
		case st := <-s.proto.done:
			return fmt.Errorf("proto ended at start: %s", describe(st))
		case <-timeout:
			return errors.New("proto sent no credential in time")
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	// The shell starts this late so a failure earlier leaves none behind,
	// and so its start-up overlaps the client's handshake.
	if err := s.startShell(cl.Env, slave); err != nil {
		return err
	}
	slave.Close()

	if err := s.launcher.Send(ipc.Ready{Line: line}); err != nil {
		s.log.Warn("telling the launcher", "err", err)
	}
	s.launcher.Close()
	s.launcher = nil
	s.ready = true
	return nil
}

func (s *spawner) openLog() error {
	dir := s.cfg.LogDir
	if dir == "" {
		var err error
		if dir, err = logDir(s.getenv); err != nil {
			return err
		}
	}
	w, name, err := openSessionLog(dir, time.Now(), os.Getpid())
	if err != nil {
		return err
	}
	s.logFile = w
	s.log = slog.New(slog.NewTextHandler(w, nil)).With("role", "spawner", "pid", os.Getpid())
	s.log.Info("session starting", "log", name, "version", s.cfg.Version)
	return nil
}

// startRole starts Self as a sandboxed role with sock as fd 3 and its
// stderr piped into the log under a prefix the spawner chooses.
func (s *spawner) startRole(role string, sock *os.File, gen uint32) (*child, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer w.Close()
	cmd := &exec.Cmd{
		Path: s.cfg.Self,
		Args: []string{s.cfg.Self, "--serve=" + role},
		// Nothing a confused role could follow: no HOME, no SSH_AUTH_SOCK,
		// no bus address (S4).
		Env:        roleEnv(s.cfg.Environ),
		Stderr:     w,
		ExtraFiles: []*os.File{sock},
		// A spawner that is SIGKILLed takes its roles with it; EOF on the
		// socket is the primary signal, this the backstop.
		SysProcAttr: &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL},
	}
	if err := s.start.run(cmd.Start); err != nil {
		r.Close()
		return nil, err
	}
	c := &child{role: role, gen: gen, cmd: cmd, born: time.Now(), done: make(chan *os.ProcessState, 1)}
	prefix := fmt.Sprintf("%s pid=%d", role, cmd.Process.Pid)
	if role == "emu" {
		prefix += fmt.Sprintf(" gen=%d", gen)
	}
	logs := make(chan struct{})
	go func() {
		defer close(logs)
		var out io.Writer = io.Discard
		if s.logFile != nil {
			out = s.logFile
		}
		copyRoleLog(r, out, prefix, func(line string) {
			if outOfMemory(line) {
				c.oom.Store(true)
			}
		})
		r.Close()
	}()
	go func() {
		cmd.Wait()
		// The stderr lines, the OOM one included, are all in before the
		// exit is acted on.
		<-logs
		c.done <- cmd.ProcessState
	}()
	return c, nil
}

// roleEnv is a role's whole environment: empty, or in a soak build the
// soak's own knobs.
func roleEnv(environ []string) []string {
	env := []string{}
	if soakBuild {
		for _, kv := range environ {
			if strings.HasPrefix(kv, "MOSEY_SOAK_") {
				env = append(env, kv)
			}
		}
	}
	return env
}

// startEmu starts the next emu generation and bounds its memory before
// anyone can talk to it; it returns proto's end of the new socketpair.
func (s *spawner) startEmu() (*os.File, error) {
	local, remote, err := ipc.Pair()
	if err != nil {
		return nil, err
	}
	gen := s.gen + 1
	c, err := s.startRole("emu", remote, gen)
	remote.Close()
	if err != nil {
		local.Close()
		return nil, fmt.Errorf("starting emu: %w", err)
	}
	s.restarts.started(c.born)
	s.gen = gen
	s.emu = c
	// RLIMIT_DATA is required: mosey never runs an emu with no memory
	// bound (threat-model.md §4.8). It is set from here, not by emu on
	// itself, so nothing emu says decides whether a limit is in force.
	if err := s.cfg.prlimit(c.cmd.Process.Pid); err != nil {
		c.cmd.Process.Kill()
		local.Close()
		s.log.Error("cannot limit the emulator's memory", "err", err)
		return nil, errors.New("cannot limit the emulator's memory")
	}
	c.cgroup = s.scope(c.cmd.Process.Pid, gen)
	return local, nil
}

func limitData(pid int) error {
	lim := unix.Rlimit{Cur: emuDataLimit, Max: emuDataLimit}
	return unix.Prlimit(pid, unix.RLIMIT_DATA, &lim, nil)
}

// scope moves emu into a transient systemd scope with D23's MemoryMax,
// when the user has a manager; best effort, since RLIMIT_DATA is the
// limit every host has (server.md §6.3). It returns the scope's cgroup
// directory, for reading its OOM count.
func (s *spawner) scope(pid int, gen uint32) string {
	if s.getenv("XDG_RUNTIME_DIR") == "" {
		return ""
	}
	busctl, err := exec.LookPath("busctl")
	if err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	unit := fmt.Sprintf("mosey-emu-%d-%d.scope", os.Getpid(), gen)
	cmd := exec.CommandContext(ctx, busctl, "--user", "--timeout=2", "call",
		"org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager",
		"StartTransientUnit", "ssa(sv)a(sa(sv))", unit, "fail", "4",
		"PIDs", "au", "1", strconv.Itoa(pid),
		"MemoryMax", "t", strconv.Itoa(emuMemoryMax),
		"MemorySwapMax", "t", "0",
		"CollectMode", "s", "inactive-or-failed",
		"0")
	cmd.Env = s.cfg.Environ
	if out, err := cmd.CombinedOutput(); err != nil {
		if gen == 1 {
			s.log.Info("no memory cgroup for emu; RLIMIT_DATA alone", "err", err, "busctl", SanitizeLogLine(out))
		}
		return ""
	}
	cg, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(cg), "\n") {
		if p, ok := strings.CutPrefix(l, "0::"); ok {
			return "/sys/fs/cgroup" + p
		}
	}
	return ""
}

// oomKilled says whether emu's scope saw the kernel kill it for memory.
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

func (s *spawner) startShell(env map[string]string, slave *os.File) error {
	passwd, _ := os.Open(s.cfg.Passwd)
	path, home := pty.LoginShell(s.getenv, passwd, os.Getuid())
	if passwd != nil {
		passwd.Close()
	}
	proc, err := pty.Shell{Path: path, Dir: home, Env: shellEnv(s.cfg.Environ, env, s.log)}.Start(slave)
	if err != nil {
		return fmt.Errorf("starting the shell %s: %w", path, err)
	}
	c := &child{role: "shell", born: time.Now(), done: make(chan *os.ProcessState, 1)}
	go func() {
		st, _ := proc.Wait()
		c.done <- st
	}()
	c.cmd = &exec.Cmd{Process: proc}
	s.shell = c
	s.log.Info("shell started", "shell", path, "pid", proc.Pid)
	return nil
}

// violation is proto breaking §3.4: the spawner is unsandboxed, so it
// trusts nothing more from that proto.
func (s *spawner) violation(err error) {
	s.log.Error("proto violated the control protocol; killing it", "err", err)
	if s.proto != nil {
		s.proto.cmd.Process.Kill()
	}
}

// supervise waits on everything a session can end on, and restarts emu
// whenever it dies (server.md §5).
func (s *spawner) supervise(ctx context.Context) error {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigs)

	attached := false
	backstopTimer := time.NewTimer(backstop)
	defer backstopTimer.Stop()
	var restart <-chan time.Time
	var nextReason ipc.EmuEnd
	var nextStatus int32
	shellDone := s.shell.done
	gotExit := false
	reason := "proto ended"

	for {
		var emuDone chan *os.ProcessState
		if s.emu != nil {
			emuDone = s.emu.done
		}
		select {
		case <-ctx.Done():
			reason = "cancelled"
			s.teardown(reason)
			return nil
		case sig := <-sigs:
			reason = "signal " + sig.String()
			s.teardown(reason)
			return nil
		case <-backstopTimer.C:
			if !attached {
				reason = "no client attached"
				s.teardown(reason)
				return nil
			}
		case st := <-shellDone:
			shellDone = nil
			s.shell = nil
			s.log.Info("the shell exited", "status", describe(st))
			if err := s.ctl.Send(ipc.ShellExit{Status: status(st)}); err != nil {
				s.teardown("the shell exited")
				return nil
			}
		case st := <-s.proto.done:
			s.log.Info("proto exited", "status", describe(st), "lived", time.Since(s.proto.born).Round(time.Millisecond))
			s.proto = nil
			s.teardown(reason)
			return nil
		case st := <-emuDone:
			c := s.emu
			s.emu = nil
			nextReason, nextStatus = s.classify(c, st)
			s.log.Info("emu exited", "gen", c.gen, "status", describe(st), "reason", nextReason,
				"lived", time.Since(c.born).Round(time.Millisecond))
			wait, pause := s.restarts.plan(time.Now(), c.born)
			if pause {
				s.log.Warn("emu restart budget spent; pausing", "for", EmuCooldown)
				s.ctl.Send(ipc.EmuPaused{Seconds: emuCooldownSecs})
			}
			restart = time.After(wait)
		case <-restart:
			restart = nil
			end, err := s.startEmu()
			if err != nil {
				// A failed start counts against the budget like a death.
				s.log.Warn("restarting emu", "err", err)
				wait, pause := s.restarts.plan(time.Now(), time.Now())
				if pause {
					s.ctl.Send(ipc.EmuPaused{Seconds: emuCooldownSecs})
				}
				restart = time.After(wait)
				continue
			}
			err = s.ctl.Send(ipc.EmuLink{Generation: s.gen, Reason: nextReason, Status: nextStatus, Conn: end})
			end.Close()
			if err != nil {
				s.teardown("proto gone")
				return nil
			}
		case ev := <-s.ctlMsgs:
			if ev.err != nil {
				if !ipc.IsEOF(ev.err) {
					s.violation(ev.err)
				}
				// proto's exit follows; wait for it.
				s.ctlMsgs = nil
				continue
			}
			switch m := ev.m.(type) {
			case ipc.Exit:
				if gotExit {
					s.violation(errors.New("a second Exit"))
					continue
				}
				gotExit = true
				reason = fmt.Sprintf("proto: exit code %d %s", m.Code, m.Reason)
				s.log.Info("session over", "code", m.Code, "reason", m.Reason)
				s.teardown(reason)
				return nil
			case ipc.KillEmu:
				if s.emu != nil && m.Generation == s.gen && !s.killAsked[m.Generation] {
					if s.killAsked == nil {
						s.killAsked = map[uint32]bool{}
					}
					s.killAsked[m.Generation] = true
					s.log.Warn("proto asked for emu to be killed", "gen", m.Generation, "why", m.Why)
					s.emu.cmd.Process.Kill()
				}
			case ipc.Attached:
				if attached {
					s.violation(errors.New("a second Attached"))
					continue
				}
				attached = true
				backstopTimer.Stop()
			default:
				s.violation(fmt.Errorf("%T after the bootstrap", m))
			}
		}
	}
}

// classify is how an emu ended, for the EmuLink that tells proto.
func (s *spawner) classify(c *child, st *os.ProcessState) (ipc.EmuEnd, int32) {
	code := status(st)
	switch {
	case c.oom.Load() && code == 2, oomKilled(c.cgroup):
		return ipc.EmuMemory, code
	case s.killAsked[c.gen]:
		return ipc.EmuKilled, code
	case code < 0:
		return ipc.EmuSignalled, code
	}
	return ipc.EmuExited, code
}

// status is an exit code, or minus the signal that ended the process.
func status(st *os.ProcessState) int32 {
	if st == nil {
		return -int32(syscall.SIGKILL)
	}
	if ws, ok := st.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return -int32(ws.Signal())
	}
	return int32(st.ExitCode())
}

func describe(st *os.ProcessState) string {
	if st == nil {
		return "unknown"
	}
	if ws, ok := st.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return "signal: " + ws.Signal().String()
	}
	return fmt.Sprintf("exit %d", st.ExitCode())
}

// teardown ends the session in server.md §2.4's order: proto (EOF on C,
// then SIGKILL), the shell (the hangup when the last master closes, then
// SIGKILL of its pid only, so a job the user detached survives as it does
// an ssh logout), then emu.
func (s *spawner) teardown(why string) {
	start := time.Now()
	if s.proto != nil {
		if s.ctl != nil {
			s.ctl.Close()
		}
		waitOrKill(s.proto, T7)
	}
	if s.master != nil {
		s.master.Close()
	}
	if s.shell != nil {
		waitOrKill(s.shell, T8)
	}
	if s.emu != nil {
		waitOrKill(s.emu, T9)
	}
	s.log.Info("session ended", "why", why, "teardown", time.Since(start).Round(time.Millisecond))
	if s.logFile != nil {
		s.logFile.Close()
	}
}

func waitOrKill(c *child, grace time.Duration) {
	select {
	case <-c.done:
		return
	case <-time.After(grace):
	}
	c.cmd.Process.Kill()
	select {
	case <-c.done:
	case <-time.After(grace):
	}
}

// starter starts every child from one goroutine locked to its OS thread,
// which never returns while the spawner runs: Pdeathsig fires when the
// thread that forked the child exits, not the process (S4 §3.2, measured),
// so a child started from a thread the runtime later retires would be
// killed with it.
type starter struct{ reqs chan func() }

func newStarter() *starter {
	s := &starter{reqs: make(chan func())}
	go func() {
		runtime.LockOSThread()
		for f := range s.reqs {
			f()
		}
	}()
	return s
}

func (s *starter) run(f func() error) error {
	done := make(chan error, 1)
	s.reqs <- func() { done <- f() }
	return <-done
}

// bindUDP binds the session's socket at addr, or the wildcard, on the
// first free port in [first, last], trying each in order: EADDRINUSE moves
// on, anything else stops. Sequential is enough: a credential is needed to
// talk to the port, so its predictability costs nothing (server.md §2.2).
// It is never connected: proto sends to whatever path validation settles
// on (D21).
func bindUDP(addr netip.Addr, first, last uint16) (*os.File, uint16, error) {
	family, sa := unix.AF_INET6, func(port int) unix.Sockaddr {
		return &unix.SockaddrInet6{Port: port}
	}
	switch {
	case addr.Is4():
		family, sa = unix.AF_INET, func(port int) unix.Sockaddr {
			return &unix.SockaddrInet4{Port: port, Addr: addr.As4()}
		}
	case addr.Is6():
		sa = func(port int) unix.Sockaddr { return &unix.SockaddrInet6{Port: port, Addr: addr.As16()} }
	}
	fd, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil && !addr.IsValid() {
		// A host without IPv6: the IPv4 wildcard.
		family, sa = unix.AF_INET, func(port int) unix.Sockaddr { return &unix.SockaddrInet4{Port: port} }
		fd, err = unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("making the UDP socket: %w", err)
	}
	if family == unix.AF_INET6 && !addr.IsValid() {
		// The wildcard is dual-stack, whatever the host's default.
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 0); err != nil {
			unix.Close(fd)
			return nil, 0, fmt.Errorf("making the UDP socket dual-stack: %w", err)
		}
	}
	for port := int(first); port <= int(last); port++ {
		err := unix.Bind(fd, sa(port))
		if err == nil {
			return os.NewFile(uintptr(fd), "udp"), uint16(port), nil
		}
		if !errors.Is(err, unix.EADDRINUSE) {
			unix.Close(fd)
			return nil, 0, fmt.Errorf("binding UDP port %d: %w", port, err)
		}
	}
	unix.Close(fd)
	return nil, 0, fmt.Errorf("no free UDP port in %d-%d", first, last)
}
