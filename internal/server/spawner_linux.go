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
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/danielbodart/mosey/internal/bootstrap"
	"github.com/danielbodart/mosey/internal/handshake"
	"github.com/danielbodart/mosey/internal/ipc"
	"github.com/danielbodart/mosey/internal/nocore"
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
	Self string
	// Version is this binary's, for the session log alone: nothing
	// compares it (D8 V1).
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
	// IdleTimeout is how long a detached session lives before its shell is
	// hung up; zero is the package's IdleTimeout (D8 R4). Not a user
	// option (PLAN O14): tests set it.
	IdleTimeout time.Duration

	// prlimit sets emu's RLIMIT_DATA; a test hook.
	prlimit func(pid int) error
}

// execPath is the file a role is started from (server.md §2.3): the
// spawner's own image, /proc/self/exe, never self's path, which D7 may
// have replaced since with a build of another protocol
// (bootstrap.md §4.7.7). self stays argv[0], so ps and the tests still
// see which file it came from. An empty self, a test's way of saying
// there is nothing to start, stays empty.
func execPath(self string) string {
	if self == "" {
		return ""
	}
	return "/proc/self/exe"
}

// RunSpawner is `mosey --serve=spawner`: the unsandboxed role that binds
// UDP, opens the pty, starts the login shell and the sandboxed roles, and
// supervises them for the life of the session (server.md §2). ipcFD is
// its end of the socketpair to the launcher.
func RunSpawner(ctx context.Context, ipcFD *os.File, cfg SpawnerConfig) error {
	// Before the credential line passes through: not dumpable, so the
	// user's other processes cannot read it and a crash leaves no core of
	// it. Not the core rlimit, which the login shell would inherit
	// (threat-model.md §4.10).
	if err := nocore.NotDumpable(); err != nil {
		return err
	}
	if cfg.Environ == nil {
		cfg.Environ = os.Environ()
	}
	if cfg.prlimit == nil {
		cfg.prlimit = limitData
	}
	if cfg.FirstPort == 0 && cfg.LastPort == 0 {
		cfg.FirstPort, cfg.LastPort = FirstPort, LastPort
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = IdleTimeout
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

	launcher *ipc.Conn
	ctl      *ipc.Conn
	ctlMsgs  chan ctlEvent
	// spoke closes when proto says the shell has written its first
	// output (ipc.FirstOutput), for typeInto.
	spoke      chan struct{}
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

	// The session's id, from proto's first credential, its name, from the
	// launcher's line, and its attach socket (server.md §2.6), or nil if
	// it could not be made.
	sid  [16]byte
	name string
	// command is the first line's cmd, "" for none: the greeting carries
	// it for life, so a plain `mosey HOST COMMAND` can find this session
	// again and -list can show it (bootstrap.md §9.2.1, §9.2.3).
	command string
	started time.Time
	attach  *attachListener
	// hangups carries mosey -kill's Hangup from the attach socket to the
	// supervision loop (bootstrap.md §9.5).
	hangups chan struct{}
	// agent is the session's agent socket (server.md §2.7), or nil, and
	// agentConns carries its connections to the supervision loop, which
	// hands them to proto.
	agent      *agentListener
	agentConns chan *os.File
	agentDone  chan struct{}
	// socketsClosed: closeSockets has run, at the shell's exit or the
	// teardown, whichever came first.
	socketsClosed bool
	// resumes carries each resume the attach socket has checked to the
	// supervision loop, which forwards it to proto; pending is those
	// forwarded and not yet answered, in order (proto answers in order).
	resumes chan resumeRequest
	pending []resumeRequest
	serving atomic.Int32

	// What the greeting says of the session's client: what proto last
	// said (state, since, peer, holder), and a resume's hold, which says
	// attached until its credential could no longer be confirmed
	// (bootstrap.md §9.2 "The lock").
	greetMu   sync.Mutex
	state     bootstrap.SessionState
	since     time.Time
	peer      netip.AddrPort
	holder    [8]byte
	hasHolder bool
	hold      [8]byte
	// holdOwner is the credential of the reconnecting client the hold is
	// for, if hasHoldOwner (bootstrap.md §9.2.2).
	holdOwner    [8]byte
	hasHoldOwner bool
	holdFrom     time.Time
	holdUntil    time.Time
	// holdTTL is how long a resume holds the greeting; zero is
	// handshake.CredentialTTL. Tests shorten it.
	holdTTL time.Duration
}

// resumeRequest is a checked resume on its way to proto: the client's key,
// the credential a reconnecting client named (bootstrap.md §9.2.2), and
// where the credential line goes back to.
type resumeRequest struct {
	public       []byte
	requester    [8]byte
	hasRequester bool
	reply        chan []byte
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
	if err := checkClientLine(lineMsg.Line); err != nil {
		return err
	}
	cl, _ := bootstrap.ParseClientLine(lineMsg.Line)
	s.name, s.command = cl.Name, cl.Command
	cols, rows := screen.ClampSize(int(cl.Cols), int(cl.Rows))

	// Pin no mount; outlive the ssh login's hangup; never die of a write
	// to a closed pipe. Caught, not ignored: an ignored signal stays
	// ignored across exec, so the shell would start with SIGHUP ignored,
	// and a shell that keeps that (dash, a common /bin/sh) would never end
	// for -kill or the idle timeout (§2.4). Exec resets a caught signal to
	// its default. The channel is never read; Notify drops what does not
	// fit.
	os.Chdir("/")
	signal.Notify(make(chan os.Signal, 1), syscall.SIGHUP, syscall.SIGPIPE)
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
	s.readCtl()
	err = s.ctl.Send(ipc.Start{
		Cols: uint16(cols), Rows: uint16(rows), Port: port, Addr: s.advertised,
		ClientPublic: cl.Public, Name: s.name, UDP: udp, PTY: master,
	})
	if err == nil {
		err = s.ctl.Send(ipc.EmuLink{Generation: 1, Reason: ipc.EmuFirst, Conn: emuEnd})
	}
	if err != nil {
		return fmt.Errorf("handing proto its fds: %w", err)
	}

	// The credential line passes through, and is wiped however this ends
	// (threat-model.md §4.10).
	line, err := s.awaitCredential(ctx)
	defer func() { clear(line) }()
	if err != nil {
		return err
	}

	// The credential names the session, so its attach socket can be made
	// now (server.md §2.6). Without one the session goes on, but nobody
	// can resume it.
	cred, _ := bootstrap.ParseCredentialLine(line)
	s.sid = cred.SessionID
	clear(cred.PSK[:])
	s.started = time.Now()
	s.state, s.since = bootstrap.SessionNew, s.started
	s.resumes = make(chan resumeRequest)
	s.hangups = make(chan struct{}, 1)
	if s.attach, err = listenAttach(sessionsDir(s.getenv), s.sid); err != nil {
		s.log.Warn("no attach socket: this session cannot be resumed", "err", err)
		s.attach = nil
	} else {
		s.log.Info("attach socket", "path", s.attach.path)
	}
	// The agent socket, before the shell, whose SSH_AUTH_SOCK names it
	// (server.md §2.7). Without one the shell has no agent, as under ssh
	// without -A.
	agentSock := ""
	if cl.Agent && s.attach != nil {
		if s.agent, err = listenAgent(s.attach.dir); err != nil {
			s.log.Warn("no agent socket: the shell gets no agent", "err", err)
			s.agent = nil
		} else {
			agentSock = s.agent.path
			s.agentConns = make(chan *os.File)
			s.agentDone = make(chan struct{})
			s.log.Info("agent socket", "path", agentSock)
		}
	}

	// The shell starts this late so a failure earlier leaves none behind,
	// and so its start-up overlaps the client's handshake.
	if err := s.startShell(cl, agentSock, slave); err != nil {
		return err
	}
	slave.Close()
	s.typeInto(ctx, cl.Type)

	if err := s.launcher.Send(ipc.Ready{Line: line}); err != nil {
		s.log.Warn("telling the launcher", "err", err)
	}
	s.launcher.Close()
	s.launcher = nil
	s.ready = true
	return nil
}

// awaitCredential waits up to T3 for proto's first Credential and checks
// it (§3.4).
func (s *spawner) awaitCredential(ctx context.Context) ([]byte, error) {
	timeout := time.After(T3)
	for {
		select {
		case ev := <-s.ctlMsgs:
			if ev.err != nil {
				return nil, fmt.Errorf("proto: %w", ev.err)
			}
			switch m := ev.m.(type) {
			case ipc.Credential:
				if err := checkCredential(m.Line, s.advertised, s.port, s.name); err != nil {
					clear(m.Line)
					s.violation(err)
					return nil, errors.New("proto sent a bad credential")
				}
				return m.Line, nil
			case ipc.Exit:
				return nil, fmt.Errorf("proto: %s", m.Reason)
			case ipc.KillEmu:
				// Before the session starts there is nothing to rebuild for.
				return nil, errors.New("emu failed at start")
			default:
				s.violation(fmt.Errorf("%T before the credential", m))
				return nil, errors.New("proto broke the protocol")
			}
		case st := <-s.proto.done:
			return nil, fmt.Errorf("proto ended at start: %s", describe(st))
		case <-timeout:
			return nil, errors.New("proto sent no credential in time")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// readCtl reads proto's messages into ctlMsgs, for the bootstrap and then
// supervise, until the first error.
func (s *spawner) readCtl() {
	s.ctlMsgs = make(chan ctlEvent, 8)
	s.spoke = make(chan struct{})
	go func() {
		spoke := s.spoke
		for {
			m, err := s.ctl.Recv()
			// FirstOutput only ever ends typeInto's wait, so it goes no
			// further; any after the first are ignored (server.md §3.4).
			if _, ok := m.(ipc.FirstOutput); ok {
				if spoke != nil {
					close(spoke)
					spoke = nil
				}
				continue
			}
			s.ctlMsgs <- ctlEvent{m, err}
			if err != nil {
				return
			}
		}
	}()
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
	s.log.Info("session starting", "log", name, "version", s.cfg.Version, "name", s.name)
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
		Path: execPath(s.cfg.Self),
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

func (s *spawner) startShell(cl bootstrap.ClientLine, agentSock string, slave *os.File) error {
	// The same passwd file as the launcher's -dir check, so both resolve
	// a relative -dir against the same home.
	path, home := shellAndHome(s.getenv, passwdFile)
	// The launcher checked -dir already; should it have gone since, the
	// session fails rather than start somewhere the user did not ask.
	dir, err := startDir(home, cl.Dir)
	if err != nil {
		return fmt.Errorf("the shell's directory: %w", err)
	}
	hop := hopDir(s.cfg.Environ, "/proc/self/exe")
	if hop != "" {
		s.log.Info("the server is ~/.local/bin/mosey: putting ~/.local/bin on the shell's PATH", "dir", hop)
	}
	proc, err := pty.Shell{Path: path, Dir: dir, Env: shellEnv(s.cfg.Environ, cl.Env, agentSock, hop, s.log), Command: cl.Command}.Start(slave)
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
	s.log.Info("shell started", "shell", path, "pid", proc.Pid, "command", cl.Command != "")
	return nil
}

// typeInto types -type's text into the new shell, then Enter
// (bootstrap.md §9.2.3), as tmux send-keys TEXT Enter does, once the
// shell has written its first output, its prompt as a rule, and its tty
// has stopped echoing, or TypeWait has passed. Typed before the prompt, the tty would echo it at once and
// the line editor again after the prompt, so it would show twice; typed
// after, it shows once, as a person who waited would type it. Only proto
// reads the master, so proto says when (ipc.FirstOutput): the spawner
// reading it too would take output from the emulator. The CR is what a
// terminal's Enter sends; ICRNL makes it the newline that ends the line.
// It goes before Ready, so before anything the client types. A failure
// costs the text, not the session.
func (s *spawner) typeInto(ctx context.Context, text string) {
	if text == "" {
		return
	}
	wait := time.NewTimer(TypeWait)
	defer wait.Stop()
	select {
	case <-s.spoke:
		// The first output need not be the prompt: a login shell's
		// profile can write (a window title, say) before the line editor
		// starts, and readline turns the tty's echo off only just before
		// it draws the prompt ([M] strace of bash 5.3, 2026-11-16), so
		// text typed while the tty still echoes shows twice, as CI's
		// Ubuntu runner once showed it. So wait too, within
		// the same TypeWait, for the echo to go off. A shell with no line
		// editor leaves it on and gets its text when TypeWait passes; the
		// tty's echo is then its only one.
		if !s.waitEchoOff(ctx, wait.C) {
			return
		}
	case <-wait.C:
		s.log.Info("the shell wrote nothing in time; typing -type's text anyway", "after", TypeWait)
	case <-ctx.Done():
		return
	}
	b := append([]byte(text), '\r')
	if _, err := s.master.Write(b); err != nil {
		s.log.Warn("typing -type's text into the shell", "err", err)
		return
	}
	s.log.Info("typed -type's text into the shell", "bytes", len(text))
}

// echoPoll is how often typeInto looks at the tty's echo bit while it
// waits for the line editor [choice: a small fraction of TypeWait, and
// below what a person notices].
const echoPoll = 10 * time.Millisecond

// waitEchoOff waits until the pty no longer echoes what is typed, or
// until expired fires, and says false only if ctx ended first. A master
// whose termios cannot be read is taken as not echoing: there is nothing
// to wait for.
func (s *spawner) waitEchoOff(ctx context.Context, expired <-chan time.Time) bool {
	for {
		if on, err := pty.Echoes(s.master); err != nil || !on {
			return true
		}
		select {
		case <-time.After(echoPoll):
		case <-expired:
			s.log.Info("the shell's tty still echoes; typing -type's text anyway", "after", TypeWait)
			return true
		case <-ctx.Done():
			return false
		}
	}
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

	if s.attach != nil {
		go s.serveAttach()
	}
	if s.agent != nil {
		go s.serveAgent()
	}
	attached := false
	backstopTimer := time.NewTimer(backstop)
	defer backstopTimer.Stop()
	// idle runs while the session is detached (D8 R4); hungUp is the
	// grace a hung-up shell has to exit before the teardown.
	idle := newIdleClock(s.cfg.IdleTimeout)
	defer idle.attached()
	var hungUp <-chan time.Time
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
		case <-idle.C():
			s.log.Info("detached for the idle timeout; hanging the shell up", "after", s.cfg.IdleTimeout)
			hungUp = s.hangup()
		case <-s.hangups:
			s.log.Info("mosey -kill: hanging the shell up")
			hungUp = s.hangup()
		case <-hungUp:
			hungUp = nil
			if s.shell != nil {
				reason = "hung up; the shell ignored SIGHUP"
				s.teardown(reason)
				return nil
			}
		case st := <-shellDone:
			shellDone = nil
			s.shell = nil
			// The session is ending: out of sight now, before the client
			// hears of it, so the client's next plain `mosey HOST` cannot
			// pick it as detached and fail to resume it.
			s.closeSockets()
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
		case f := <-s.agentConns:
			s.passAgentConn(f)
		case r := <-s.resumes:
			if err := s.ctl.Send(ipc.Resume{ClientPublic: r.public}); err != nil {
				s.log.Warn("forwarding a resume to proto", "err", err)
				close(r.reply)
				continue
			}
			s.pending = append(s.pending, r)
			if !attached {
				// A credential minted before any client attached keeps the
				// session waiting as long as it lives (bootstrap.md §4.5).
				backstopTimer.Reset(backstop)
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
				if !attached {
					attached = true
					backstopTimer.Stop()
				}
				idle.attached()
				s.setAttached(m.Credential, m.Peer)
				s.log.Info("a client attached", "peer", m.Peer, "credential", fmt.Sprintf("%x", m.Credential))
			case ipc.Detached:
				s.setDetached()
				idle.detached()
				s.log.Info("the client detached")
			case ipc.Credential:
				if len(s.pending) == 0 {
					s.violation(errors.New("a Credential nobody asked for"))
					continue
				}
				r := s.pending[0]
				s.pending = s.pending[1:]
				if err := s.checkResumed(m.Line); err != nil {
					clear(m.Line)
					close(r.reply)
					s.violation(err)
					continue
				}
				// Held for the credential's life, so the next launcher does
				// not choose this session too (bootstrap.md §9.2).
				if cl, err := bootstrap.ParseCredentialLine(m.Line); err == nil {
					s.holdFor(cl.CredentialID, r.requester, r.hasRequester)
					clear(cl.PSK[:])
				}
				// reply has room for one, so the loop never waits on a
				// resume that gave up.
				r.reply <- m.Line
			default:
				s.violation(fmt.Errorf("%T after the bootstrap", m))
			}
		}
	}
}

// hangup is D8 R4's end of a session by -kill or the idle timeout
// (server.md §2.4): SIGHUP to the shell and to the pty's foreground
// process group, as a hangup does, so the shell exits and the session
// ends the usual way. It returns when to give up on the shell.
func (s *spawner) hangup() <-chan time.Time {
	if s.shell == nil {
		return nil
	}
	pid := s.shell.cmd.Process.Pid
	if err := syscall.Kill(pid, syscall.SIGHUP); err != nil {
		s.log.Warn("SIGHUP to the shell", "err", err)
	}
	if s.master != nil {
		// The foreground job (an editor, say) is told as well, as the
		// kernel tells it when a terminal hangs up.
		if pg, err := unix.IoctlGetInt(int(s.master.Fd()), unix.TIOCGPGRP); err == nil && pg > 1 && pg != pid {
			if err := syscall.Kill(-pg, syscall.SIGHUP); err != nil {
				s.log.Warn("SIGHUP to the foreground job", "pgrp", pg, "err", err)
			}
		}
	}
	return time.After(HangupGrace)
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

// closeSockets takes the session out of sight: no launcher lists it or
// resumes it after this (server.md §2.6). The agent socket goes before the
// attach socket because closing the attach listener removes the session's
// directory, which it can only do once agent.sock has left it (server.md
// §2.7). It is safe to call twice.
func (s *spawner) closeSockets() {
	if s.socketsClosed {
		return
	}
	s.socketsClosed = true
	if s.agent != nil {
		s.agent.Close()
		close(s.agentDone)
	}
	if s.attach != nil {
		s.attach.Close()
	}
}

// teardown ends the session in server.md §2.4's order: proto (EOF on C,
// then SIGKILL), the shell (the hangup when the last master closes, then
// SIGKILL of its pid only, so a job the user detached survives as it does
// an ssh logout), then emu.
func (s *spawner) teardown(why string) {
	start := time.Now()
	s.closeSockets()
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
