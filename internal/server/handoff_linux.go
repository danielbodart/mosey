package server

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/danielbodart/mosey/internal/bootstrap"
	"github.com/danielbodart/mosey/internal/ipc"
	"github.com/danielbodart/mosey/internal/screen"
)

// The live upgrade (D8 V2, server.md §2.8): a session's spawner handing
// itself to a newer binary's (the old side, serveHandoff and the
// supervision loop's part), and a newer spawner adopting it (adopt).

// handoffJob is one hand-off under way on the old side: the attach
// connection's goroutine asks the supervision loop for it, the loop
// freezes proto and gathers the snapshot, the goroutine sends the state,
// and says whether the adopter took it.
type handoffJob struct {
	// ready is answered once by the loop: nil when the snapshot and the
	// pidfd are here, or why there will be none.
	ready    chan error
	snapshot []byte
	pidfd    *os.File
	shellPID int
	// released closes once the loop has committed to the hand-off: it
	// has stopped accepting and told proto to go, so it will never thaw,
	// and HandoffReleased may be sent. gone closes once it has torn its
	// part down, so the connection closes only then.
	released chan struct{}
	gone     chan struct{}
}

// snapshotWait bounds the loop's wait for proto's Snapshot: proto gives
// up freezing after T3, so twice that is an answer that will never come
// [derived].
const snapshotWait = 2 * T3

// checkHandoffPeer is the uid check on a hand-off's connection (server.md
// §2.8): samePeer, unless a test plays another uid.
func (s *spawner) checkHandoffPeer(f *os.File) error {
	raw, err := f.SyscallConn()
	if err != nil {
		return err
	}
	check := s.peerCheck
	if check == nil {
		check = samePeer
	}
	var perr error
	raw.Control(func(fd uintptr) { perr = check(int(fd)) })
	return perr
}

// serveHandoff is the old side of a live upgrade, on an attach connection
// whose peer has sent HandoffRequest (server.md §2.8 steps 3 to 9). Every
// check comes before proto is frozen or any fd leaves the spawner.
func (s *spawner) serveHandoff(conn *ipc.Conn, f *os.File, req ipc.HandoffRequest) error {
	refuse := func(err error) error {
		conn.Send(ipc.Failed{Text: printableASCII("hand-off refused: "+err.Error(), ipc.MaxFailed)})
		return fmt.Errorf("refused a hand-off: %w", err)
	}
	if err := s.checkHandoffPeer(f); err != nil {
		return refuse(err)
	}
	// Forward only: a session never goes to a binary that is not newer
	// than its own, whoever asks (D8 V2).
	if cmp, ok := bootstrap.CompareVersions(req.SoftwareVersion, s.cfg.Version); !ok || cmp <= 0 {
		return refuse(fmt.Errorf("version %s is not newer than this session's %s", req.SoftwareVersion, s.cfg.Version))
	}
	if int(req.Version) < bootstrap.AttachMin || int(req.Version) > bootstrap.AttachMax {
		return refuse(fmt.Errorf("attach protocol %d", req.Version))
	}
	j := &handoffJob{ready: make(chan error, 1), released: make(chan struct{}), gone: make(chan struct{})}
	select {
	case s.handoffs <- j:
	case <-time.After(T3):
		return refuse(errors.New("the session is busy"))
	}
	if err := <-j.ready; err != nil {
		return refuse(err)
	}
	// Until the loop has the commit, any return drops the hand-off, and
	// the loop thaws proto.
	committed := false
	defer func() {
		if !committed {
			s.handoffDropped <- struct{}{}
		}
	}()
	// The size is the snapshot's, which is the emulator's and so the
	// pty's; the spawner decodes it rather than trust proto's word.
	g := screen.NewGrid(0, 0)
	if err := g.Apply(j.snapshot); err != nil {
		return refuse(fmt.Errorf("proto's snapshot: %w", err))
	}
	cols, rows := g.Size()
	greet := s.greeting()
	state := ipc.HandoffState{
		Version: req.Version, Agent: s.agent != nil, SessionID: s.sid,
		Started: uint64(s.started.Unix()), State: uint8(greet.State), Since: uint64(greet.Since.Unix()),
		Cols: uint16(cols), Rows: uint16(rows), ShellPID: uint32(j.shellPID), ScreenLen: uint32(len(j.snapshot)),
		Peer: greet.Peer, Name: s.name,
		PTY: s.master, Pidfd: j.pidfd, Listener: s.attach.f,
	}
	if err := conn.Send(state); err != nil {
		return fmt.Errorf("sending the hand-off's state: %w", err)
	}
	if s.agent != nil {
		if err := conn.Send(ipc.HandoffAgent{Listener: s.agent.f}); err != nil {
			return fmt.Errorf("sending the agent socket: %w", err)
		}
	}
	for rest := j.snapshot; len(rest) > 0; {
		n := min(len(rest), ipc.MaxFragment-1)
		if err := conn.Send(ipc.HandoffScreen{More: n < len(rest), Fragment: rest[:n]}); err != nil {
			return fmt.Errorf("sending the screen: %w", err)
		}
		rest = rest[n:]
	}
	f.SetReadDeadline(time.Now().Add(s.takenWait))
	m, err := conn.Recv()
	if _, ok := m.(ipc.HandoffTaken); err != nil || !ok {
		ipc.CloseFiles(m)
		return fmt.Errorf("the newer spawner did not take the session (%v): carrying on", err)
	}
	// The commit is two-phase (server.md §2.8 steps 8 and 9): the adopter
	// keeps nothing until HandoffReleased, which goes only once the loop
	// has committed. A loop that has ended the session meanwhile (the
	// shell exited) never takes the commit, and the adopter, hearing no
	// HandoffReleased, gives the session up too.
	select {
	case s.handoffCommit <- struct{}{}:
	case <-time.After(T3):
		return errors.New("the session did not let go in time: carrying on")
	}
	committed = true
	<-j.released
	s.log.Info("handing the session to a newer binary", "version", req.SoftwareVersion)
	if err := conn.Send(ipc.HandoffReleased{}); err != nil {
		// Committed all the same: the adopter, hearing nothing, ends
		// what it started, and the shell hangs up with the last master.
		s.log.Warn("telling the newer spawner the session is released", "err", err)
	}
	<-j.gone
	return nil
}

// startHandoff is the supervision loop's answer to a hand-off request: a
// pidfd for the shell, then Freeze to proto, whose Snapshot the loop
// gathers. It returns when the snapshot is due, or nil with j answered if
// the session cannot hand off.
func (s *spawner) startHandoff(j *handoffJob) <-chan time.Time {
	fail := func(err error) <-chan time.Time {
		j.ready <- err
		return nil
	}
	switch {
	case s.job != nil:
		return fail(errors.New("a hand-off is already under way"))
	case s.shell == nil || s.proto == nil || s.master == nil || s.attach == nil:
		return fail(errors.New("the session is ending"))
	}
	pidfd, err := s.shellPidfd()
	if err != nil {
		return fail(fmt.Errorf("a pidfd for the shell: %w", err))
	}
	s.pauseAgent()
	if err := s.ctl.Send(ipc.Freeze{}); err != nil {
		pidfd.Close()
		s.resumeAgent()
		return fail(fmt.Errorf("asking proto to freeze: %w", err))
	}
	j.pidfd, j.shellPID = pidfd, s.shell.pid()
	s.job, s.snapping, s.lateSnapshot = j, true, false
	return time.After(snapshotWait)
}

// shellPidfd is a pidfd for the shell: a duplicate of the one an adopted
// shell came with, or a new one (pidfd_open, Linux 5.3). The shell is the
// spawner's child, not yet reaped, so its pid cannot have been reused.
func (s *spawner) shellPidfd() (*os.File, error) {
	if s.shell.pidfd != nil {
		raw, err := s.shell.pidfd.SyscallConn()
		if err != nil {
			return nil, err
		}
		var nfd int
		var derr error
		raw.Control(func(fd uintptr) { nfd, derr = unix.FcntlInt(fd, unix.F_DUPFD_CLOEXEC, 0) })
		if derr != nil {
			return nil, derr
		}
		return os.NewFile(uintptr(nfd), "pidfd"), nil
	}
	fd, err := unix.PidfdOpen(s.shell.pid(), 0)
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(fd)
	return os.NewFile(uintptr(fd), "pidfd"), nil
}

// snapshotFragment takes one of proto's Snapshot fragments for the job
// under way. It says whether the snapshot is complete, and refuses one
// nobody asked for (server.md §3.4); the rest of one from a hand-off the
// loop gave up waiting for is dropped.
func (s *spawner) snapshotFragment(m ipc.Snapshot) (done bool, err error) {
	if !s.snapping {
		if s.lateSnapshot {
			s.lateSnapshot = m.More
			return false, nil
		}
		return false, errors.New("a Snapshot nobody asked for")
	}
	if len(s.job.snapshot)+len(m.Fragment) > ipc.MaxSnapshot {
		return false, fmt.Errorf("a snapshot over %d bytes", ipc.MaxSnapshot)
	}
	s.job.snapshot = append(s.job.snapshot, m.Fragment...)
	if m.More {
		return false, nil
	}
	s.snapping = false
	return true, nil
}

// snapshotLate is the loop giving up on proto's Snapshot: the hand-off is
// refused, and whatever of the snapshot still comes is dropped.
func (s *spawner) snapshotLate() {
	if !s.snapping {
		return
	}
	s.snapping, s.lateSnapshot = false, true
	s.job.ready <- errNotFrozen
	s.abandonHandoff()
}

// abandonHandoff ends the job under way without a hand-off: proto is told
// to carry on, and the pidfd goes.
func (s *spawner) abandonHandoff() {
	if s.job == nil {
		return
	}
	if err := s.ctl.Send(ipc.Thaw{}); err != nil {
		s.log.Warn("thawing proto", "err", err)
	}
	s.job.pidfd.Close()
	s.job = nil
	s.resumeAgent()
	s.log.Info("the hand-off was not taken; the session carries on")
}

// handedOff is the old spawner's end once the newer one has taken the
// session (server.md §2.8 step 9): proto and emu go, and the spawner's
// copies of the master, the pidfd and the listeners close, but no socket
// is removed and the shell is never signalled: they are the newer
// spawner's now.
func (s *spawner) handedOff() {
	start := time.Now()
	if s.agent != nil {
		s.agent.release()
		close(s.agentDone)
	}
	if s.attach != nil {
		s.attach.release()
	}
	// proto cuts its client off with REVOKED, as a takeover does (D26),
	// so a client attached here hears now that another has the session.
	if s.ctl != nil {
		if err := s.ctl.Send(ipc.Revoke{}); err != nil {
			s.log.Warn("asking proto to revoke its client", "err", err)
		}
		s.ctl.Close()
	}
	close(s.job.released)
	if s.proto != nil {
		waitOrKill(s.proto, T7)
	}
	if s.master != nil {
		s.master.Close()
	}
	if s.emu != nil {
		waitOrKill(s.emu, T9)
	}
	if s.job != nil {
		s.job.pidfd.Close()
		close(s.job.gone)
	}
	s.log.Info("handed the session over; this binary's part is done", "teardown", time.Since(start).Round(time.Millisecond))
	if s.logFile != nil {
		s.logFile.Close()
	}
}

// release closes the attach listener without removing its socket, which
// another spawner now listens on (server.md §2.8 step 9).
func (l *attachListener) release() error {
	l.closed.Store(true)
	return l.f.Close()
}

// release closes the agent listener without removing its socket.
func (l *agentListener) release() error {
	l.closed.Store(true)
	return l.f.Close()
}

// adoption is what the newer spawner gathers from the old before it
// starts anything (server.md §2.8 steps 2 to 5).
type adoption struct {
	state    ipc.HandoffState
	agent    *os.File
	snapshot []byte
}

// close closes every fd an adoption holds: the spawner's copies only,
// never anything the old session still serves with.
func (a *adoption) close() {
	for _, f := range []*os.File{a.state.PTY, a.state.Pidfd, a.state.Listener, a.agent} {
		if f != nil {
			f.Close()
		}
	}
}

// requestHandoff is steps 2 and 5 of server.md §2.8 on the newer side:
// check the peer, ask, and read and check everything the session sends.
func (s *spawner) requestHandoff(attach *ipc.Conn, sid [16]byte) (*adoption, error) {
	if err := s.checkHandoffPeer(attach.File()); err != nil {
		return nil, err
	}
	// Attach protocol v1 is the only version there is, so it is the one
	// both ranges meet at; a build with two would carry the launcher's
	// choice in Adopt.
	if err := attach.Send(ipc.HandoffRequest{Version: bootstrap.AttachMax, SoftwareVersion: s.cfg.Version}); err != nil {
		return nil, fmt.Errorf("asking for the session: %w", err)
	}
	attach.File().SetReadDeadline(time.Now().Add(T2))
	defer attach.File().SetReadDeadline(time.Time{})
	m, err := attach.Recv()
	if err != nil {
		return nil, fmt.Errorf("waiting for the session's state: %w", err)
	}
	if f, ok := m.(ipc.Failed); ok {
		return nil, fmt.Errorf("the session refused: %s", f.Text)
	}
	st, ok := m.(ipc.HandoffState)
	if !ok {
		ipc.CloseFiles(m)
		return nil, fmt.Errorf("the session sent %T, not its state", m)
	}
	a := &adoption{state: st}
	fail := func(err error) (*adoption, error) {
		a.close()
		return nil, err
	}
	switch {
	case st.Version != bootstrap.AttachMax:
		return fail(fmt.Errorf("state for attach protocol %d", st.Version))
	case st.SessionID != sid:
		return fail(errors.New("the state of another session"))
	case !bootstrap.ValidSessionName(st.Name):
		return fail(fmt.Errorf("a session name %q", printableASCII(st.Name, 64)))
	}
	if st.Agent {
		m, err := attach.Recv()
		ag, ok := m.(ipc.HandoffAgent)
		if err != nil || !ok {
			ipc.CloseFiles(m)
			return fail(fmt.Errorf("waiting for the agent socket: %T %v", m, err))
		}
		a.agent = ag.Listener
	}
	for {
		m, err := attach.Recv()
		if err != nil {
			return fail(fmt.Errorf("waiting for the screen: %w", err))
		}
		frag, ok := m.(ipc.HandoffScreen)
		if !ok {
			ipc.CloseFiles(m)
			return fail(fmt.Errorf("the session sent %T, not its screen", m))
		}
		if len(a.snapshot)+len(frag.Fragment) > int(st.ScreenLen) {
			return fail(errors.New("a screen longer than the state said"))
		}
		a.snapshot = append(a.snapshot, frag.Fragment...)
		if !frag.More {
			break
		}
	}
	if len(a.snapshot) != int(st.ScreenLen) {
		return fail(errors.New("a screen shorter than the state said"))
	}
	if err := s.checkAdoption(a); err != nil {
		return fail(err)
	}
	return a, nil
}

// checkAdoption is server.md §2.8's "What spawner-N checks": the screen
// through the validating decoder at the size the state gives, and that
// each fd is what it is said to be.
func (s *spawner) checkAdoption(a *adoption) error {
	st := a.state
	g := screen.NewGrid(0, 0)
	if err := g.Apply(a.snapshot); err != nil {
		return fmt.Errorf("the session's screen: %w", err)
	}
	if c, r := g.Size(); c != int(st.Cols) || r != int(st.Rows) {
		return fmt.Errorf("a %dx%d screen for a %dx%d session", c, r, st.Cols, st.Rows)
	}
	if err := withFD(st.PTY, func(fd int) error {
		_, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
		return err
	}); err != nil {
		return fmt.Errorf("the pty master is not one: %w", err)
	}
	if err := withFD(st.Pidfd, func(fd int) error {
		pid, err := pidfdPid(fd)
		switch {
		case err != nil:
			return err
		case pid != int(st.ShellPID):
			return fmt.Errorf("it names pid %d, not the shell's %d", pid, st.ShellPID)
		}
		return unix.PidfdSendSignal(fd, 0, nil, 0)
	}); err != nil {
		return fmt.Errorf("the shell's pidfd: %w", err)
	}
	dir := sessionDir(sessionsDir(s.getenv), st.SessionID)
	if err := checkListener(st.Listener, filepath.Join(dir, attachName), unix.SOCK_SEQPACKET); err != nil {
		return fmt.Errorf("the attach socket: %w", err)
	}
	if a.agent != nil {
		if err := checkListener(a.agent, filepath.Join(dir, agentName), unix.SOCK_STREAM); err != nil {
			return fmt.Errorf("the agent socket: %w", err)
		}
	}
	return nil
}

// withFD runs check on f's descriptor.
func withFD(f *os.File, check func(fd int) error) error {
	raw, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var cerr error
	if err := raw.Control(func(fd uintptr) { cerr = check(int(fd)) }); err != nil {
		return err
	}
	return cerr
}

// pidfdPid is the pid a pidfd names, from its fdinfo's Pid line (-1 once
// the process has been reaped) [kernel ABI, proc(5)].
func pidfdPid(fd int) (int, error) {
	f, err := os.Open("/proc/self/fdinfo/" + strconv.Itoa(fd))
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := bytes.CutPrefix(sc.Bytes(), []byte("Pid:")); ok {
			return strconv.Atoi(string(bytes.TrimSpace(v)))
		}
	}
	return 0, errors.New("not a pidfd")
}

// checkListener says whether f is a listening unix socket of type typ
// bound at path: under path.tmp, the name it is bound under before it is
// renamed into place (server.md §2.6), which is the name the kernel keeps.
func checkListener(f *os.File, path string, typ int) error {
	return withFD(f, func(fd int) error {
		sa, err := unix.Getsockname(fd)
		if err != nil {
			return err
		}
		if u, ok := sa.(*unix.SockaddrUnix); !ok || u.Name != path+".tmp" && u.Name != path {
			return fmt.Errorf("bound at %v, not %s", sa, path)
		}
		if t, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE); err != nil || t != typ {
			return fmt.Errorf("a socket of type %d", t)
		}
		if acc, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ACCEPTCONN); err != nil || acc != 1 {
			return errors.New("not listening")
		}
		return nil
	})
}

// adoptShell is a child for a shell this spawner did not start: watched
// through its pidfd, which polls readable once the process has exited
// [kernel ABI, pidfd_open(2)].
func adoptShell(pidfd *os.File, pid int) *child {
	c := &child{role: "shell", born: time.Now(), done: make(chan *os.ProcessState, 1), pidfd: pidfd, pidfdPid: pid}
	raw, err := pidfd.SyscallConn()
	go func() {
		if err == nil {
			raw.Control(func(fd uintptr) {
				pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
				for {
					if _, err := unix.Poll(pfd, -1); err != unix.EINTR {
						return
					}
				}
			})
		}
		c.done <- nil
	}()
	return c
}

// commitAdoption is the adopter's half of the two-phase commit (server.md
// §2.8 steps 8 and 9): HandoffTaken, then HandoffReleased within T2. The
// old side sends that only once it has stopped accepting and will never
// thaw; anything else (it closed the connection, it gave up waiting for
// HandoffTaken, it sent something else) means it carries on, and so this
// spawner must not.
func (s *spawner) commitAdoption(attach *ipc.Conn) error {
	if err := attach.Send(ipc.HandoffTaken{}); err != nil {
		return fmt.Errorf("taking the session: %w", err)
	}
	attach.File().SetReadDeadline(time.Now().Add(T2))
	defer attach.File().SetReadDeadline(time.Time{})
	m, err := attach.Recv()
	if err != nil {
		return fmt.Errorf("waiting for the session to let go: %w", err)
	}
	if _, ok := m.(ipc.HandoffReleased); !ok {
		ipc.CloseFiles(m)
		return fmt.Errorf("the session sent %T, not HandoffReleased", m)
	}
	return nil
}

// stopStarted ends the proto and emu a failed adoption started, before
// the old session thaws.
func (s *spawner) stopStarted() {
	if s.ctl != nil {
		s.ctl.Close()
	}
	if s.proto != nil {
		waitOrKill(s.proto, T7)
		s.proto = nil
	}
	if s.emu != nil {
		waitOrKill(s.emu, T9)
		s.emu = nil
	}
	s.master = nil // a.close closes it
}

// adopt is the newer spawner's whole part of a live upgrade (server.md
// §2.8 steps 2 and 5 to 10), in place of bootstrap's: it takes the session
// at the other end of m.Conn for the client whose line is m.Line. Until
// HandoffReleased, any failure leaves the old session whole (it thaws when
// the connection closes) and nothing of it is touched here but this
// spawner's own copies of its fds.
func (s *spawner) adopt(ctx context.Context, m ipc.Adopt) error {
	attach, err := ipc.NewConn(m.Conn, ipc.Launcher, ipc.Spawner)
	if err != nil {
		m.Conn.Close()
		return err
	}
	// Closed on any failure, which is what thaws the old session; once
	// the session is taken, by the goroutine that waits for its EOF.
	taken := false
	defer func() {
		if !taken {
			attach.Close()
		}
	}()
	cl, err := bootstrap.ParseClientLine(m.Line)
	if err != nil || cl.Attach != bootstrap.AttachResume {
		return &LaunchError{Code: bootstrap.CodeLine, Text: "not a resume to adopt"}
	}
	if _, err := checkResumeLine(m.Line, cl.SessionID); err != nil {
		return err
	}
	// As bootstrap: pin no mount, outlive the ssh login's hangup, never
	// die of a write to a closed pipe.
	os.Chdir("/")
	signal.Ignore(syscall.SIGHUP, syscall.SIGPIPE)
	if err := s.openLog(); err != nil {
		return err
	}
	a, err := s.requestHandoff(attach, cl.SessionID)
	if err != nil {
		return fmt.Errorf("the hand-off: %w", err)
	}
	// From here until HandoffReleased an error ends proto-N and emu-N,
	// then closes a's fds (this spawner's copies), and only then the
	// connection, which thaws the old session: so no two protos ever read
	// the pty at once.
	defer func() {
		if !taken {
			s.stopStarted()
			a.close()
		}
	}()
	st := a.state
	s.sid, s.name = st.SessionID, st.Name
	s.started = time.Unix(int64(st.Started), 0)
	s.log.Info("adopting a session from an older binary", "name", s.name, "shell", st.ShellPID)

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
	s.master = st.PTY

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
		Cols: st.Cols, Rows: st.Rows, Port: port, Addr: s.advertised,
		ClientPublic: cl.Public, Name: s.name, Adopted: true, SessionID: s.sid,
		UDP: udp, PTY: st.PTY,
	})
	if err == nil {
		err = s.ctl.Send(ipc.EmuLink{Generation: 1, Reason: ipc.EmuFirst, Conn: emuEnd})
	}
	for rest := a.snapshot; err == nil && len(rest) > 0; {
		n := min(len(rest), ipc.MaxFragment-1)
		err = s.ctl.Send(ipc.Seed{More: n < len(rest), Fragment: rest[:n]})
		rest = rest[n:]
	}
	if err != nil {
		return fmt.Errorf("handing proto the session: %w", err)
	}

	line, err := s.awaitCredential(ctx)
	defer func() { clear(line) }()
	if err != nil {
		return err
	}
	cred, _ := bootstrap.ParseCredentialLine(line)
	clear(cred.PSK[:])
	if cred.SessionID != s.sid {
		s.violation(errors.New("a credential for another session"))
		return errors.New("proto sent a bad credential")
	}

	// Steps 8 and 9: the session is this spawner's only once the old one
	// says it has let go. Without that, the old one may yet thaw, so this
	// one keeps nothing.
	if err := s.commitAdoption(attach); err != nil {
		return err
	}
	taken = true
	dir := sessionDir(sessionsDir(s.getenv), s.sid)
	s.attach = &attachListener{f: st.Listener, dir: dir, path: filepath.Join(dir, attachName)}
	if a.agent != nil {
		s.agent = &agentListener{f: a.agent, path: filepath.Join(dir, agentName)}
		s.agentConns = make(chan *os.File)
		s.agentDone = make(chan struct{})
	}
	s.shell = adoptShell(st.Pidfd, int(st.ShellPID))
	s.adopted = true
	s.resumes = make(chan resumeRequest)
	s.hangups = make(chan struct{}, 1)
	// Whatever client the old proto had is cut off with it, so the
	// session is detached until one attaches here, held meanwhile for the
	// credential just minted, as for any resume (bootstrap.md §9.2).
	s.state, s.since, s.peer = bootstrap.SessionDetached, time.Now(), st.Peer
	s.holdFor(cred.CredentialID, cl.Holder, cl.HasHolder)
	// The old spawner closes the connection once its proto and emu are
	// gone (step 9); nothing waits on that, since it has let go, but the
	// log says when.
	go func() {
		defer attach.Close()
		attach.File().SetReadDeadline(time.Now().Add(T2))
		m, err := attach.Recv()
		ipc.CloseFiles(m)
		s.log.Info("the older spawner has gone", "eof", ipc.IsEOF(err))
	}()
	if err := s.launcher.Send(ipc.Ready{Line: line}); err != nil {
		s.log.Warn("telling the launcher", "err", err)
	}
	s.launcher.Close()
	s.launcher = nil
	s.ready = true
	s.log.Info("adopted the session", "name", s.name, "shell", st.ShellPID)
	return nil
}
