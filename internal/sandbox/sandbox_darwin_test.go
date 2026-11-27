package sandbox

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Each scenario runs in a fresh copy of the test binary, because a
// sandbox cannot be left: TestMain sees MOSEY_SANDBOX_CHILD and runs the
// scenario instead of the tests.
const childEnv = "MOSEY_SANDBOX_CHILD"

func TestMain(m *testing.M) {
	if scenario := os.Getenv(childEnv); scenario != "" {
		run, ok := children[scenario]
		if !ok {
			fmt.Fprintln(os.Stderr, "child: unknown scenario", scenario)
			os.Exit(2)
		}
		if err := run(); err != nil {
			fmt.Fprintln(os.Stderr, "child:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

var children = map[string]func() error{
	"proto": childProto,
	"emu":   childEmu,
}

// The fds a child is started with (exec.Cmd.ExtraFiles).
const (
	fdIPC = 3 // a unix stream socket to the test, as the roles' IPC socket is
	fdUDP = 4 // proto's UDP socket
)

// What the test gives the child, in its environment.
const (
	envFile   = "MOSEY_SANDBOX_FILE"   // a file the child must not open
	envTCP    = "MOSEY_SANDBOX_TCP"    // a TCP listener the child must not reach
	envUnix   = "MOSEY_SANDBOX_UNIX"   // a unix socket path the child must not reach
	envPeer   = "MOSEY_SANDBOX_PEER"   // a UDP address a new socket must not send to
	envVictim = "MOSEY_SANDBOX_VICTIM" // a process the child must not signal or inspect
)

// childProto is proto's needs and limits after Enter (server.md §10): it
// answers a datagram on its own port, takes an fd over its IPC socket with
// SCM_RIGHTS and uses it, and sets the pty's size.
func childProto() error {
	pc, err := net.FilePacketConn(os.NewFile(fdUDP, "udp"))
	if err != nil {
		return err
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	master, slave, err := openPTY()
	if err != nil {
		return err
	}
	defer slave.Close()
	if err := Enter(Proto, Kill, Params{UDPPort: port}, nil); err != nil {
		return fmt.Errorf("entering the sandbox: %w", err)
	}
	if err := checkSandboxed(); err != nil {
		return err
	}

	// The test sent a datagram to this port before the child started.
	buf := make([]byte, 64)
	n, from, err := pc.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "ping" {
		return fmt.Errorf("reading the test's datagram: %q, %v", buf[:n], err)
	}
	if _, err := pc.WriteTo([]byte("pong"), from); err != nil {
		return fmt.Errorf("answering on its own UDP socket: %w", err)
	}

	// The agent connection comes as AgentConn does: an fd over IPC.
	fds, err := recvFDs(fdIPC)
	if err != nil {
		return fmt.Errorf("recvmsg with SCM_RIGHTS: %w", err)
	}
	agent := os.NewFile(uintptr(fds[0]), "agent")
	if _, err := agent.Read(buf[:1]); err != nil || buf[0] != 'a' {
		return fmt.Errorf("reading the passed fd: %q, %v", buf[:1], err)
	}
	if _, err := agent.Write([]byte("b")); err != nil {
		return fmt.Errorf("writing the passed fd: %w", err)
	}

	fd := int(master.Fd())
	if err := unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &unix.Winsize{Row: 40, Col: 120}); err != nil {
		return fmt.Errorf("TIOCSWINSZ: %w", err)
	}
	if _, err := unix.IoctlGetTermios(fd, unix.TIOCGETA); err != nil {
		return fmt.Errorf("TIOCGETA: %w", err)
	}
	if ws, err := unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ); err != nil || ws.Col != 120 {
		return fmt.Errorf("TIOCGWINSZ: %+v, %v", ws, err)
	}
	return refusals()
}

// childEmu is emu's needs and limits after Enter: it reads and writes its
// IPC socket, and nothing else.
func childEmu() error {
	if err := Enter(Emu, Kill, Params{}, nil); err != nil {
		return fmt.Errorf("entering the sandbox: %w", err)
	}
	if err := checkSandboxed(); err != nil {
		return err
	}
	ipc := os.NewFile(fdIPC, "ipc")
	buf := make([]byte, 1)
	if _, err := ipc.Read(buf); err != nil || buf[0] != 'x' {
		return fmt.Errorf("reading IPC: %q, %v", buf, err)
	}
	if _, err := ipc.Write([]byte("y")); err != nil {
		return fmt.Errorf("writing IPC: %w", err)
	}
	return refusals()
}

// checkSandboxed checks the process is under a profile, and that the
// runtime still sees every CPU: without the hw.ncpu rule its GOMAXPROCS
// update drops to 1 [M].
func checkSandboxed() error {
	if !sandboxed(os.Getpid()) {
		return errors.New("sandbox_check says the process is not sandboxed")
	}
	runtime.SetDefaultGOMAXPROCS()
	if n := runtime.GOMAXPROCS(0); runtime.NumCPU() > 1 && n < 2 {
		return fmt.Errorf("GOMAXPROCS is %d after Enter, with %d CPUs", n, runtime.NumCPU())
	}
	return nil
}

// refusals is what neither role may do: each must fail.
func refusals() error {
	var bad []string
	refused := func(what string, err error) {
		if err == nil {
			bad = append(bad, what)
		}
	}
	f, err := os.Open(os.Getenv(envFile))
	refused("open a file", err)
	if err == nil {
		f.Close()
	}
	_, err = os.Stat(os.Getenv(envFile))
	refused("stat a file", err)
	c, err := net.Dial("tcp", os.Getenv(envTCP))
	refused("connect over TCP", err)
	if err == nil {
		c.Close()
	}
	c, err = net.Dial("unix", os.Getenv(envUnix))
	refused("connect a unix socket", err)
	if err == nil {
		c.Close()
	}
	refused("send from a new UDP socket", sendFromNewSocket(os.Getenv(envPeer)))
	refused("bind a new UDP socket", func() error {
		c, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err == nil {
			c.Close()
		}
		return err
	}())
	refused("exec", exec.Command("/usr/bin/true").Run())
	victim, _ := strconv.Atoi(os.Getenv(envVictim))
	refused("signal another process", unix.Kill(victim, unix.SIGCONT))
	_, err = unix.SysctlKinfoProc("kern.proc.pid", victim)
	refused("read another process's info", err)
	if len(bad) > 0 {
		return fmt.Errorf("allowed under the sandbox: %s", strings.Join(bad, ", "))
	}
	return nil
}

// sendFromNewSocket sends a datagram to addr from a new, unbound UDP
// socket.
func sendFromNewSocket(addr string) error {
	ap, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	sa := &unix.SockaddrInet4{Port: ap.Port}
	copy(sa.Addr[:], ap.IP.To4())
	return unix.Sendto(fd, []byte("escaped"), 0, sa)
}

func recvFDs(fd int) ([]int, error) {
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	_, oobn, _, _, err := unix.Recvmsg(fd, buf, oob, 0)
	if err != nil {
		return nil, err
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) != 1 {
		return nil, fmt.Errorf("control messages %d: %v", len(msgs), err)
	}
	return unix.ParseUnixRights(&msgs[0])
}

// openPTY opens a pty pair, as the spawner does, before the sandbox.
func openPTY() (master, slave *os.File, err error) {
	master, err = os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}
	fd := int(master.Fd())
	if err := unix.IoctlSetInt(fd, unix.TIOCPTYGRANT, 0); err != nil {
		return nil, nil, err
	}
	if err := unix.IoctlSetInt(fd, unix.TIOCPTYUNLK, 0); err != nil {
		return nil, nil, err
	}
	name := make([]byte, 128)
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TIOCPTYGNAME), uintptr(unsafe.Pointer(&name[0]))); e != 0 {
		return nil, nil, e
	}
	slave, err = os.OpenFile(unix.ByteSliceToString(name), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}
	return master, slave, nil
}

// world is what the test sets up around a child: the things it may use,
// and the things it must not reach.
type world struct {
	t    *testing.T
	ipc  *os.File // the test's end of the child's IPC socket
	kid  *os.File // the child's end
	env  []string
	peer *net.UDPConn
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{t: t}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	w.ipc, w.kid = os.NewFile(uintptr(pair[0]), "ipc"), os.NewFile(uintptr(pair[1]), "kid")
	t.Cleanup(func() { w.ipc.Close(); w.kid.Close() })

	// Not t.TempDir: a unix socket path holds 104 bytes, and the test's
	// name and a macOS $TMPDIR together are longer.
	dir, err := os.MkdirTemp("", "sb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	file := filepath.Join(dir, "secret")
	if err := os.WriteFile(file, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tcp.Close() })
	sock := filepath.Join(dir, "s")
	ux, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("no unix socket at %s: %v", sock, err)
	}
	t.Cleanup(func() { ux.Close() })
	w.peer, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.peer.Close() })
	victim := exec.Command("/bin/sleep", "600")
	if err := victim.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { victim.Process.Kill(); victim.Wait() })

	w.env = []string{
		envFile + "=" + file,
		envTCP + "=" + tcp.Addr().String(),
		envUnix + "=" + sock,
		envPeer + "=" + w.peer.LocalAddr().String(),
		envVictim + "=" + strconv.Itoa(victim.Process.Pid),
	}
	return w
}

// run runs scenario with fd 3 the IPC socket and any more fds after it,
// and fails the test if it does not exit 0.
func (w *world) run(scenario string, more ...*os.File) {
	w.t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(append(os.Environ(), childEnv+"="+scenario), w.env...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	cmd.ExtraFiles = append([]*os.File{w.kid}, more...)
	if err := cmd.Run(); err != nil {
		w.t.Fatalf("%s: %v\n%s", scenario, err, stderr.String())
	}
}

func TestProtoUnderItsProfileDoesItsJobAndNothingElse(t *testing.T) {
	w := newWorld(t)
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	udpFile, err := udp.File()
	udp.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer udpFile.Close()
	// Everything the child reads is in place before it starts, so no step
	// waits on another: the datagram, and the fd with a byte in it.
	if _, err := w.peer.WriteTo([]byte("ping"), udp.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	agent, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(agent[0])
	if _, err := unix.Write(agent[0], []byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Sendmsg(int(w.ipc.Fd()), []byte{0}, unix.UnixRights(agent[1]), nil, 0); err != nil {
		t.Fatal(err)
	}
	unix.Close(agent[1])

	w.run("proto", udpFile)

	buf := make([]byte, 64)
	if n, err := unix.Read(agent[0], buf); err != nil || string(buf[:n]) != "b" {
		t.Errorf("the passed fd carried %q, %v", buf[:n], err)
	}
	// The answer was sent before the child exited; the deadline only
	// keeps a lost datagram from hanging the test.
	w.peer.SetReadDeadline(time.Now().Add(30 * time.Second))
	if n, _, err := w.peer.ReadFrom(buf); err != nil || string(buf[:n]) != "pong" {
		t.Errorf("proto's answer was %q, %v", buf[:n], err)
	}
}

func TestEmuUnderItsProfileTalksToItsSocketAndNothingElse(t *testing.T) {
	w := newWorld(t)
	if _, err := w.ipc.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	w.run("emu")
	buf := make([]byte, 1)
	if _, err := w.ipc.Read(buf); err != nil || buf[0] != 'y' {
		t.Errorf("emu answered %q, %v", buf, err)
	}
}

// The children check that sandboxed is true after Enter. This checks that
// it is not true of every process.
func TestAProcessWithNoProfileIsNotSandboxed(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "600")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	if sandboxed(cmd.Process.Pid) {
		t.Errorf("sleep, started with no profile, is sandboxed")
	}
}

// TestLiveRolesAreSandboxed checks the processes MOSEY_SANDBOX_PIDS names
// (a comma-separated list) are under a profile: run it on a Mac against
// the proto and emu of a live session, found with ps.
func TestLiveRolesAreSandboxed(t *testing.T) {
	pids := os.Getenv("MOSEY_SANDBOX_PIDS")
	if pids == "" {
		t.Skip("MOSEY_SANDBOX_PIDS names no live roles")
	}
	for _, s := range strings.Split(pids, ",") {
		pid, err := strconv.Atoi(s)
		if err != nil {
			t.Fatal(err)
		}
		if !sandboxed(pid) {
			t.Errorf("pid %d is not sandboxed", pid)
		} else {
			t.Logf("pid %d is sandboxed", pid)
		}
	}
}
