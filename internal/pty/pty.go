package pty

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/danielbodart/mosey/internal/startup"
)

// Size is a window size in cells.
type Size struct{ Cols, Rows int }

// Open makes a new pty at the given size and returns its master and slave,
// both close-on-exec. The master is non-blocking, so reads and writes park
// on the poller and closing it at the session's end releases them.
func Open(size Size) (master, slave *os.File, err error) {
	return open(size)
}

// SetSize sets the window size on a pty master; the kernel sends the
// foreground process group SIGWINCH when it changes.
func SetSize(master *os.File, size Size) error {
	return setSize(master, size)
}

// GetSize reads the window size back.
func GetSize(f *os.File) (Size, error) {
	return getSize(f)
}

// EchoOff reads the slave's termios through the master and says whether
// echo is off in canonical mode (!ECHO && ICANON), the D12 echo-off bit: a
// password prompt, not a full-screen program in raw mode.
func EchoOff(master *os.File) (bool, error) {
	return echoOff(master)
}

// Echoes reads the slave's termios through the master and says whether
// the line discipline echoes what is typed (ECHO). A line editor such as
// readline turns it off just before it draws its prompt and reads keys
// itself, so text typed while it is still on would show twice
// (bootstrap.md §9.2.3).
func Echoes(master *os.File) (bool, error) {
	return echoes(master)
}

// ForegroundRoot says whether the process at the keyboard of the pty whose
// master this is runs as root: the leader of the slave's foreground
// process group, read with TIOCGPGRP, has effective uid 0 in the Uid line
// of /proc/PGID/status (screen.md §4.8, server.md §2.9). The leader is one
// small file; every member of the group would be a walk of /proc. A
// leader that is gone or hidden is not root: an unknown is never shown as
// root. Outside Linux it returns errors.ErrUnsupported.
func ForegroundRoot(master *os.File) (bool, error) {
	return foregroundRoot(master)
}

// maxStatus bounds the read of /proc/PID/status: the Uid line is the
// ninth or so of a file of about 1.5 KiB [measured here, Linux 6.18], so
// 4 KiB holds it with room to spare and a kernel that grew the file
// cannot make the read unbounded.
const maxStatus = 4096

// rootIn reads the status file of process pid under proc (/proc, or a
// test's fake) and says whether its effective uid is 0.
func rootIn(proc string, pid int) bool {
	f, err := os.Open(filepath.Join(proc, strconv.Itoa(pid), "status"))
	if err != nil {
		return false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxStatus))
	if err != nil {
		return false
	}
	euid, ok := effectiveUID(b)
	return ok && euid == 0
}

// effectiveUID is the second field of a proc(5) status file's Uid line,
// "Uid:" then the real, effective, saved and filesystem uids, tab
// separated. A line that is missing, short, or not decimal gives false.
func effectiveUID(status []byte) (uint32, bool) {
	for line := range bytes.SplitSeq(status, []byte("\n")) {
		rest, ok := bytes.CutPrefix(line, []byte("Uid:"))
		if !ok {
			continue
		}
		f := strings.Fields(string(rest))
		if len(f) != 4 {
			return 0, false
		}
		u, err := strconv.ParseUint(f[1], 10, 32)
		if err != nil {
			return 0, false
		}
		return uint32(u), true
	}
	return 0, false
}

// Shell is how to start the user's login shell (D14, server.md §2.5).
type Shell struct {
	// Self is how this mosey was started; the shell is started the same
	// way (internal/startup).
	Self startup.Process
	// Path is the shell to run; LoginShell finds the user's.
	Path string
	// Dir is the directory it starts in.
	Dir string
	// Env is its whole environment.
	Env []string
	// Command, if set, is run by the shell with -c in place of an
	// interactive session (bootstrap.md §9.2.3, server.md §2.5), as one
	// argument: the shell is the only thing that reads it.
	Command string
}

// Start starts the shell as a login shell (argv[0] is "-" and its base
// name), with -c and Command if there is one, as the leader of a new session with slave as its controlling
// terminal and as its stdin, stdout and stderr. It has no parent-death
// signal: the shell is the user's, and the spawner hangs it up instead.
// The caller closes slave once Start returns.
func (s Shell) Start(slave *os.File) (*os.Process, error) {
	cmd := &exec.Cmd{
		Path:   s.Path,
		Args:   s.args(),
		Dir:    s.Dir,
		Env:    s.Env,
		Stdin:  slave,
		Stdout: slave,
		Stderr: slave,
	}
	cmd.SysProcAttr = sessionLeader()
	s.Self.Prepare(cmd)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd.Process, nil
}

// args is the shell's argv: a login shell's argv[0], and -c and the
// command when there is one. A login shell reads the user's profile, so
// the command gets the PATH the interactive shell would have had.
func (s Shell) args() []string {
	argv := []string{"-" + filepath.Base(s.Path)}
	if s.Command != "" {
		argv = append(argv, "-c", s.Command)
	}
	return argv
}

// LoginShell finds the user's shell and home directory as server.md §2.5
// says: $SHELL if it is an absolute path to an executable file (sshd sets
// it from the password database through NSS, which a CGO_ENABLED=0 binary
// cannot query, so it is the only way to see an LDAP or sssd user's shell);
// else the shell field of uid's line in passwd; else /bin/sh. The home is
// $HOME, else passwd's, else /.
func LoginShell(getenv func(string) string, passwd io.Reader, uid int) (shell, home string) {
	pwShell, pwHome := passwdEntry(passwd, uid)
	shell = "/bin/sh"
	if s := getenv("SHELL"); filepath.IsAbs(s) && executable(s) {
		shell = s
	} else if filepath.IsAbs(pwShell) && executable(pwShell) {
		shell = pwShell
	}
	home = "/"
	if h := getenv("HOME"); filepath.IsAbs(h) {
		home = h
	} else if filepath.IsAbs(pwHome) {
		home = pwHome
	}
	return shell, home
}

func executable(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
}

// passwdEntry is the home and shell of uid's line in a passwd(5) file:
// name:password:uid:gid:gecos:home:shell.
func passwdEntry(r io.Reader, uid int) (shell, home string) {
	if r == nil {
		return "", ""
	}
	want := strconv.Itoa(uid)
	s := bufio.NewScanner(io.LimitReader(r, 16<<20))
	s.Buffer(make([]byte, 4096), 64<<10)
	for s.Scan() {
		line := s.Bytes()
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		f := bytes.Split(line, []byte(":"))
		if len(f) != 7 || string(f[2]) != want {
			continue
		}
		return strings.TrimSpace(string(f[6])), string(f[5])
	}
	return "", ""
}
