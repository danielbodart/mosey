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

// Shell is how to start the user's login shell (D14, server.md §2.5).
type Shell struct {
	// Path is the shell to run; LoginShell finds the user's.
	Path string
	// Dir is the directory it starts in.
	Dir string
	// Env is its whole environment.
	Env []string
}

// Start starts the shell as a login shell (argv[0] is "-" and its base
// name), as the leader of a new session with slave as its controlling
// terminal and as its stdin, stdout and stderr. It has no parent-death
// signal: the shell is the user's, and the spawner hangs it up instead.
// The caller closes slave once Start returns.
func (s Shell) Start(slave *os.File) (*os.Process, error) {
	cmd := &exec.Cmd{
		Path:   s.Path,
		Args:   []string{"-" + filepath.Base(s.Path)},
		Dir:    s.Dir,
		Env:    s.Env,
		Stdin:  slave,
		Stdout: slave,
		Stderr: slave,
	}
	cmd.SysProcAttr = sessionLeader()
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd.Process, nil
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
