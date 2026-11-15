//go:build linux

package e2e

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/danielbodart/mosey/internal/bootstrap"
)

// clientRun is one run of the real client binary on a pty, against the
// throwaway sshd, with no -remote: D7's probe and copy-over.
type clientRun struct {
	cmd    *exec.Cmd
	master *os.File
	screen screenLog
	exited chan error
}

func startUploadClient(t *testing.T, s *sshd, mosey, state string, flags ...string) *clientRun {
	t.Helper()
	master, slave := openPTY(t)
	args := append(flags, "--", "-F", s.config, s.host)
	c := &clientRun{cmd: exec.Command(mosey, args...), master: master, exited: make(chan error, 1)}
	c.cmd.Stdin, c.cmd.Stdout, c.cmd.Stderr = slave, slave, slave
	c.cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
	c.cmd.Env = append(os.Environ(), "XDG_STATE_HOME="+state, "TERM=xterm-256color", "LANG=C.UTF-8")
	if err := c.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	slave.Close()
	go c.screen.collect(master)
	go func() { c.exited <- c.cmd.Wait() }()
	t.Cleanup(func() {
		select {
		case <-c.exited:
		default:
			c.cmd.Process.Signal(syscall.SIGTERM)
			<-c.exited
		}
	})
	return c
}

// wait is the client's exit status, once it has exited.
func (c *clientRun) wait(t *testing.T) int {
	t.Helper()
	var err error
	waitFor(t, "mosey to exit", func() bool {
		select {
		case err = <-c.exited:
			c.exited <- err
			return true
		default:
			return false
		}
	})
	return bootstrap.ExitStatus(err)
}

// session checks a whole session works: the far shell answers, and exiting
// it ends the client with status 0.
func (c *clientRun) session(t *testing.T, state string) {
	t.Helper()
	waitFor(t, "the session's screen", func() bool { return strings.Contains(c.screen.String(), "\x1b[?1049h") })
	if _, err := c.master.Write([]byte("echo copied-$((6*7))\r")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the shell's answer", func() bool {
		return strings.Contains(screenOf([]byte(c.screen.String()), 100, 30), "copied-42")
	})
	c.master.Write([]byte("exit\r"))
	if status := c.wait(t); status != 0 {
		t.Fatalf("mosey exited %d; log:\n%s", status, readFile(filepath.Join(state, "mosey", "client.log")))
	}
}

func (s *sshd) cached(version string) string {
	return filepath.Join(s.home, ".cache", "mosey", version, "mosey")
}

func sameFile(t *testing.T, a, b string) bool {
	t.Helper()
	x, err := os.ReadFile(a)
	if err != nil {
		t.Logf("%s: %v", a, err)
		return false
	}
	y, err := os.ReadFile(b)
	return err == nil && bytes.Equal(x, y)
}

// D7 end to end through a real sshd (bootstrap.md §4.7, §12): a host with
// no mosey of this version gets the client's own file, by consent, and the
// session then runs from ~/.cache/mosey/V/mosey; another version installs
// beside it; a cached file of the wrong version is replaced; and a
// ~/.cache/mosey that is a symlink is refused with nothing written through
// it. The remote HOME is the throwaway sshd's, never the user's, and the
// versions are ones nothing on the remote PATH can have.
func TestAutoUploadThroughSSH(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	s := startSSHD(t)
	a := buildMosey(t, "0-e2e-upload-a")
	b := buildMosey(t, "0-e2e-upload-b")
	for _, v := range []string{"0-e2e-upload-a", "0-e2e-upload-b", "0-e2e-upload-c"} {
		// The far side's processes run from the cache, not from the
		// build: end them too when the test is done.
		path := s.cached(v)
		t.Cleanup(func() { killExe(path) })
	}
	state := t.TempDir()

	t.Run("a host with none asks, copies and runs the copy", func(t *testing.T) {
		c := startUploadClient(t, s, a, state)
		waitFor(t, "the question", func() bool { return strings.Contains(c.screen.String(), "[y/N]") })
		if !strings.Contains(c.screen.String(), "has no mosey 0-e2e-upload-a. Copy this one (linux/") {
			t.Errorf("asked %q", c.screen.String())
		}
		c.master.Write([]byte("y\r"))
		c.session(t, state)
		if !sameFile(t, s.cached("0-e2e-upload-a"), a) {
			t.Fatal("the cache does not hold the client's own file")
		}
		if st, err := os.Stat(s.cached("0-e2e-upload-a")); err != nil || st.Mode().Perm() != 0o700 {
			t.Errorf("the copy's mode: %v %v", st.Mode(), err)
		}
		if leftovers, _ := filepath.Glob(filepath.Join(s.home, ".cache", "mosey", ".upload.*")); len(leftovers) != 0 {
			t.Errorf("left %q", leftovers)
		}
	})

	t.Run("another version installs beside it without asking again", func(t *testing.T) {
		c := startUploadClient(t, s, b, state)
		c.session(t, state)
		if strings.Contains(c.screen.String(), "[y/N]") {
			t.Error("asked again for a remembered host")
		}
		if !sameFile(t, s.cached("0-e2e-upload-b"), b) || !sameFile(t, s.cached("0-e2e-upload-a"), a) {
			t.Error("the two versions are not side by side")
		}
	})

	t.Run("-list finds the copy in the cache", func(t *testing.T) {
		// Nothing on the remote PATH is this version: only the probe's
		// look in ~/.cache/mosey finds a lister (bootstrap.md §9.4). The
		// last session may still be on its way out, so it may be listed.
		cmd := exec.Command(b, "-list", "--", "-F", s.config, s.host)
		cmd.Env = append(os.Environ(), "XDG_STATE_HOME="+state)
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "no sessions") && !strings.HasPrefix(string(out), "NAME ") {
			t.Errorf("mosey -list: %v\n%q", err, out)
		}
	})

	cBuild := buildMosey(t, "0-e2e-upload-c")
	t.Run("-list and -kill copy nothing to a host without this version", func(t *testing.T) {
		cmd := exec.Command(cBuild, "-list", "--", "-F", s.config, s.host)
		cmd.Env = append(os.Environ(), "XDG_STATE_HOME="+state)
		out, err := cmd.CombinedOutput()
		if bootstrap.ExitStatus(err) == 0 || !strings.Contains(string(out), "no mosey 0-e2e-upload-c on mosey-e2e") {
			t.Errorf("mosey -list: %v\n%q", err, out)
		}
		c := startUploadClient(t, s, cBuild, state, "-kill", "work", "-upload=yes")
		if status := c.wait(t); status != 1 {
			t.Errorf("mosey -kill exited %d", status)
		}
		if !strings.Contains(c.screen.String(), "no mosey 0-e2e-upload-c on mosey-e2e") {
			t.Errorf("mosey -kill said %q", c.screen.String())
		}
		if _, err := os.Lstat(filepath.Dir(s.cached("0-e2e-upload-c"))); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("something was copied: %v", err)
		}
	})

	t.Run("a cached file of the wrong version is replaced", func(t *testing.T) {
		// Version b's place holds a's file: the probe asks it, hears
		// the wrong version, and b is copied over it.
		// Put in place by a rename: the last session's processes may still
		// be running from the file being replaced.
		data, _ := os.ReadFile(a)
		tmp := s.cached("0-e2e-upload-b") + ".tmp"
		if err := os.WriteFile(tmp, data, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, s.cached("0-e2e-upload-b")); err != nil {
			t.Fatal(err)
		}
		c := startUploadClient(t, s, b, state)
		c.session(t, state)
		if !sameFile(t, s.cached("0-e2e-upload-b"), b) {
			t.Error("the wrong version was kept")
		}
	})

	t.Run("a symlinked cache is refused", func(t *testing.T) {
		cache := filepath.Join(s.home, ".cache", "mosey")
		elsewhere := filepath.Join(t.TempDir(), "mosey")
		if err := os.Rename(cache, elsewhere); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(elsewhere, cache); err != nil {
			t.Fatal(err)
		}
		c := startUploadClient(t, s, cBuild, state, "-upload=yes")
		if status := c.wait(t); status != 1 {
			t.Errorf("exit %d", status)
		}
		out := c.screen.String()
		if !strings.Contains(out, "~/.cache/mosey is a symbolic link") || !strings.Contains(out, "copying mosey to mosey-e2e failed") {
			t.Errorf("said %q", out)
		}
		if _, err := os.Lstat(filepath.Join(elsewhere, "0-e2e-upload-c")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("written through the link: %v", err)
		}
	})
}
