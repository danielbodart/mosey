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
	"time"

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
			return
		default:
		}
		if t.Failed() {
			t.Logf("the client's screen:\n%q\nits log:\n%s", c.screen.String(), readFile(filepath.Join(state, "mosey", "client.log")))
		}
		// SIGTERM detaches a running client (bootstrap.md §9.3); one
		// stuck before its screen is up is killed.
		c.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-c.exited:
		case <-time.After(10 * time.Second):
			c.cmd.Process.Kill()
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

// up waits for the session's screen and the far shell's answer to a sum.
func (c *clientRun) up(t *testing.T) {
	t.Helper()
	waitFor(t, "the session's screen", func() bool { return strings.Contains(c.screen.String(), "\x1b[22;2t\x1b[?7l") })
	c.answers(t, "echo copied-$((6*7))", "copied-42")
}

// answers types line into the far shell and waits for want on the screen.
func (c *clientRun) answers(t *testing.T, line, want string) {
	t.Helper()
	if _, err := c.master.Write([]byte(line + "\r")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the shell's answer "+want, func() bool {
		return strings.Contains(screenOf([]byte(c.screen.String()), 100, 30), want)
	})
}

// session checks a whole session works: the far shell answers, and exiting
// it ends the client with status 0.
func (c *clientRun) session(t *testing.T, state string) {
	t.Helper()
	c.up(t)
	c.end(t, state)
}

// end exits the far shell and checks the client exits 0.
func (c *clientRun) end(t *testing.T, state string) {
	t.Helper()
	c.master.Write([]byte("exit\r"))
	if status := c.wait(t); status != 0 {
		t.Fatalf("mosey exited %d; log:\n%s", status, readFile(filepath.Join(state, "mosey", "client.log")))
	}
}

// cached is D7's one file on the far host (bootstrap.md §4.7).
func (s *sshd) cached() string {
	return filepath.Join(s.home, ".cache", "mosey", "mosey")
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

// tools is a directory of links to just the commands the probe and the
// upload script run, to be a far host's whole PATH: whatever the machine
// running the test has installed, that host has no mosey on PATH unless
// a test puts one there.
func tools(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, tool := range []string{"uname", "mkdir", "mktemp", "cat", "chmod", "rm", "ls"} {
		path, err := exec.LookPath(tool)
		if err != nil {
			t.Skipf("no %s", tool)
		}
		if err := os.Symlink(path, filepath.Join(dir, tool)); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// farPath is the PATH the far host's /bin/sh sees under this sshd: the
// test's SetEnv PATH, unless the login shell's rc files set it afresh, as
// NixOS's bash does even for ssh's commands.
func farPath(t *testing.T, s *sshd) []string {
	t.Helper()
	out, err := exec.Command("ssh", "-F", s.config, s.host, `exec /bin/sh -c 'printf %s "$PATH"'`).Output()
	if err != nil {
		t.Fatalf("asking the far host its PATH: %v", err)
	}
	return filepath.SplitList(string(out))
}

// noMoseyOnFarPath skips a test that needs a far host with no mosey on its
// PATH when the machine running it has one there that the test cannot
// hide.
func noMoseyOnFarPath(t *testing.T, s *sshd) {
	t.Helper()
	if exec.Command("ssh", "-F", s.config, s.host, `exec /bin/sh -c 'command -v mosey'`).Run() == nil {
		t.Skip("the far host's PATH has a mosey of this machine's that the test cannot hide")
	}
}

// farPathDir is a directory on the far host's PATH that the test owns:
// bin, which SetEnv put there, or one under the throwaway HOME, as a
// login shell's rc files may name (~/.nix-profile/bin on NixOS). It is
// made if missing; with none, the test is skipped.
func farPathDir(t *testing.T, s *sshd, bin string) string {
	t.Helper()
	for _, dir := range farPath(t, s) {
		if dir == bin || strings.HasPrefix(dir, s.home+"/") {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			return dir
		}
	}
	t.Skip("no directory on the far host's PATH is the test's to write")
	return ""
}

// plainShell is a session shell that keeps the PATH it is given: an
// interactive /bin/sh, which reads no profile. So hopping is proven here
// only for a shell whose profile does not reset PATH. A bash login shell
// on Debian or NixOS, whose profile assigns PATH outright, loses what the
// spawner put there by the first prompt, and `mosey otherhost` is not
// found: a known limitation, open for Dan (bootstrap.md §4.7.9, §14
// question G), which this test does not hide.
func plainShell(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "plainsh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexec /bin/sh -i\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// replaceWith puts content at path by a rename, as an upgrade would: the
// last session's processes may still be running from the file it replaces.
func replaceWith(t *testing.T, path string, content []byte) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, content, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// D7 end to end through a real sshd (bootstrap.md §4.7, §12), on a host
// whose PATH has no mosey: it asks, copies the client's own file to
// ~/.cache/mosey/mosey, and the session runs from it and can hop on with
// it; a client of another version then uses that copy as it is; a cached
// copy of another protocol is replaced; -list finds it, and -list and
// -kill copy nothing; and a symlinked cached file or cache directory is
// refused with nothing written through it. The remote HOME is the
// throwaway sshd's, never the user's.
func TestAutoUploadThroughSSH(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	s := startSSHDWith(t, sshdOptions{path: tools(t), shell: plainShell(t)})
	noMoseyOnFarPath(t, s)
	a := buildMosey(t, "0-e2e-upload-a")
	b := buildMosey(t, "0-e2e-upload-b")
	// The far side's processes run from the cache, not from the build:
	// end them too when the test is done.
	t.Cleanup(func() { killExe(s.cached()) })
	state := t.TempDir()

	t.Run("a host with no mosey asks, copies, and the session hops on from the copy", func(t *testing.T) {
		c := startUploadClient(t, s, a, state)
		waitFor(t, "the question", func() bool { return strings.Contains(c.screen.String(), "[y/N]") })
		if !strings.Contains(c.screen.String(), "mosey-e2e has no mosey this one can use. Copy this one (linux/") {
			t.Errorf("asked %q", c.screen.String())
		}
		c.master.Write([]byte("y\r"))
		c.up(t)
		// D7: the session's shell finds the copy first on its PATH, so
		// `mosey otherhost` works in it (bootstrap.md §4.7.9), for a shell
		// whose profile does not reset PATH (plainShell; §14 question G).
		c.answers(t, `[ "$(command -v mosey)" = "$HOME/.cache/mosey/mosey" ] && echo hop-$((40+2))`, "hop-42")
		c.end(t, state)
		if !sameFile(t, s.cached(), a) {
			t.Fatal("the cache does not hold the client's own file")
		}
		if st, err := os.Stat(s.cached()); err != nil || st.Mode().Perm() != 0o700 {
			t.Errorf("the copy's mode: %v %v", st.Mode(), err)
		}
		if entries, _ := os.ReadDir(filepath.Dir(s.cached())); len(entries) != 1 {
			t.Errorf("~/.cache/mosey holds %v, not the one file", entries)
		}
	})

	t.Run("a client of another version uses the copy as it is", func(t *testing.T) {
		c := startUploadClient(t, s, b, state)
		c.session(t, state)
		if out := c.screen.String(); strings.Contains(out, "[y/N]") || strings.Contains(out, "copying mosey") {
			t.Errorf("copied again: %q", out)
		}
		if !sameFile(t, s.cached(), a) {
			t.Error("the copy of another version was replaced")
		}
	})

	t.Run("-list finds the copy", func(t *testing.T) {
		// Nothing on the remote PATH: only the probe's look in
		// ~/.cache/mosey finds a lister (bootstrap.md §9.4). The last
		// session may still be on its way out, so it may be listed.
		cmd := exec.Command(b, "-list", "--", "-F", s.config, s.host)
		cmd.Env = append(os.Environ(), "XDG_STATE_HOME="+state)
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "no sessions") && !strings.HasPrefix(string(out), "NAME ") {
			t.Errorf("mosey -list: %v\n%q", err, out)
		}
	})

	t.Run("a cached copy of another protocol is replaced", func(t *testing.T) {
		// A copy left by a client of another protocol: the probe asks it,
		// hears another answer, and b is copied over it. The host is
		// remembered, so nothing is asked.
		replaceWith(t, s.cached(), []byte("#!/bin/sh\n[ \"$1\" = --serve=protocol ] && echo 9 9\nexit 1\n"))
		c := startUploadClient(t, s, b, state)
		c.session(t, state)
		if !sameFile(t, s.cached(), b) {
			t.Error("the copy of another protocol was kept")
		}
		if strings.Contains(c.screen.String(), "[y/N]") {
			t.Error("asked again for a remembered host")
		}
	})

	t.Run("-list and -kill copy nothing to a host without mosey", func(t *testing.T) {
		if err := os.RemoveAll(filepath.Dir(s.cached())); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(b, "-list", "--", "-F", s.config, s.host)
		cmd.Env = append(os.Environ(), "XDG_STATE_HOME="+state)
		out, err := cmd.CombinedOutput()
		if bootstrap.ExitStatus(err) == 0 || !strings.Contains(string(out), "no mosey on mosey-e2e") {
			t.Errorf("mosey -list: %v\n%q", err, out)
		}
		c := startUploadClient(t, s, b, state, "-kill", "work", "-upload=yes")
		if status := c.wait(t); status != 1 {
			t.Errorf("mosey -kill exited %d", status)
		}
		if !strings.Contains(c.screen.String(), "no mosey on mosey-e2e") {
			t.Errorf("mosey -kill said %q", c.screen.String())
		}
		if _, err := os.Lstat(filepath.Dir(s.cached())); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("something was copied: %v", err)
		}
	})

	t.Run("a symlinked cached file is refused", func(t *testing.T) {
		if err := os.MkdirAll(filepath.Dir(s.cached()), 0o700); err != nil {
			t.Fatal(err)
		}
		victim := filepath.Join(t.TempDir(), "victim")
		if err := os.WriteFile(victim, []byte("precious"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(victim, s.cached()); err != nil {
			t.Fatal(err)
		}
		c := startUploadClient(t, s, b, state, "-upload=yes")
		if status := c.wait(t); status != 1 {
			t.Errorf("exit %d", status)
		}
		out := c.screen.String()
		if !strings.Contains(out, "~/.cache/mosey/mosey is a symbolic link: not replacing it") || !strings.Contains(out, "copying mosey to mosey-e2e failed") {
			t.Errorf("said %q", out)
		}
		if got, _ := os.ReadFile(victim); string(got) != "precious" {
			t.Errorf("written through the link: %q", got)
		}
		if l, err := os.Readlink(s.cached()); err != nil || l != victim {
			t.Errorf("the link was replaced: %q %v", l, err)
		}
		os.Remove(s.cached())
	})

	t.Run("a symlinked cache is refused", func(t *testing.T) {
		cache := filepath.Dir(s.cached())
		elsewhere := filepath.Join(t.TempDir(), "mosey")
		if err := os.Rename(cache, elsewhere); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(elsewhere, cache); err != nil {
			t.Fatal(err)
		}
		c := startUploadClient(t, s, b, state, "-upload=yes")
		if status := c.wait(t); status != 1 {
			t.Errorf("exit %d", status)
		}
		out := c.screen.String()
		if !strings.Contains(out, "~/.cache/mosey is a symbolic link") || !strings.Contains(out, "copying mosey to mosey-e2e failed") {
			t.Errorf("said %q", out)
		}
		if _, err := os.Lstat(filepath.Join(elsewhere, "mosey")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("written through the link: %v", err)
		}
	})
}

// spawnerOf says whether a process of this user runs path as a session's
// spawner. It goes by argv, as killExe does: a spawner is not dumpable.
func spawnerOf(path string) bool {
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		argv, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err == nil && bytes.Equal(argv, []byte(path+"\x00--serve=spawner\x00")) {
			return true
		}
	}
	return false
}

// Whatever mosey the host has on its PATH is used as it is (Dan,
// 2026-11-15; bootstrap.md §4.7.2): a build of another version serves the
// session and nothing is copied; one of another protocol fails with one
// line naming both numbers, and nothing is copied either.
func TestAMoseyOnThePathIsUsedAsItIs(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	bin := t.TempDir()
	s := startSSHDWith(t, sshdOptions{path: bin + ":" + tools(t)})
	noMoseyOnFarPath(t, s)
	client := buildMosey(t, "0-e2e-path-new")
	older := buildMosey(t, "0-e2e-path-old")
	onPath := filepath.Join(farPathDir(t, s, bin), "mosey")
	t.Cleanup(func() { killExe(onPath) })
	state := t.TempDir()

	t.Run("a build of another version on PATH serves the session", func(t *testing.T) {
		data, err := os.ReadFile(older)
		if err != nil {
			t.Fatal(err)
		}
		replaceWith(t, onPath, data)
		c := startUploadClient(t, s, client, state)
		c.up(t)
		if !spawnerOf(onPath) {
			t.Error("the session's spawner is not the mosey on PATH")
		}
		c.end(t, state)
		if out := c.screen.String(); strings.Contains(out, "[y/N]") || strings.Contains(out, "copying mosey") {
			t.Errorf("asked or copied: %q", out)
		}
		if _, err := os.Lstat(filepath.Join(s.home, ".cache", "mosey")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("something was copied: %v", err)
		}
	})

	t.Run("a mosey on PATH of another protocol fails with both numbers", func(t *testing.T) {
		// What any later build must answer to a line it cannot read: the
		// ErrorLine's grammar is frozen (bootstrap.md §6.4).
		replaceWith(t, onPath, []byte("#!/bin/sh\ncat >/dev/null\necho 'MOSEY-ERROR 3 version -'\nexit 1\n"))
		c := startUploadClient(t, s, client, state, "-upload=yes")
		if status := c.wait(t); status != 1 {
			t.Errorf("exit %d", status)
		}
		if out := c.screen.String(); !strings.Contains(out, "mosey-e2e's mosey speaks protocol 3; this mosey speaks 2") {
			t.Errorf("said %q", out)
		}
		if _, err := os.Lstat(filepath.Join(s.home, ".cache", "mosey")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("something was copied: %v", err)
		}
	})
}
