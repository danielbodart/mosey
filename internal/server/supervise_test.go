package server

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"
	"unicode/utf8"
)

// The idle clock runs only while the session is detached, an attach stops
// it, and each detach starts it from zero (D8 R4, bootstrap.md §9.3), on
// virtual time.
func TestTheIdleClockRunsOnlyWhileDetachedAndAnAttachStopsIt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newIdleClock(IdleTimeout)
		defer c.attached()
		fired := func() bool {
			synctest.Wait()
			select {
			case <-c.C():
				return true
			default:
				return false
			}
		}
		time.Sleep(2 * IdleTimeout)
		if fired() {
			t.Fatal("fired before the session ever detached")
		}
		c.detached()
		time.Sleep(IdleTimeout - time.Second)
		c.attached()
		time.Sleep(2 * IdleTimeout)
		if fired() {
			t.Fatal("fired for a session whose client came back")
		}
		c.detached()
		time.Sleep(IdleTimeout - time.Second)
		c.attached()
		c.detached()
		time.Sleep(IdleTimeout - time.Second)
		if fired() {
			t.Fatal("a second detach did not start the clock from zero")
		}
		time.Sleep(time.Second)
		if !fired() {
			t.Fatal("did not fire after the whole timeout detached")
		}
	})
}

// emu restarts (server.md §5.2): 50 ms, doubling to 5 s, reset after 60 s
// alive; the eleventh start in 60 s is not made, and the spawner pauses
// for EmuCooldown instead, then starts again with a fresh budget.
func TestRestartsBackOffAndPauseOnceTheBudgetIsSpent(t *testing.T) {
	var r restarts
	now := time.Unix(1_000_000, 0)
	born := now
	r.started(born)
	var waits []time.Duration
	pausedAt := -1
	for i := range 12 {
		// Each emu dies at once.
		wait, pause := r.plan(now, born)
		if pause {
			pausedAt = i
			if wait != EmuCooldown {
				t.Fatalf("paused for %v, want %v", wait, EmuCooldown)
			}
			break
		}
		waits = append(waits, wait)
		now = now.Add(wait)
		born = now
		r.started(born)
	}
	want := []time.Duration{50, 100, 200, 400, 800, 1600, 3200, 5000, 5000}
	if len(waits) != len(want) {
		t.Fatalf("waits %v, want %v ms", waits, want)
	}
	for i := range want {
		if waits[i] != want[i]*time.Millisecond {
			t.Errorf("wait %d is %v, want %v ms", i, waits[i], want[i])
		}
	}
	// 10 starts in under 60 s (the first and 9 restarts summing about 16 s),
	// so the next would be the eleventh.
	if pausedAt != 9 {
		t.Errorf("paused before restart %d, want 9", pausedAt)
	}
	// After the pause: a fresh budget, back to 50 ms.
	now = now.Add(EmuCooldown)
	r.started(now)
	if wait, pause := r.plan(now, now); pause || wait != restartFirst {
		t.Errorf("after the pause: wait %v, pause %v", wait, pause)
	}
}

func TestAnEmuThatLivedAMinuteRestartsAfterTheFirstBackoff(t *testing.T) {
	var r restarts
	now := time.Unix(1_000_000, 0)
	for range 5 {
		r.started(now)
		wait, _ := r.plan(now, now)
		now = now.Add(wait)
	}
	r.started(now)
	born := now
	now = now.Add(restartHealthy)
	if wait, pause := r.plan(now, born); pause || wait != restartFirst {
		t.Errorf("wait %v, pause %v; want %v", wait, pause, restartFirst)
	}
}

func TestOutOfMemoryIsRecognisedOnAnyLineNotJustTheLast(t *testing.T) {
	var log bytes.Buffer
	var stderr strings.Builder
	stderr.WriteString("starting\n")
	stderr.WriteString("fatal error: out of memory\n\n")
	for i := range 200 {
		fmt.Fprintf(&stderr, "goroutine %d [running]:\n", i)
	}
	oom := false
	copyRoleLog(strings.NewReader(stderr.String()), &log, "emu pid=1 gen=1", func(line string) {
		if outOfMemory(line) {
			oom = true
		}
	})
	if !oom {
		t.Error("the out-of-memory line was missed")
	}
	if outOfMemory("panic: runtime error") || !outOfMemory("fatal error: runtime: out of memory") {
		t.Error("outOfMemory misclassifies")
	}
}

// A role's stderr reaches the log one sanitised line at a time under the
// spawner's prefix, so a compromised role can neither write control bytes
// nor pass its lines off as another's (server.md §6.4).
func TestRoleLogLinesAreSanitisedAndPrefixed(t *testing.T) {
	var log bytes.Buffer
	in := "ok\n\x1b[31mred\x1b[0m\r\nproto pid=2 forged\n" + strings.Repeat("a", MaxLogLine+100) + "\nlast"
	copyRoleLog(strings.NewReader(in), &log, "emu pid=1 gen=3", nil)
	lines := strings.Split(strings.TrimSuffix(log.String(), "\n"), "\n")
	want := []string{
		"emu pid=1 gen=3 ok",
		"emu pid=1 gen=3 ?[31mred?[0m?",
		"emu pid=1 gen=3 proto pid=2 forged",
		"emu pid=1 gen=3 " + strings.Repeat("a", MaxLogLine) + " [cut]",
		"emu pid=1 gen=3 last",
	}
	if len(lines) != len(want) {
		t.Fatalf("lines %q", lines)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d is %q, want %q", i, lines[i], want[i])
		}
	}
}

func TestTheSessionLogIsCapped(t *testing.T) {
	var buf bytes.Buffer
	w := &cappedWriter{w: &buf, left: 100}
	for range 10 {
		w.Write([]byte(strings.Repeat("x", 19) + "\n"))
	}
	if buf.Len() > 100 || !strings.HasSuffix(buf.String(), truncatedLine) {
		t.Errorf("log %d bytes: %q", buf.Len(), buf.String())
	}
	if strings.Count(buf.String(), truncatedLine) != 1 {
		t.Error("truncation marked more than once")
	}
}

// FuzzLogLine: the stderr line sanitiser never emits a byte outside
// 0x20-0x7E, nor more than MaxLogLine bytes and its mark.
func FuzzLogLine(f *testing.F) {
	f.Add([]byte("fatal error: out of memory"))
	f.Add([]byte("\x1b]0;evil\x07\r\n\x00\xff"))
	f.Add(bytes.Repeat([]byte("é"), MaxLogLine))
	f.Fuzz(func(t *testing.T, b []byte) {
		s := SanitizeLogLine(b)
		if len(s) > MaxLogLine+len(" [cut]") {
			t.Fatalf("%d bytes", len(s))
		}
		for i := 0; i < len(s); i++ {
			if s[i] < 0x20 || s[i] > 0x7e {
				t.Fatalf("byte %#02x at %d", s[i], i)
			}
		}
		if !utf8.ValidString(s) {
			t.Fatal("not valid UTF-8")
		}
		var log bytes.Buffer
		copyRoleLog(bytes.NewReader(b), &log, "p", nil)
		for _, c := range log.Bytes() {
			if c != '\n' && (c < 0x20 || c > 0x7e) {
				t.Fatalf("log byte %#02x", c)
			}
		}
	})
}

// The shell's environment (server.md §2.5): sshd's, without SSH_TTY and
// sshd's agent, with the emulator's TERM, and the client's locale and
// COLORTERM re-checked here whatever the parser accepted.
func TestTheShellGetsSSHDsEnvironmentWithTheClientsLocale(t *testing.T) {
	base := []string{
		"PATH=/usr/bin:/bin", "HOME=/home/u", "USER=u", "SSH_CONNECTION=1.2.3.4 5 6.7.8.9 22",
		"SSH_TTY=/dev/pts/3", "SSH_AUTH_SOCK=/tmp/ssh-x/agent.1", "TERM=dumb", "LANG=C",
	}
	from := map[string]string{
		"TERM": "alacritty", "COLORTERM": "truecolor", "LANG": "en_GB.UTF-8",
		"LC_ALL": "bad value with spaces", "EVIL": "x",
	}
	env := shellEnv(base, from, "", "", discardLog())
	got := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		if _, dup := got[k]; dup {
			t.Errorf("%s twice", k)
		}
		got[k] = v
	}
	for k, v := range map[string]string{
		"PATH": "/usr/bin:/bin", "HOME": "/home/u", "USER": "u", "SSH_CONNECTION": "1.2.3.4 5 6.7.8.9 22",
		"TERM": shellTERM, "COLORTERM": "truecolor", "LANG": "en_GB.UTF-8",
	} {
		if got[k] != v {
			t.Errorf("%s=%q, want %q", k, got[k], v)
		}
	}
	for _, k := range []string{"SSH_TTY", "SSH_AUTH_SOCK", "LC_ALL", "EVIL"} {
		if _, ok := got[k]; ok {
			t.Errorf("%s is set", k)
		}
	}
}

// The address advertised and bound (server.md §2.2, bootstrap.md §2.2):
// the one SSH reached, bound, unless it is loopback or link-local, which
// are advertised with the wildcard bound; none at all without a usable
// SSH_CONNECTION.
func TestTheAddressComesFromSSHConnection(t *testing.T) {
	for _, c := range []struct {
		conn            string
		advertise, bind string
	}{
		{"10.0.0.1 50000 10.0.0.2 22", "10.0.0.2", "10.0.0.2"},
		{"2001:db8::1 50000 2001:db8::2 22", "2001:db8::2", "2001:db8::2"},
		{"::ffff:10.0.0.1 50000 ::ffff:10.0.0.2 22", "10.0.0.2", "10.0.0.2"},
		{"127.0.0.1 50000 127.0.0.1 22", "127.0.0.1", ""},
		{"fe80::1%eth0 50000 fe80::2%eth0 22", "fe80::2", ""},
		{"", "", ""},
		{"10.0.0.1 50000 10.0.0.2", "", ""},
		{"10.0.0.1 50000 not-an-address 22", "", ""},
		{"10.0.0.1 50000 0.0.0.0 22", "", ""},
		{"10.0.0.1 50000 224.0.0.1 22", "", ""},
	} {
		adv, bind := addresses(c.conn)
		if s(adv) != c.advertise || s(bind) != c.bind {
			t.Errorf("addresses(%q) = %v, %v; want %q, %q", c.conn, adv, bind, c.advertise, c.bind)
		}
	}
}

func s(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

// With the agent forwarded, the shell's SSH_AUTH_SOCK is mosey's own
// socket, never sshd's, which dies with the bootstrap login (server.md
// §2.5, §2.7).
func TestTheShellsAgentIsMoseysSocketWhenTheAgentIsForwarded(t *testing.T) {
	base := []string{"PATH=/bin", "SSH_AUTH_SOCK=/tmp/ssh-x/agent.1"}
	env := shellEnv(base, nil, "/run/user/1/mosey/abc/agent.sock", "", discardLog())
	var socks []string
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "SSH_AUTH_SOCK="); ok {
			socks = append(socks, v)
		}
	}
	if len(socks) != 1 || socks[0] != "/run/user/1/mosey/abc/agent.sock" {
		t.Errorf("SSH_AUTH_SOCK %q", socks)
	}
}

// A session served from D7's cached copy, on a host with no mosey on
// PATH, gets ~/.cache/mosey first on its shell's PATH, so `mosey
// otherhost` in it finds the copy (bootstrap.md §4.7.9, server.md §2.5);
// any other server, or a PATH with a mosey of its own, leaves PATH alone.
func TestTheCachedCopyGoesFirstOnTheShellsPathOnlyWhenNeeded(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".cache", "mosey")
	cached := filepath.Join(dir, "mosey")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cached, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	elsewhere := filepath.Join(t.TempDir(), "mosey")
	if err := os.WriteFile(elsewhere, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	bare, withMosey := t.TempDir(), filepath.Dir(elsewhere)
	env := func(path string) []string { return []string{"HOME=" + home, "PATH=" + path} }

	if got := hopDir(env(bare+":/nonexistent"), cached); got != dir {
		t.Errorf("the cached copy on a bare PATH: %q, want %q", got, dir)
	}
	if got := hopDir(env(withMosey+":"+bare), cached); got != "" {
		t.Errorf("a PATH with a mosey of its own: %q", got)
	}
	if got := hopDir(env(bare), elsewhere); got != "" {
		t.Errorf("a server that is not the cached copy: %q", got)
	}
	if got := hopDir([]string{"PATH=" + bare}, cached); got != "" {
		t.Errorf("no HOME: %q", got)
	}

	for _, c := range []struct {
		base []string
		want string
	}{
		{[]string{"PATH=/usr/bin:/bin", "HOME=" + home}, dir + ":/usr/bin:/bin"},
		{[]string{"PATH=/old", "PATH=/usr/bin", "HOME=" + home}, dir + ":/usr/bin"},
		{[]string{"HOME=" + home}, dir},
	} {
		var paths []string
		for _, kv := range shellEnv(c.base, nil, "", dir, discardLog()) {
			if p, ok := strings.CutPrefix(kv, "PATH="); ok {
				paths = append(paths, p)
			}
		}
		if len(paths) != 1 || paths[0] != c.want {
			t.Errorf("%q: PATH %q, want %q", c.base, paths, c.want)
		}
	}
}
