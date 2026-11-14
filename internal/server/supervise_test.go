package server

import (
	"bytes"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

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
	env := shellEnv(base, from, discardLog())
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
