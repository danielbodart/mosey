package server

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestEmuScopeIsTheCallServerMdGives: the busctl arguments are exactly
// §6.3's, so the spec's line can be pasted into a shell to try it.
func TestEmuScopeIsTheCallServerMdGives(t *testing.T) {
	got := strings.Join(scopeArgs("mosey-emu-7-1.scope", 9, []scopeProp{
		{"MemoryMax", "t", []string{"536870912"}},
		{"MemorySwapMax", "t", []string{"0"}},
		{"CollectMode", "s", []string{"inactive-or-failed"}},
	}), " ")
	want := "--user --timeout=2 call org.freedesktop.systemd1 /org/freedesktop/systemd1 " +
		"org.freedesktop.systemd1.Manager StartTransientUnit ssa(sv)a(sa(sv)) mosey-emu-7-1.scope fail 4 " +
		"PIDs au 1 9 MemoryMax t 536870912 MemorySwapMax t 0 CollectMode s inactive-or-failed 0"
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestTheUserManagerOutlivesOnlyWhatItAlreadyHoldsUnlessTheUserLingers(t *testing.T) {
	const console = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-dbus\\x2d:1.1\\x2dorg.gnome.Console.slice/dbus-:1.1-org.gnome.Console@0.service\n"
	const sshLogin = "0::/user.slice/user-1000.slice/session-4.scope\n"
	for _, c := range []struct {
		name      string
		cgroup    string
		uid       int
		lingering bool
		want      bool
	}{
		{"a desktop terminal, inside the manager", console, 1000, false, true},
		{"an ssh login", sshLogin, 1000, false, false},
		{"an ssh login of a lingering user", sshLogin, 1000, true, true},
		{"another uid's manager", console, 1001, false, false},
		{"the manager's own cgroup, no trailing slash", "0::/user.slice/user-1000.slice/user@1000.service\n", 1000, false, true},
		{"cgroup v1 lines only", "12:pids:/user.slice\n", 1000, false, false},
		{"no cgroup file", "", 1000, false, false},
	} {
		if got := userManagerOutlives(c.cgroup, c.uid, c.lingering); got != c.want {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
}

func TestLingeringIsLogindsMarkForUSER(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "dan"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for user, want := range map[string]bool{"dan": true, "ann": false, "": false, "..": false, "../linger/dan": false} {
		s := &spawner{cfg: SpawnerConfig{Environ: []string{"USER=" + user}, lingerDir: dir}}
		if got := s.lingering(); got != want {
			t.Errorf("USER=%q: got %v", user, got)
		}
	}
}

// TestEmuStopsAfterTheSessionsScope (§6.3): with a session scope, emu's
// is part of it and ordered before it, so a shutdown stops the spawner
// first and emu after; without one, emu's call is §6.3's alone.
func TestEmuStopsAfterTheSessionsScope(t *testing.T) {
	var calls [][]string
	s := &spawner{log: discardLog(), cfg: SpawnerConfig{
		Environ: []string{"XDG_RUNTIME_DIR=/run/user/1000"},
		busctl: func(args []string) ([]byte, error) {
			calls = append(calls, args)
			return nil, nil
		},
	}}
	s.emuScope(os.Getpid(), 1)
	s.sessionScope = "mosey-session-7.scope"
	s.emuScope(os.Getpid(), 2)
	if len(calls) != 2 {
		t.Fatalf("%d busctl calls", len(calls))
	}
	alone, inSession := strings.Join(calls[0], " "), strings.Join(calls[1], " ")
	if strings.Contains(alone, "PartOf") || strings.Contains(alone, "Before") || !strings.Contains(alone, " fail 4 ") {
		t.Errorf("without a session scope: %s", alone)
	}
	for _, want := range []string{" fail 6 ", "PartOf as 1 mosey-session-7.scope", "Before as 1 mosey-session-7.scope"} {
		if !strings.Contains(inSession, want) {
			t.Errorf("with a session scope, no %q in %s", want, inSession)
		}
	}
}

// TestASessionScopeIsBestEffort: no user manager, or busctl failing,
// leaves the session where it is, and nothing is asked of a manager the
// spawner would not outlive.
func TestASessionScopeIsBestEffort(t *testing.T) {
	asked := 0
	fail := func(args []string) ([]byte, error) {
		asked++
		if !slices.Contains(args, "mosey-session-"+strconv.Itoa(os.Getpid())+".scope") {
			t.Errorf("asked for %v", args)
		}
		return []byte("Access denied"), errors.New("exit status 1")
	}
	lingering := t.TempDir()
	os.WriteFile(filepath.Join(lingering, "dan"), nil, 0o644)

	for _, c := range []struct {
		name    string
		environ []string
		asks    int
	}{
		{"no XDG_RUNTIME_DIR", []string{"USER=dan"}, 0},
		{"busctl fails", []string{"USER=dan", "XDG_RUNTIME_DIR=/run/user/1000"}, 1},
	} {
		asked = 0
		s := &spawner{log: discardLog(), cfg: SpawnerConfig{Environ: c.environ, busctl: fail, lingerDir: lingering}}
		s.joinSessionScope()
		if s.sessionScope != "" || asked != c.asks {
			t.Errorf("%s: scope %q after %d calls", c.name, s.sessionScope, asked)
		}
	}

	sshLogin := filepath.Join(t.TempDir(), "cgroup")
	os.WriteFile(sshLogin, []byte("0::/user.slice/user-1000.slice/session-4.scope\n"), 0o644)
	s := &spawner{log: discardLog(), cfg: SpawnerConfig{
		Environ: []string{"USER=nobody-lingers", "XDG_RUNTIME_DIR=/run/user/1000"},
		busctl: func([]string) ([]byte, error) {
			t.Error("asked a manager that may stop before the session")
			return nil, nil
		},
		lingerDir:  t.TempDir(),
		selfCgroup: sshLogin,
	}}
	s.joinSessionScope()
	if s.sessionScope != "" {
		t.Errorf("an ssh login without linger got %q", s.sessionScope)
	}
}
