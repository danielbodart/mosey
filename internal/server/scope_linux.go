package server

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// lingerDir is where systemd-logind marks a user whose manager runs from
// boot to shutdown rather than from first login to last logout
// [loginctl(1), enable-linger].
const lingerDir = "/var/lib/systemd/linger"

// scopeProp is one property of a transient unit, as busctl spells it: a
// name, its D-Bus signature, and the values that signature takes.
type scopeProp struct {
	name, sig string
	values    []string
}

// scopeArgs is the busctl call that asks the user's manager for a
// transient scope unit holding pid alone (server.md §6.3, §2.1).
func scopeArgs(unit string, pid int, props []scopeProp) []string {
	args := []string{"--user", "--timeout=2", "call",
		"org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager",
		"StartTransientUnit", "ssa(sv)a(sa(sv))", unit, "fail",
		strconv.Itoa(len(props) + 1),
		"PIDs", "au", "1", strconv.Itoa(pid)}
	for _, p := range props {
		args = append(append(args, p.name, p.sig), p.values...)
	}
	return append(args, "0")
}

// startScope puts pid in a new transient scope with props, in the
// user's systemd manager; busctl, not a D-Bus library (D19). It needs the
// manager, and so XDG_RUNTIME_DIR and busctl; without them it fails, and
// every caller carries on without the scope.
func (s *spawner) startScope(unit string, pid int, props []scopeProp) error {
	if s.getenv("XDG_RUNTIME_DIR") == "" {
		return fmt.Errorf("no XDG_RUNTIME_DIR, so no user manager")
	}
	args := scopeArgs(unit, pid, props)
	run := s.cfg.busctl
	if run == nil {
		run = s.runBusctl
	}
	if out, err := run(args); err != nil {
		return fmt.Errorf("%w: %s", err, SanitizeLogLine(out))
	}
	return nil
}

func (s *spawner) runBusctl(args []string) ([]byte, error) {
	busctl, err := exec.LookPath("busctl")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, busctl, args...)
	s.cfg.Self.Prepare(cmd)
	cmd.Env = s.cfg.Environ
	return cmd.CombinedOutput()
}

// emuScope moves emu into a transient scope with D23's MemoryMax, when
// the user has a manager; best effort, since RLIMIT_DATA is the limit
// every host has (server.md §6.3). It returns the scope's cgroup
// directory, for reading its OOM count.
//
// When the session has a scope of its own, emu's is PartOf it, so
// stopping the session stops emu, and Before it, so that when both stop
// together, as at shutdown, the session's stops first [systemd.unit(5):
// stopping reverses the start order]. The spawner's teardown then ends
// emu by closing its socket, and emu's own scope is never left to stop a
// live emu that the spawner, still running, would take for a death and
// restart.
func (s *spawner) emuScope(pid int, gen uint32) string {
	unit := fmt.Sprintf("mosey-emu-%d-%d.scope", os.Getpid(), gen)
	props := []scopeProp{
		{"MemoryMax", "t", []string{strconv.Itoa(emuMemoryMax)}},
		{"MemorySwapMax", "t", []string{"0"}},
		{"CollectMode", "s", []string{"inactive-or-failed"}},
	}
	if s.sessionScope != "" {
		props = append(props,
			scopeProp{"PartOf", "as", []string{"1", s.sessionScope}},
			scopeProp{"Before", "as", []string{"1", s.sessionScope}})
	}
	if err := s.startScope(unit, pid, props); err != nil {
		if gen == 1 {
			s.log.Info("no memory cgroup for emu; RLIMIT_DATA alone", "err", err)
		}
		return ""
	}
	return cgroupDir(pid)
}

// joinSessionScope moves the spawner into a transient scope of its own,
// mosey-session-PID.scope, before it starts anything, so that proto, emu
// and the shell, and everything the shell runs, start there too
// (server.md §2.1 step 4.2). Then stopping the user's manager, at
// shutdown or logout, sends SIGTERM to the session as a whole, and the
// spawner tears it down (§2.4) instead of being left running, unasked,
// until the SIGKILL: a terminal's unit may well be KillMode=process, as
// GNOME Console's is, so that a window can close while its programs live
// on, and then nothing stops a session started in it.
//
// Only when the manager lives at least as long as where the spawner
// already is: when it is already inside that manager (a terminal on the
// desktop), or when the user lingers, so the manager runs until
// shutdown. An ssh login's spawner without linger is in logind's scope
// for that login, which outlives the login while it holds processes, and
// with it the user's manager; moved into the manager instead, the
// session would die with it seconds after the login ended
// [logind.conf(5), UserStopDelaySec]. With linger, the move also lets a
// detached session outlive the login under KillUserProcesses=yes
// (bootstrap.md §4.5).
func (s *spawner) joinSessionScope() {
	pid := os.Getpid()
	cg, _ := os.ReadFile(s.cfg.selfCgroup)
	if !userManagerOutlives(string(cg), os.Getuid(), s.lingering()) {
		s.log.Info("left in the login's own scope: the user's manager may stop first")
		return
	}
	unit := fmt.Sprintf("mosey-session-%d.scope", pid)
	err := s.startScope(unit, pid, []scopeProp{
		{"CollectMode", "s", []string{"inactive-or-failed"}},
	})
	if err != nil {
		s.log.Info("no scope for the session", "err", err)
		return
	}
	// The call returns once the job is queued; the move is only counted
	// once the kernel shows it, so emu's scope never names a session
	// scope the spawner is not in.
	if cg, _ := os.ReadFile(s.cfg.selfCgroup); !strings.Contains(string(cg), "/"+unit) {
		s.log.Info("asked for a scope for the session, but not moved into it", "unit", unit)
		return
	}
	s.sessionScope = unit
	s.log.Info("the session has its own scope", "unit", unit)
}

// userManagerOutlives says whether user uid's systemd manager lives at
// least as long as the cgroup in cgroupFile (/proc/PID/cgroup's text):
// the user lingers, or the cgroup is already inside the manager.
func userManagerOutlives(cgroupFile string, uid int, lingering bool) bool {
	if lingering {
		return true
	}
	manager := fmt.Sprintf("/user@%d.service/", uid)
	for _, l := range strings.Split(cgroupFile, "\n") {
		if p, ok := strings.CutPrefix(l, "0::"); ok {
			return strings.Contains(p+"/", manager)
		}
	}
	return false
}

// lingering says whether logind keeps this user's manager from boot to
// shutdown. $USER names the user: sshd and a desktop login both set it,
// and a CGO_ENABLED=0 binary cannot ask NSS (§2.5).
func (s *spawner) lingering() bool {
	user := s.getenv("USER")
	if user == "" || strings.ContainsAny(user, "/\x00") || user == "." || user == ".." {
		return false
	}
	_, err := os.Stat(filepath.Join(s.cfg.lingerDir, user))
	return err == nil
}

// cgroupDir is pid's cgroup v2 directory, or "".
func cgroupDir(pid int) string {
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
