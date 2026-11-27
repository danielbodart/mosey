//go:build linux || darwin

package server

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func logPath(state string) string {
	logs, _ := filepath.Glob(filepath.Join(state, "mosey", "serve-*.log"))
	if len(logs) == 0 {
		return ""
	}
	return logs[0]
}

func sessionLog(state string) string {
	b, _ := os.ReadFile(logPath(state))
	return string(b)
}

// waitForLog returns the log at path once done says it has what the test
// waits for. It waits for each write (inotify on Linux, kqueue on macOS),
// never on the clock, so a slow machine only makes it slower (Dan,
// 2026-11-18); a session that never writes the line is caught by go
// test's own -timeout.
func waitForLog(t *testing.T, path string, done func(string) bool) string {
	t.Helper()
	if path == "" {
		t.Fatal("no session log")
	}
	// Watched before the first read, so no write between them is missed.
	w := watchFile(t, path)
	defer w.close()
	for {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading the log: %v", err)
		}
		if done(string(b)) {
			return string(b)
		}
		w.wait(t)
	}
}

var spawnerPid = regexp.MustCompile(`role=spawner pid=(\d+)`)

// killSpawner ends a session a test left running: its spawner's pid is in
// its log, and its roles die with it (Pdeathsig, EOF).
func killSpawner(t *testing.T, state string) {
	m := spawnerPid.FindStringSubmatch(sessionLog(state))
	if m == nil {
		return
	}
	pid, _ := strconv.Atoi(m[1])
	if syscall.Kill(pid, 0) == nil {
		syscall.Kill(pid, syscall.SIGTERM)
		for range 100 {
			if syscall.Kill(pid, 0) != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		syscall.Kill(pid, syscall.SIGKILL)
	}
}
