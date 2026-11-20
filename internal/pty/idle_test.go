package pty

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseStatSession(t *testing.T) {
	for _, c := range []struct {
		name string
		stat string
		sid  int
		ok   bool
	}{
		{"normal", "1234 (bash) S 1233 1234 1234 34816 1234 4194304\n", 1234, true},
		{"comm with spaces", "5678 (my background job) S 1234 5678 1234 34816\n", 1234, true},
		{"comm with parens", "5678 (weird ) (app) name) T 1234 5678 1234 0\n", 1234, true},
		{"comm with only parens", "99 ())) S 1 2 42\n", 42, true},
		{"missing close paren", "1234 (bash S 1 2 3\n", 0, false},
		{"too few fields", "1234 (bash) S 1 2\n", 0, false},
		{"non-numeric sid", "1234 (bash) S 1 2 nope\n", 0, false},
		{"empty", "", 0, false},
	} {
		sid, ok := parseStatSession([]byte(c.stat))
		if ok != c.ok || sid != c.sid {
			t.Errorf("%s: got (%d, %v), want (%d, %v)", c.name, sid, ok, c.sid, c.ok)
		}
	}
}

func TestHasOtherSessionMember(t *testing.T) {
	writeStat := func(proc, pid, content string) {
		t.Helper()
		dir := filepath.Join(proc, pid)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// Only the shell itself and processes in other sessions: idle.
	proc := t.TempDir()
	writeStat(proc, "100", "100 (bash) S 99 100 100 0\n")
	writeStat(proc, "200", "200 (other) S 1 200 200 0\n")
	if err := os.WriteFile(filepath.Join(proc, "uptime"), []byte("123.45 67.89\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	other, err := hasOtherSessionMember(proc, 100)
	if err != nil || other {
		t.Fatalf("only shell in session: got (%v, %v), want (false, nil)", other, err)
	}

	// A background job with spaces and ')' in comm shares sid 100: busy.
	writeStat(proc, "101", "101 (sleep ) 100) S 100 101 100 0\n")
	other, err = hasOtherSessionMember(proc, 100)
	if err != nil || !other {
		t.Fatalf("background job in session: got (%v, %v), want (true, nil)", other, err)
	}

	// Missing /proc directory fails safe with an error.
	if _, err := hasOtherSessionMember(filepath.Join(proc, "nonexistent"), 100); err == nil {
		t.Errorf("missing proc dir: want error, got nil")
	}
}
