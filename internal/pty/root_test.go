package pty

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// status is a status file as Linux writes it, with the uids put in: the
// Uid line is the real, effective, saved and filesystem uid (proc(5)).
func status(uids string) string {
	return "Name:\tsudo\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t4242\nPid:\t4242\nPPid:\t100\n" +
		"Uid:\t" + uids + "\nGid:\t100\t100\t100\t100\nGroups:\t100\n"
}

// fakeProc is a /proc with one process, pid, whose status file is body.
func fakeProc(t *testing.T, pid int, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, strconv.Itoa(pid)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, strconv.Itoa(pid), "status"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// Root is the effective uid: sudo is set-uid root, so while it runs its
// real uid is the user's and its effective uid 0, and that counts; a
// process that dropped to the user, with only a saved uid of 0, does not.
func TestRootIsTheForegroundLeadersEffectiveUID(t *testing.T) {
	for _, c := range []struct {
		uids string
		root bool
	}{
		{"0\t0\t0\t0", true},
		{"1000\t0\t0\t0", true},
		{"0\t1000\t0\t1000", false},
		{"1000\t1000\t1000\t1000", false},
		{"1000\t1000\t0\t1000", false},
	} {
		if got := rootIn(fakeProc(t, 4242, status(c.uids)), 4242); got != c.root {
			t.Errorf("Uid %q: root %v, want %v", c.uids, got, c.root)
		}
	}
}

// What cannot be read is not root: a leader that has gone, a status file
// with no Uid line, a short or garbled one, or one whose Uid line lies
// past the bound on the read. An unknown is never shown as root.
func TestAnUnreadableLeaderIsNotRoot(t *testing.T) {
	if rootIn(t.TempDir(), 4242) {
		t.Error("a missing process is root")
	}
	for name, body := range map[string]string{
		"no Uid line":    "Name:\tsh\nGid:\t0\t0\t0\t0\n",
		"short":          "Uid:\t0\n",
		"too long":       "Uid:\t0\t0\t0\t0\t0\n",
		"not decimal":    "Uid:\tx\t-0\t0\t0\n",
		"negative":       "Uid:\t1\t-1\t0\t0\n",
		"past the bound": strings.Repeat("x", maxStatus) + "\nUid:\t0\t0\t0\t0\n",
		"empty":          "",
	} {
		if rootIn(fakeProc(t, 4242, body), 4242) {
			t.Errorf("%s: root", name)
		}
	}
}
