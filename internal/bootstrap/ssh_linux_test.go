package bootstrap

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// R3's batch ssh runs in a session of its own, so neither it nor anything
// it starts (a ProxyCommand, a ProxyJump's inner ssh) has the user's
// terminal to ask on while the screen is up, and askpass is off too
// (§9.2.2). The stand-in reports its session id, read from /proc, and its
// SSH_ASKPASS_REQUIRE.
func TestABatchSSHHasNoTerminalOfTheUsersToAskOn(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	prog := filepath.Join(dir, "ssh")
	script := "#!/bin/sh\nread -r stat < /proc/$$/stat\nset -- $stat\nprintf '%s %s\\n' \"$6\" \"${SSH_ASKPASS_REQUIRE:--}\" > '" + out + "'\n"
	if err := os.WriteFile(prog, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	ours, err := unix.Getsid(0)
	if err != nil {
		t.Fatal(err)
	}
	for _, batch := range []bool{false, true} {
		cmd := SSH{Program: prog, Destination: "far", Server: "mosey", Batch: batch}.Command(t.Context(), Config{})
		if err := cmd.Run(); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		sid, askpass, _ := strings.Cut(strings.TrimSpace(string(b)), " ")
		own := sid != strconv.Itoa(ours)
		if own != batch || (askpass == "never") != batch {
			t.Errorf("batch %v: session %s (the test's is %d), SSH_ASKPASS_REQUIRE %s", batch, sid, ours, askpass)
		}
	}
}
