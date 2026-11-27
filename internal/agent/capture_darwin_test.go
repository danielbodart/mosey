package agent

import (
	"os"
	"strconv"
	"testing"
)

// TestTheCaptureDirectoryOnMacOSIsAlwaysUnderTmp: as the server's
// sessions directory is there, so a socket path fits in sun_path
// (server.md §10).
func TestTheCaptureDirectoryOnMacOSIsAlwaysUnderTmp(t *testing.T) {
	env := map[string]string{"XDG_RUNTIME_DIR": "/run/user/501", "TMPDIR": "/var/folders/ab/cdefgh/T/"}
	want := "/tmp/mosey-" + strconv.Itoa(os.Getuid())
	if got := CaptureDir(func(k string) string { return env[k] }); got != want {
		t.Errorf("CaptureDir is %s, not %s", got, want)
	}
}
