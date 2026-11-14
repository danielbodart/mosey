package server

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// The attach socket (server.md §2.6): where a session's spawner listens for
// a resume (D8), and how a launcher or a lister finds it. Only processes of
// the user can reach it: it lives in a 0700 directory of theirs, checked
// by both sides, and the spawner checks the peer's uid as well.
const (
	// attachName is the socket's name in its session's directory.
	attachName = "attach.sock"
	// MaxAttachConns is how many attach-socket connections a spawner
	// serves at once: a resume takes milliseconds, so more are closed
	// unanswered [choice].
	MaxAttachConns = 4
	// GreetingTimeout bounds how long a launcher or lister waits for a
	// session's greeting: the spawner answers at once, so a hung one is
	// skipped rather than waited on [choice] (bootstrap.md §11).
	GreetingTimeout = 2 * time.Second
)

// sessionsDir is R/mosey (server.md §2.6): under $XDG_RUNTIME_DIR when it
// is set and absolute, else under the temporary directory with the uid in
// its name, so users of a shared /tmp do not collide.
func sessionsDir(getenv func(string) string) string {
	if r := getenv("XDG_RUNTIME_DIR"); filepath.IsAbs(r) {
		return filepath.Join(r, "mosey")
	}
	tmp := getenv("TMPDIR")
	if !filepath.IsAbs(tmp) {
		tmp = "/tmp"
	}
	return filepath.Join(tmp, "mosey-"+strconv.Itoa(os.Getuid()))
}

// sessionDir is a session's directory under base, named by its id in hex.
func sessionDir(base string, sid [16]byte) string {
	return filepath.Join(base, fmt.Sprintf("%x", sid))
}

// isSessionDirName says whether name could be a session's directory: 32
// lower-case hex digits, as sessionDir writes them.
func isSessionDirName(name string) bool {
	if len(name) != 32 {
		return false
	}
	for i := 0; i < len(name); i++ {
		if c := name[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// errNotPrivate is a directory that is not one only the user can use.
var errNotPrivate = errors.New("not a private directory of this user")

// checkPrivateDir says whether path is a directory, not a symlink, owned
// by this user with no group or other permission bits: one no other user
// can have put a socket in, or swapped for a link to theirs.
func checkPrivateDir(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.IsDir(), fi.Mode()&os.ModeSymlink != 0:
		return fmt.Errorf("%s: %w (not a directory)", path, errNotPrivate)
	case !ok || int(st.Uid) != os.Getuid():
		return fmt.Errorf("%s: %w (owned by someone else)", path, errNotPrivate)
	case fi.Mode().Perm()&0o077 != 0:
		return fmt.Errorf("%s: %w (mode %#o)", path, errNotPrivate, fi.Mode().Perm())
	}
	return nil
}

// makePrivateDir makes path with mode 0700 unless it exists, and checks it
// either way.
func makePrivateDir(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return checkPrivateDir(path)
}
