package server

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/danielbodart/mosey/internal/pty"
)

// passwdFile is where the shell and home are looked up when $SHELL or
// $HOME will not do (server.md §2.5).
const passwdFile = "/etc/passwd"

// shellAndHome is the login shell and the home directory a session's
// shell starts with (server.md §2.5): $SHELL and $HOME first, else the
// passwd file's, as getenv and the file at passwd give them.
func shellAndHome(getenv func(string) string, passwd string) (shell, home string) {
	f, _ := os.Open(passwd)
	if f != nil {
		defer f.Close()
	}
	return pty.LoginShell(getenv, f, os.Getuid())
}

// startDir is where a new session's shell starts (bootstrap.md §9.2.3):
// the home directory if the ClientLine has no dir; dir itself if it is
// absolute; else dir joined to home. It must be a directory, symlinks
// followed, so a -dir that is missing is refused before anything starts.
func startDir(home, dir string) (string, error) {
	if dir == "" {
		return home, nil
	}
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(home, dir)
	}
	info, err := os.Stat(dir)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", dir)
	}
	return dir, nil
}
