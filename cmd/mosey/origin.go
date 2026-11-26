package main

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/danielbodart/mosey/internal/bootstrap"
)

// origin is where the terminal started this client: what decides the
// implicit directory, and with MOSEY_FROM the host, of a session it
// creates (bootstrap.md §9.2.4). It is read once, in runClient, so that
// parseArgs stays a pure function of it.
type origin struct {
	// wd is the client's working directory, "" if it cannot be had or
	// could not be sent as a dir.
	wd string
	// from is MOSEY_FROM, already removed from the environment, and
	// leader whether this process leads its session, as a command a
	// terminal starts does. hostname is this machine's name.
	from     string
	leader   bool
	hostname string
}

// currentOrigin reads this process's origin, and removes MOSEY_FROM from
// its environment first of all, so that no session's shell, no ssh and no
// later mosey gets it (§9.2.4).
func currentOrigin() origin {
	o := origin{from: os.Getenv(bootstrap.FromVar)}
	os.Unsetenv(bootstrap.FromVar)
	// os.Getwd gives $PWD when it names the same directory, so a path
	// through a symlink stays as the shell showed it.
	if wd, err := os.Getwd(); err == nil && filepath.IsAbs(wd) && bootstrap.ValidDir(wd) {
		o.wd = wd
	}
	if sid, err := unix.Getsid(0); err == nil && sid == os.Getpid() {
		o.leader = true
	}
	o.hostname, _ = os.Hostname()
	return o
}

// remote is the host and directory MOSEY_FROM names, when it names
// another machine and the terminal itself started this client (§9.2.4).
func (o origin) remote() (host, dir string, ok bool) {
	if !o.leader || o.from == "" {
		return "", "", false
	}
	host, dir, ok = bootstrap.ParseFrom(o.from)
	if !ok || bootstrap.SameHost(host, o.hostname) {
		return "", "", false
	}
	return host, dir, true
}
