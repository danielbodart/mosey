package main

import (
	"os"
	"path/filepath"

	"github.com/danielbodart/mosey/internal/bootstrap"
)

// origin is where the terminal started this client: what decides the
// implicit directory of a session it creates (bootstrap.md §9.2.4). It is
// read once, in runClient, so that parseArgs stays a pure function of it.
type origin struct {
	// wd is the client's working directory, "" if it cannot be had or
	// could not be sent as a dir.
	wd string
}

// currentOrigin reads this process's origin.
func currentOrigin() origin {
	var o origin
	// os.Getwd gives $PWD when it names the same directory, so a path
	// through a symlink stays as the shell showed it.
	if wd, err := os.Getwd(); err == nil && filepath.IsAbs(wd) && bootstrap.ValidDir(wd) {
		o.wd = wd
	}
	return o
}
