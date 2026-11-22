package server

import (
	"os/exec"

	"github.com/danielbodart/mosey/internal/startup"
)

// selfCommand starts this mosey again with flag (--serve=ROLE): from
// self's very image, not whatever is at its path by now, which D7 may have
// replaced with a build of another protocol (server.md §2.3,
// bootstrap.md §4.7.7); with self's path as argv[0], so ps and the tests
// see which file it came from; and through the loader that started this
// one, if any (internal/startup). The caller sets the rest of the Cmd.
func selfCommand(self startup.Process, flag string) *exec.Cmd {
	cmd := &exec.Cmd{Path: self.Executable(), Args: []string{self.Path, flag}}
	self.Prepare(cmd)
	return cmd
}
