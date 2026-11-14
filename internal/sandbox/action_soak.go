//go:build soak

package sandbox

import "os"

// A soak build reads MOSEY_SOAK_ACTION (kill, errno, log or the
// SIGSYS one), so CI can soak an architecture under Kill before its default
// changes, and the discovery procedure can log every syscall or crash with
// the stack that made a missing one (server.md §6.3, §9). A release build has
// no such knob: this file is not in it.
func init() {
	soakAction = func() (Action, bool) {
		switch os.Getenv("MOSEY_SOAK_ACTION") {
		case "kill":
			return Kill, true
		case "errno":
			return Errno, true
		case "log":
			return Log, true
		case "trap":
			return Trap, true
		}
		return 0, false
	}
}
