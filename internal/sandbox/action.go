package sandbox

// builtAction is the action each architecture's binary is built with,
// never chosen by the environment in a release build (server.md §6.1).
//
// D22 says Kill on amd64. Both run Errno until the KILL soak (server.md
// §9) is a green CI job: before that a missing syscall in a rare runtime
// path would kill a user's session, and TestReleaseAction, which the
// release job runs, refuses to let such a build out. arm64 stays on Errno
// until a soak on arm64 hardware passes (D22).
var builtAction = map[Arch]Action{
	AMD64: Errno,
	ARM64: Errno,
}

// soakAction is set only by a soak build (action_soak.go), so the soak can
// run either architecture under Kill, or Log for discovery, before its
// default changes.
var soakAction func() (Action, bool)

// DefaultAction is the action the server's roles enter their sandbox with
// on this architecture.
func DefaultAction() Action {
	if soakAction != nil {
		if a, ok := soakAction(); ok {
			return a
		}
	}
	arch, err := Native()
	if err != nil {
		return Kill
	}
	return builtAction[arch]
}
