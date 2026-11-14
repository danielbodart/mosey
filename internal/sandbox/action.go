package sandbox

// builtAction is the action each architecture's binary is built with,
// never chosen by the environment in a release build (server.md §6.1).
//
// D22: Kill on amd64, which the KILL soak (server.md §9, CI's kill-soak
// job, scripts/soak.sh) covers on every push; TestReleaseAction keeps it
// so. arm64 stays on Errno until a soak under Kill on arm64 hardware
// passes, and a later commit cites that run (D22).
var builtAction = map[Arch]Action{
	AMD64: Kill,
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
