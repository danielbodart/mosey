package sandbox

// builtAction is the action each architecture's binary is built with,
// never chosen by the environment in a release build (server.md §6.1).
//
// D22: Kill on both architectures. The KILL soak (server.md §9, CI's
// kill-soak job, scripts/soak.sh) covers both on every push, and
// TestReleaseAction keeps it so. arm64 switched from Errno after CI run
// 43626969195 (commit 1c73272) soaked it under Kill for 150 s on
// ubuntu-24.04-arm with a CPU quota, with no role killed.
var builtAction = map[Arch]Action{
	AMD64: Kill,
	ARM64: Kill,
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
