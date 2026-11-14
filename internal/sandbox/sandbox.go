package sandbox

// Role is a sandboxed process's job, which picks its allow-list.
type Role uint8

const (
	// Proto may receive and send UDP, receive fds over its IPC socket, and
	// read and write the pty masters it was given (with TIOCSWINSZ on them).
	Proto Role = iota + 1
	// Emu may read and write its IPC socket and nothing else.
	Emu
)

// Action is what seccomp does with a syscall outside the allow-list.
type Action uint8

const (
	// Kill ends the whole process (SECCOMP_RET_KILL_PROCESS). The target on
	// amd64; on arm64 only once a CI soak on real hardware passes (D22).
	Kill Action = iota
	// Errno fails the call with EPERM and lets the process carry on. Slice 1
	// may ship with it while the KILL soak is not ready.
	Errno
)

// Enter confines the calling process for role, in S4's order: drop
// dumpability, Landlock deny-all (with abstract-unix and signal scoping
// where the kernel has them), then seccomp on every thread. Call it after
// every inherited fd is wrapped and before reading any input.
func Enter(role Role, action Action) error {
	return enter(role, action)
}
