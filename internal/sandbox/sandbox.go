package sandbox

//go:generate go run gensysnum.go

// Role is a sandboxed process's job, which picks its allow-list.
type Role uint8

const (
	// Proto may receive and send UDP, receive fds over its IPC socket, and
	// read and write the pty master it was given, with TCGETS and
	// TIOCSWINSZ on it and nothing else.
	Proto Role = iota + 1
	// Emu may read and write its IPC socket and nothing else.
	Emu
)

func (r Role) String() string {
	switch r {
	case Proto:
		return "proto"
	case Emu:
		return "emu"
	}
	return "unknown"
}

// Action is what seccomp does with a syscall outside the allow-list.
type Action uint8

const (
	// Kill ends the whole process (SECCOMP_RET_KILL_PROCESS). D22's target
	// on amd64; on arm64 only once a CI soak on real hardware passes.
	Kill Action = iota
	// Errno fails the call with EPERM and lets the process carry on.
	// Development builds run it until the KILL soak is a CI gate
	// (server.md §6.1, §9).
	Errno
	// Log allows the call and has the kernel log it (SECCOMP_RET_LOG). It
	// exists for the discovery procedure of server.md §6.3, which re-derives
	// the allow-lists from the real roles; only a soak build can choose it.
	Log
	// Trap sends the calling thread SIGSYS (SECCOMP_RET_TRAP), which the Go
	// runtime turns into a crash showing the goroutine stack that made the
	// call: the quickest way to find what a policy is missing (it is how
	// the roles' lazy time zone load was found; see server.settleLazyInit).
	// Soak builds only, like Log.
	Trap
)

func (a Action) String() string {
	switch a {
	case Kill:
		return "kill"
	case Errno:
		return "errno"
	case Log:
		return "log"
	case Trap:
		return "trap"
	}
	return "unknown"
}

// Params are the facts about the calling process that its filter is
// compiled with, because they are known only once it is running.
type Params struct {
	// PTY is the pty master's fd number, the only fd proto may ioctl.
	// Needed for Proto; ignored for Emu.
	PTY int
	// Pid is the process's own pid, the only thread group it may tgkill.
	// Enter fills it from getpid() when it is zero; tests give another to
	// the interpreter.
	Pid int
}

// Enter confines the calling process for role, in the order of server.md
// §6.1: PR_SET_DUMPABLE 0, NO_NEW_PRIVS on every thread, Landlock deny-all,
// then the seccomp filter on every thread with TSYNC. Call it after every
// inherited fd is wrapped and before reading any input.
//
// Every failure is an error the caller must treat as fatal, except one:
// a kernel without Landlock (the version probe says 0, ENOSYS or
// EOPNOTSUPP), which Enter reports through warn and carries on with seccomp
// alone, which on its own stopped every attack in S4's battery (S4 §3.6).
// On systems other than Linux it returns errors.ErrUnsupported.
func Enter(role Role, action Action, params Params, warn func(string)) error {
	if warn == nil {
		warn = func(string) {}
	}
	return enter(role, action, params, warn)
}

// NotDumpable is PR_SET_DUMPABLE 0 on its own, which a role does first of
// all, before anything holds a key (server.md §6.1); Enter does it again.
func NotDumpable() error {
	return notDumpable()
}
