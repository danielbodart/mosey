package sandbox

import "golang.org/x/sys/unix"

// GoRuntime is the set of syscalls the Go 1.27 runtime (CGO_ENABLED=0,
// linux/amd64 + linux/arm64) was observed to make *after start-up*, under
// GC, scavenging, async preemption, timers, goroutine churn and GOMAXPROCS
// changes. Derived in the S4 spike from strace -ff (amd64, native) and
// qemu-aarch64 -strace (arm64) and then soak-tested under a KILL filter;
// see docs/spikes/s4-privsep/FINDINGS.md. Names that don't exist on an arch
// (e.g. "epoll_wait" on arm64) are skipped by Program.
var GoRuntime = []string{
	// memory
	"mmap", "munmap", "madvise", "mprotect",
	// threads, scheduling, preemption (tgkill(getpid(), tid, SIGURG))
	"clone", "futex", "sched_yield", "nanosleep", "gettid", "getpid", "tgkill",
	"sigaltstack", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
	"exit", "exit_group",
	// Go >= 1.25 updatemaxprocs: sysmon re-reads affinity about once a
	// second, and pread64s the cgroup cpu.max fd it opened at start-up.
	"sched_getaffinity", "pread64",
	// netpoller
	"epoll_create1", "epoll_ctl", "epoll_pwait", "epoll_pwait2", "epoll_wait",
	"eventfd2", "pipe2",
	// time (vDSO normally; the syscall is the fallback)
	"clock_gettime", "clock_nanosleep",
	// misc
	"getrandom", "fcntl", "close",
	// read/write: the IPC fd and the runtime's own fds
	"read", "write",
}

// runtimeFail: calls the runtime probes and survives failing. See Policy.Fail.
var runtimeFail = map[string]unix.Errno{"clone3": unix.ENOSYS, "prctl": unix.EINVAL}

// UDPAndIPC is what the network process adds for an *already open* UDP
// socket and the SOCK_SEQPACKET socketpair to the session process. Note what
// is absent: socket, socketpair, connect, bind, listen, accept, open/openat,
// execve, ptrace, process_vm_*, pidfd_*, io_uring_*, ioctl, kill.
var UDPAndIPC = []string{
	"recvfrom", "recvmsg", "recvmmsg", "sendto", "sendmsg", "sendmmsg",
	"getsockname", "getpeername", "getsockopt",
}

// NetPolicy is the network process's policy.
func NetPolicy(def Action) Policy {
	return Policy{
		Name:            "net",
		Allow:           append(append([]string{}, GoRuntime...), UDPAndIPC...),
		Fail:            runtimeFail,
		CloneThreadOnly: true,
		Default:         def,
	}
}

// NetRecvOnlyPolicy is NetPolicy without any send path: no sendto, sendmsg,
// sendmmsg. write(2) stays (the IPC socket is written with write), but on
// the unconnected UDP socket write fails with EDESTADDRREQ and connect(2) is
// not allowed, so the process cannot emit a datagram. Layout "B2": the
// session process, which already chooses the destination, does the sending.
func NetRecvOnlyPolicy(def Action) Policy {
	p := NetPolicy(def)
	p.Name = "net-recvonly"
	p.Allow = nil
	for _, n := range NetPolicy(def).Allow {
		if n != "sendto" && n != "sendmsg" && n != "sendmmsg" {
			p.Allow = append(p.Allow, n)
		}
	}
	return p
}

// EmuPolicy is the emulator helper's policy: the runtime and its one IPC fd.
func EmuPolicy(def Action) Policy {
	return Policy{
		Name:            "emu",
		Allow:           append(append([]string{}, GoRuntime...), "recvmsg", "sendmsg", "recvfrom", "sendto"),
		Fail:            runtimeFail,
		CloneThreadOnly: true,
		Default:         def,
	}
}

// StartupExtras are what a Go program does between execve and main.main
// (and our own pre-sandbox setup): TLS (arch_prctl, amd64), the
// RLIMIT_NOFILE bump (prlimit64), reading THP size and cgroup files (openat,
// read), fstat, wrapping inherited fds (getsockopt etc. are in UDPAndIPC),
// landlock (if applied after), and prctl for NO_NEW_PRIVS.
var StartupExtras = []string{
	"arch_prctl", "prlimit64", "openat", "fstat", "newfstatat", "readlinkat",
	"getppid", "getuid", "uname", "lseek",
	"landlock_create_ruleset", "landlock_add_rule", "landlock_restrict_self",
	"seccomp", "prctl",
}

// SpawnExtras are what Go's syscall.forkAndExecInChild does in the vfork
// child before execve.
var SpawnExtras = []string{
	"execve", "dup3", "dup2", "close_range", "setsid", "setpgid", "ioctl",
	"chdir", "wait4", "waitid", "pidfd_open", "pidfd_send_signal",
}

// PreRuntimePolicy is the policy that must be in force from the first
// instruction of the child image: everything the runtime needs to start
// plus everything NetPolicy needs afterwards. Approach (2): it can only be
// as narrow as start-up allows; a narrower TSYNC filter is stacked later.
func PreRuntimePolicy(def Action) Policy {
	p := NetPolicy(def)
	p.Name = "net-preruntime"
	p.Allow = append(p.Allow, StartupExtras...)
	p.Fail = map[string]unix.Errno{"clone3": unix.ENOSYS}
	return p
}

// SpawnPolicy is PreRuntimePolicy widened so it can be installed in the
// parent on the thread that will vfork+exec the child (approach 2a). clone
// must be unrestricted there (vfork is clone without CLONE_THREAD), and
// execve must be allowed, and stays allowed in the child until the stacked
// TSYNC filter takes it away.
func SpawnPolicy(def Action) Policy {
	p := PreRuntimePolicy(def)
	p.Name = "net-prespawn"
	p.Allow = append(p.Allow, SpawnExtras...)
	p.CloneThreadOnly = false
	return p
}
