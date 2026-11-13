package sandbox

import "golang.org/x/sys/unix"

// GoRuntime is the set of syscalls the Go 1.27 runtime (CGO_ENABLED=0)
// makes *after* our sandbox is applied, i.e. after start-up and after the
// inherited fds have been wrapped (which is when the netpoller is created).
//
// Every entry was OBSERVED in a trace committed under
// docs/spikes/s4-privsep/data/ (strace -ff on amd64; qemu-aarch64 -strace on
// arm64), except where the comment gives a runtime source path instead.
// Entries of the first version that were never observed are gone (see
// Removed below), and the KILL soaks were re-run without them.
var GoRuntime = []string{
	// memory (mprotect removed: never observed; Go's linux runtime has no
	// mprotect call outside race/msan builds)
	"mmap", "munmap", "madvise",
	// threads, scheduling, async preemption = tgkill(getpid(), tid, SIGURG)
	"clone", "futex", "sched_yield", "nanosleep", "gettid", "getpid", "tgkill",
	"sigaltstack", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
	"exit_group",
	// NOT observed, kept: exit(2) is how an M ends (runtime.exitThread,
	// src/runtime/sys_linux_{amd64,arm64}.s), reached when a goroutine
	// exits while locked to its thread (runtime.LockOSThread without
	// Unlock). Our code does that in InstallThisThread's caller and the red
	// team; without it such an exit would SIGSYS the process.
	"exit",
	// Go >= 1.25 updatemaxprocs: sysmon re-reads affinity about once a
	// second, and pread64s the cgroup cpu.max fd it opened at start-up.
	// pread64 appears only when cpu.max exists (a CPUQuota): observed in
	// data/pread64-systemd.trace, absent from the unconstrained traces.
	"sched_getaffinity", "pread64",
	// netpoller (epoll_create1/eventfd2 happen at start-up, before the
	// filter; epoll_wait/epoll_pwait2/pipe2 removed: never observed)
	"epoll_pwait", "epoll_ctl",
	// time: vDSO normally; observed as a syscall under qemu-aarch64
	"clock_gettime",
	"fcntl", "close",
	// read/write: the IPC fd and the runtime's own fds
	"read", "write",
}

// Removed lists what the first version allowed without ever observing it.
// Kept as a record; Program never sees it.
var Removed = []string{"mprotect", "clock_nanosleep", "epoll_pwait2", "epoll_wait", "pipe2",
	"getrandom (net, emu)", "recvmmsg", "sendmmsg", "recvmsg (net)", "sendmsg",
	"getsockname", "getpeername", "getsockopt", "eventfd2", "epoll_create1"}

// runtimeFail: calls the runtime probes and survives failing. See Policy.Fail.
var runtimeFail = map[string]unix.Errno{"clone3": unix.ENOSYS, "prctl": unix.EINVAL}

func policy(name string, def Action, extra ...string) Policy {
	return Policy{
		Name:            name,
		Allow:           append(append([]string{}, GoRuntime...), extra...),
		Fail:            runtimeFail,
		CloneThreadOnly: true,
		Default:         def,
	}
}

// NetPolicy is the network process's policy in layouts A and B: receive and
// send on the already-open UDP socket (ReadFromUDPAddrPort = recvfrom,
// WriteToUDPAddrPort = sendto; both observed). Note what is absent: socket,
// socketpair, connect, bind, listen, accept, open/openat, execve, ptrace,
// process_vm_*, pidfd_*, io_uring_*, ioctl, kill.
func NetPolicy(def Action) Policy { return policy("net", def, "recvfrom", "sendto") }

// NetRecvOnlyPolicy (layout B2): no sendto. write(2) stays (the IPC socket
// is written with it), so this is only a no-send policy while the shared UDP
// socket is unconnected: on an unconnected UDP socket write fails with
// EDESTADDRREQ, and connect(2) is not allowed here. If the session ever
// connected the socket, write would send (measured: the B2c counterfactual
// in the red-team table). The session asserts the invariant at start-up.
func NetRecvOnlyPolicy(def Action) Policy { return policy("net-recvonly", def, "recvfrom") }

// EmuPolicy is the emulator helper's policy: the runtime and its one IPC fd,
// which a SOCK_SEQPACKET *net.UnixConn reads and writes with read/write
// (observed: no sendto/recvmsg in the emu trace).
func EmuPolicy(def Action) Policy { return policy("emu", def) }

// ProtoPolicy is layout C's protocol process: UDP recv and send (it owns
// the socket), recvmsg to receive pty masters over SCM_RIGHTS, and
// getrandom for crypto/rand (challenge nonces, rekeying). Reads and writes
// on the pty masters are plain read/write. A real server also needs
// ioctl(TIOCSWINSZ) on the masters for window size, argument-filtered;
// the spike never resizes, so it is not allowed here.
func ProtoPolicy(def Action) Policy {
	return policy("proto", def, "recvfrom", "sendto", "recvmsg", "getrandom")
}

// StartupExtras are what a Go program does between execve and main.main
// (and our own pre-sandbox setup): TLS (arch_prctl, amd64), the
// RLIMIT_NOFILE bump (prlimit64), reading THP size and cgroup files (openat,
// read), fstat, wrapping inherited fds (getsockopt etc. are in UDPAndIPC),
// landlock (if applied after), and prctl for NO_NEW_PRIVS.
var StartupExtras = []string{
	"getsockname", "getpeername", "getsockopt", "epoll_create1", "eventfd2", "getrandom",
	"arch_prctl", "prlimit64", "openat", "fstat", "newfstatat", "readlinkat",
	"getppid", "getuid", "uname", "lseek",
	"landlock_create_ruleset", "landlock_add_rule", "landlock_restrict_self",
	"seccomp", "prctl",
}

// SpawnExtras are what Go's syscall.forkAndExecInChild does in the vfork
// child before execve.
var SpawnExtras = []string{
	"execve", "pipe2", "dup3", "dup2", "close_range", "setsid", "setpgid", "ioctl",
	"chdir", "wait4", "waitid", "pidfd_open", "pidfd_send_signal",
}

// PreRuntimePolicy is the policy that must be in force from the first
// instruction of the child image: everything the runtime needs to start
// plus everything NetPolicy needs afterwards. Approach (2): it can only be
// as narrow as start-up allows; a narrower TSYNC filter is stacked later.
//
// Filters stack (every installed filter must allow a call), so this must be
// a superset of every role's later policy: it is built on ProtoPolicy,
// which contains Net, NetRecvOnly and Emu. (Measured: built on NetPolicy,
// proto died with SIGSYS at its first recvmsg.)
func PreRuntimePolicy(def Action) Policy {
	p := ProtoPolicy(def)
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
