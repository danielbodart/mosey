package sandbox

import (
	"errors"
	"fmt"
	"slices"
	"sort"
)

// Arch is a seccomp audit architecture the compiler can target, so the
// filter for each architecture is built and tested on any host.
type Arch uint8

const (
	AMD64 Arch = iota + 1
	ARM64
)

func (a Arch) String() string {
	switch a {
	case AMD64:
		return "amd64"
	case ARM64:
		return "arm64"
	}
	return "unknown"
}

// The kernel's names for the two (linux/audit.h): the first thing a filter
// checks, because a syscall number means nothing without its architecture.
const (
	auditArchX86_64  = 0xc000003e
	auditArchAArch64 = 0xc00000b7
)

func (a Arch) audit() uint32 {
	switch a {
	case AMD64:
		return auditArchX86_64
	case ARM64:
		return auditArchAArch64
	}
	return 0
}

// Number is the syscall's number on a, from the table generated from the
// pinned golang.org/x/sys.
func (a Arch) Number(name string) (uint32, bool) {
	var n uint32
	var ok bool
	switch a {
	case AMD64:
		n, ok = sysnumAMD64[name]
	case ARM64:
		n, ok = sysnumARM64[name]
	}
	return n, ok
}

// Instruction is one cBPF instruction, as struct sock_filter lays it out.
// It is the package's own type so the compiler and its interpreter test run
// on systems without seccomp.
type Instruction struct {
	Code   uint16
	JT, JF uint8
	K      uint32
}

// Rule is a syscall allowed only when its arguments pass a check, because
// allowing it outright would let the role reach another process.
type Rule uint8

const (
	// CloneThread allows clone(2) only with CLONE_THREAD: new threads,
	// never new processes, so no fork and no path to exec.
	CloneThread Rule = iota + 1
	// TgkillSelf allows tgkill(2) only at the role's own thread group. The
	// runtime only ever signals its own threads (preemption, forwarding,
	// raise on a crash), so this costs it nothing, and emu cannot signal
	// another of the user's processes on any kernel (server.md §6.3).
	TgkillSelf
	// Fcntl allows fcntl(2) only with the commands the runtime and os use
	// after start-up, and F_SETFL only with O_ASYNC clear, which shuts the
	// other route to a signal: F_SETOWN, F_SETOWN_EX and F_SETSIG are
	// absent, so no fd can be armed to signal a victim.
	Fcntl
	// IoctlPTY allows ioctl(2) only on the pty master's fd, and only
	// TCGETS (the echo-off bit, D12) and TIOCSWINSZ (the window size).
	IoctlPTY
)

func (r Rule) syscall() string {
	switch r {
	case CloneThread:
		return "clone"
	case TgkillSelf:
		return "tgkill"
	case Fcntl:
		return "fcntl"
	case IoctlPTY:
		return "ioctl"
	}
	return ""
}

// Failure is a syscall answered with an errno instead of the default
// action, because the runtime probes it and copes when it fails.
type Failure struct {
	Name  string
	Errno uint16
}

// Policy is a role's allow-list, by name, so one policy compiles for every
// architecture.
type Policy struct {
	Name string
	// Allow are allowed whatever their arguments.
	Allow []string
	// Rules are allowed only when their arguments pass (Rule).
	Rules []Rule
	// Fail are answered with their errno.
	Fail []Failure
}

// Linux errno values, the same on amd64 and arm64 (asm-generic/errno-base.h,
// asm-generic/errno.h).
const (
	errnoEPERM  = 1
	errnoEINVAL = 22
	errnoENOSYS = 38
)

// The Go runtime's set (CGO_ENABLED=0, after start-up), from S4's traces
// (S4 §3.3), as server.md §6.3 lists it. exit was never traced but is how a
// thread ends when its goroutine exits locked to it (runtime.exitThread);
// pread64 appears only under a CPU quota, when updatemaxprocs re-reads the
// cgroup's cpu.max (S4 §3.5: the soak that found it). restart_syscall was
// never traced either: it is how the kernel goes on with a sleep that a
// stop interrupted, and the freezer stops every task at suspend, so
// without it every session died when the machine woke.
var runtimeSyscalls = []string{
	"mmap", "munmap", "madvise",
	"futex", "sched_yield", "nanosleep", "restart_syscall", "gettid", "getpid",
	"sigaltstack", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
	"exit", "exit_group",
	"sched_getaffinity", "pread64",
	"epoll_pwait", "epoll_ctl",
	"clock_gettime",
	"close", "read", "write",
}

var runtimeRules = []Rule{CloneThread, TgkillSelf, Fcntl}

// clone3 fails with ENOSYS so the runtime falls back to clone, which the
// filter can inspect (clone3's flags are behind a pointer). prctl fails
// with EINVAL because Go 1.25 and later name their mappings with
// prctl(PR_SET_VMA) and stop for good on EINVAL, where a kill would crash
// on any kernel with CONFIG_ANON_VMA_NAME (S4).
var runtimeFailures = []Failure{
	{"clone3", errnoENOSYS},
	{"prctl", errnoEINVAL},
}

// PolicyFor is role's allow-list: the Go runtime's set plus the role's own
// (server.md §6.3).
func PolicyFor(role Role) Policy {
	p := Policy{
		Name:  role.String(),
		Allow: slices.Clone(runtimeSyscalls),
		Rules: slices.Clone(runtimeRules),
		Fail:  slices.Clone(runtimeFailures),
	}
	switch role {
	case Proto:
		// recvfrom and sendto are the UDP socket (ReadFromUDPAddrPort,
		// WriteToUDPAddrPort): never sendmsg, so proto can pass no fd.
		// recvmsg is EmuLink's fd after the sandbox is on. getrandom is
		// crypto/rand: the credential, handshakes, rekeys, path challenges.
		p.Allow = append(p.Allow, "recvfrom", "sendto", "recvmsg", "getrandom")
		p.Rules = append(p.Rules, IoctlPTY)
	case Emu:
		// Nothing: emu reads and writes its one socket with read and write.
	}
	return p
}

// seccomp return values (linux/seccomp.h).
const (
	retKillProcess = 0x80000000
	retErrno       = 0x00050000
	retTrap        = 0x00030000
	retLog         = 0x7ffc0000
	retAllow       = 0x7fff0000
)

func (a Action) ret() uint32 {
	switch a {
	case Kill:
		return retKillProcess
	case Errno:
		return retErrno | errnoEPERM
	case Log:
		return retLog
	case Trap:
		return retTrap
	}
	return retKillProcess
}

// Classic BPF opcodes (linux/bpf_common.h), only the few the filter uses.
const (
	opLoadAbs = 0x00 | 0x00 | 0x20 // BPF_LD | BPF_W | BPF_ABS
	opJEQ     = 0x05 | 0x10        // BPF_JMP | BPF_JEQ | BPF_K
	opJGE     = 0x05 | 0x30        // BPF_JMP | BPF_JGE | BPF_K
	opJSET    = 0x05 | 0x40        // BPF_JMP | BPF_JSET | BPF_K
	opRet     = 0x06               // BPF_RET | BPF_K
)

// Offsets into struct seccomp_data. Arguments are 64 bits, little-endian on
// both targets, so the word at an argument's offset is its low half, which
// is all any rule compares: the kernel takes each argument a rule checks as
// a 32-bit type, so the high half cannot change what it does.
const (
	offNr   = 0
	offArch = 4
	offArgs = 16
)

func argLow(i int) uint32 { return uint32(offArgs + 8*i) }

// The numbers the rules compare, the same on amd64 and arm64 (asm-generic
// ioctls.h, fcntl.h; linux/sched.h).
const (
	x32Bit        = 0x40000000
	cloneThread   = 0x00010000
	ioctlTCGETS   = 0x5401
	ioctlTIOCSWIN = 0x5414
	fGetFD        = 1
	fSetFD        = 2
	fGetFL        = 3
	fSetFL        = 4
	fDupFDCloexec = 1030
	oAsync        = 0x2000
)

// ErrJumpTooLong is Compile's refusal of a policy whose filter would need a
// conditional jump past 255 instructions, which cBPF cannot encode.
var ErrJumpTooLong = errors.New("sandbox: the filter needs a jump longer than cBPF allows")

// Compile turns p into a filter for arch, for a process with params. In
// order (server.md §6.3): a foreign audit architecture is killed, and on
// amd64 so is any x32 syscall, whatever the action, since a filter that
// cannot read the syscall number right has nothing to fall back on; then
// each rule's check; then p's failures; then p's syscalls, one JEQ each,
// sorted by number; and action for everything else.
func Compile(arch Arch, p Policy, action Action, params Params) ([]Instruction, error) {
	if arch.audit() == 0 {
		return nil, fmt.Errorf("sandbox: unknown architecture %d", arch)
	}
	num := func(name string) (uint32, error) {
		n, ok := arch.Number(name)
		if !ok {
			// A missing name is an error, never a silent skip: policies
			// list only names both targets have (no open on arm64).
			return 0, fmt.Errorf("sandbox: %s has no syscall %q (policy %s)", arch, name, p.Name)
		}
		return n, nil
	}
	seen := map[uint32]string{}
	claim := func(name string) (uint32, error) {
		n, err := num(name)
		if err != nil {
			return 0, err
		}
		if prev, dup := seen[n]; dup {
			return 0, fmt.Errorf("sandbox: policy %s lists syscall %q twice (as %q)", p.Name, name, prev)
		}
		seen[n] = name
		return n, nil
	}

	var a assembler
	deny := action.ret()
	a.load(offArch)
	a.jeq(arch.audit(), "nr", "kill")
	a.label("kill")
	a.ret(retKillProcess)
	a.label("nr")
	a.load(offNr)
	if arch == AMD64 {
		a.jge(x32Bit, "x32", "rules")
		a.label("x32")
		a.ret(retKillProcess)
	}
	a.label("rules")

	for i, r := range p.Rules {
		nr, err := claim(r.syscall())
		if err != nil {
			return nil, err
		}
		next := fmt.Sprintf("rule%d", i+1)
		allow, refuse := fmt.Sprintf("rule%d.allow", i), fmt.Sprintf("rule%d.deny", i)
		a.jeq(nr, fmt.Sprintf("rule%d.body", i), next)
		a.label(fmt.Sprintf("rule%d.body", i))
		switch r {
		case CloneThread:
			a.load(argLow(0))
			a.jset(cloneThread, allow, refuse)
		case TgkillSelf:
			if params.Pid <= 0 {
				return nil, fmt.Errorf("sandbox: policy %s needs the process's pid", p.Name)
			}
			a.load(argLow(0))
			a.jeq(uint32(params.Pid), allow, refuse)
		case Fcntl:
			a.load(argLow(1))
			for _, cmd := range []uint32{fGetFD, fSetFD, fGetFL, fDupFDCloexec} {
				a.jeq(cmd, allow, "")
			}
			a.jeq(fSetFL, fmt.Sprintf("rule%d.setfl", i), refuse)
			a.label(fmt.Sprintf("rule%d.setfl", i))
			a.load(argLow(2))
			a.jset(oAsync, refuse, allow)
		case IoctlPTY:
			if params.PTY <= 0 {
				return nil, fmt.Errorf("sandbox: policy %s needs the pty master's fd", p.Name)
			}
			a.load(argLow(0))
			a.jeq(uint32(params.PTY), fmt.Sprintf("rule%d.req", i), refuse)
			a.label(fmt.Sprintf("rule%d.req", i))
			a.load(argLow(1))
			a.jeq(ioctlTCGETS, allow, "")
			a.jeq(ioctlTIOCSWIN, allow, refuse)
		default:
			return nil, fmt.Errorf("sandbox: unknown rule %d", r)
		}
		a.label(allow)
		a.ret(retAllow)
		a.label(refuse)
		a.ret(deny)
		// The rule's checks loaded arguments into A, but every path
		// through them returns, so the next rule is reached only by the
		// first JEQ's false branch, with A still the syscall number.
		a.label(next)
	}

	for _, f := range p.Fail {
		nr, err := claim(f.Name)
		if err != nil {
			return nil, err
		}
		a.jeq(nr, "fail."+f.Name, "")
	}

	type entry struct {
		nr   uint32
		name string
	}
	var allowed []entry
	for _, name := range p.Allow {
		nr, err := claim(name)
		if err != nil {
			return nil, err
		}
		allowed = append(allowed, entry{nr, name})
	}
	sort.Slice(allowed, func(i, j int) bool { return allowed[i].nr < allowed[j].nr })
	for _, e := range allowed {
		a.jeq(e.nr, "allow", "")
	}
	a.ret(deny)
	a.label("allow")
	a.ret(retAllow)
	for _, f := range p.Fail {
		a.label("fail." + f.Name)
		a.ret(retErrno | uint32(f.Errno))
	}
	return a.assemble()
}

// assembler is just enough of one to write the filter with named targets
// rather than hand-counted offsets: each jump names where it goes, "" being
// the next instruction, and assemble resolves them, refusing any that cBPF's
// 8-bit offsets cannot reach.
type assembler struct {
	code   []Instruction
	labels map[string]int
	jumps  []pendingJump
}

type pendingJump struct {
	at     int
	jt, jf string
}

func (a *assembler) label(name string) {
	if a.labels == nil {
		a.labels = map[string]int{}
	}
	a.labels[name] = len(a.code)
}

func (a *assembler) load(offset uint32) {
	a.code = append(a.code, Instruction{Code: opLoadAbs, K: offset})
}
func (a *assembler) ret(k uint32) { a.code = append(a.code, Instruction{Code: opRet, K: k}) }
func (a *assembler) jeq(k uint32, jt, jf string) {
	a.jump(opJEQ, k, jt, jf)
}
func (a *assembler) jge(k uint32, jt, jf string)  { a.jump(opJGE, k, jt, jf) }
func (a *assembler) jset(k uint32, jt, jf string) { a.jump(opJSET, k, jt, jf) }

func (a *assembler) jump(op uint16, k uint32, jt, jf string) {
	a.jumps = append(a.jumps, pendingJump{len(a.code), jt, jf})
	a.code = append(a.code, Instruction{Code: op, K: k})
}

func (a *assembler) assemble() ([]Instruction, error) {
	offset := func(from int, to string) (uint8, error) {
		if to == "" {
			return 0, nil
		}
		target, ok := a.labels[to]
		if !ok {
			return 0, fmt.Errorf("sandbox: no label %q", to)
		}
		d := target - from - 1
		if d < 0 {
			return 0, fmt.Errorf("sandbox: label %q is behind its jump", to)
		}
		if d > 255 {
			return 0, ErrJumpTooLong
		}
		return uint8(d), nil
	}
	for _, j := range a.jumps {
		jt, err := offset(j.at, j.jt)
		if err != nil {
			return nil, err
		}
		jf, err := offset(j.at, j.jf)
		if err != nil {
			return nil, err
		}
		a.code[j.at].JT, a.code[j.at].JF = jt, jf
	}
	if len(a.code) > 4096 { // BPF_MAXINSNS
		return nil, fmt.Errorf("sandbox: %d instructions is more than the kernel takes", len(a.code))
	}
	return a.code, nil
}
