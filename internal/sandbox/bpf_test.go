package sandbox

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"testing"
)

// call is one syscall as the kernel hands it to a filter: struct
// seccomp_data, with the arguments as the 64-bit values they are.
type call struct {
	arch uint32
	nr   uint32
	args [6]uint64
}

func (c call) data() []byte {
	b := make([]byte, 64)
	binary.LittleEndian.PutUint32(b[offNr:], c.nr)
	binary.LittleEndian.PutUint32(b[offArch:], c.arch)
	for i, a := range c.args {
		binary.LittleEndian.PutUint64(b[offArgs+8*i:], a)
	}
	return b
}

// interpret runs a filter as the kernel would, for the instructions Compile
// emits, refusing anything else, a jump off the end, or a load outside
// seccomp_data, so a compiler bug fails here rather than in the kernel.
func interpret(prog []Instruction, c call) (uint32, error) {
	data := c.data()
	var acc uint32
	for pc := 0; pc < len(prog); pc++ {
		in := prog[pc]
		switch in.Code {
		case opLoadAbs:
			if in.K%4 != 0 || int(in.K)+4 > len(data) {
				return 0, fmt.Errorf("load at %d outside seccomp_data", in.K)
			}
			acc = binary.LittleEndian.Uint32(data[in.K:])
		case opJEQ, opJGE, opJSET:
			var taken bool
			switch in.Code {
			case opJEQ:
				taken = acc == in.K
			case opJGE:
				taken = acc >= in.K
			case opJSET:
				taken = acc&in.K != 0
			}
			if taken {
				pc += int(in.JT)
			} else {
				pc += int(in.JF)
			}
		case opRet:
			return in.K, nil
		default:
			return 0, fmt.Errorf("unknown opcode %#x at %d", in.Code, pc)
		}
	}
	return 0, errors.New("fell off the end of the filter")
}

const testPid = 4242
const testPTY = 7

var arches = []Arch{AMD64, ARM64}

type checker struct {
	t    *testing.T
	arch Arch
	prog []Instruction
}

func compile(t *testing.T, arch Arch, role Role, action Action) checker {
	t.Helper()
	prog, err := Compile(arch, PolicyFor(role), action, Params{PTY: testPTY, Pid: testPid})
	if err != nil {
		t.Fatal(err)
	}
	return checker{t, arch, prog}
}

func (c checker) nr(name string) uint32 {
	c.t.Helper()
	n, ok := c.arch.Number(name)
	if !ok {
		c.t.Fatalf("%s has no %s", c.arch, name)
	}
	return n
}

func (c checker) expect(name string, args []uint64, want uint32) {
	c.t.Helper()
	cl := call{arch: c.arch.audit(), nr: c.nr(name)}
	copy(cl.args[:], args)
	got, err := interpret(c.prog, cl)
	if err != nil {
		c.t.Fatal(err)
	}
	if got != want {
		c.t.Errorf("%s: %s%v = %#x, want %#x", c.arch, name, args, got, want)
	}
}

func TestEveryPolicySyscallIsAllowedOnBothArchitectures(t *testing.T) {
	for _, arch := range arches {
		for _, role := range []Role{Proto, Emu} {
			c := compile(t, arch, role, Kill)
			for _, name := range PolicyFor(role).Allow {
				c.expect(name, nil, retAllow)
			}
		}
	}
}

func TestASyscallOffTheListGetsTheAction(t *testing.T) {
	absent := []string{"socket", "socketpair", "connect", "bind", "listen", "accept4", "openat",
		"execve", "ptrace", "process_vm_readv", "pidfd_open", "pidfd_getfd", "kill", "io_uring_setup",
		"userfaultfd", "keyctl", "unshare", "setns", "sendmsg", "mprotect", "prlimit64", "setrlimit"}
	for _, arch := range arches {
		for _, action := range []Action{Kill, Errno, Log} {
			c := compile(t, arch, Emu, action)
			for _, name := range append(absent, "recvfrom", "sendto", "recvmsg", "getrandom", "ioctl") {
				c.expect(name, nil, action.ret())
			}
			c = compile(t, arch, Proto, action)
			for _, name := range absent {
				c.expect(name, nil, action.ret())
			}
		}
	}
}

func TestErrnoIsEPERMAndKillIsKillProcess(t *testing.T) {
	if Errno.ret() != 0x00050001 || Kill.ret() != 0x80000000 || Log.ret() != 0x7ffc0000 {
		t.Fatalf("actions: kill %#x errno %#x log %#x", Kill.ret(), Errno.ret(), Log.ret())
	}
}

func TestAForeignArchitectureIsKilledWhateverTheAction(t *testing.T) {
	for _, arch := range arches {
		other := ARM64
		if arch == ARM64 {
			other = AMD64
		}
		for _, action := range []Action{Errno, Log} {
			c := compile(t, arch, Emu, action)
			for _, name := range []string{"read", "socket"} {
				got, err := interpret(c.prog, call{arch: other.audit(), nr: c.nr(name)})
				if err != nil {
					t.Fatal(err)
				}
				if got != retKillProcess {
					t.Errorf("%s filter, %s %s: %#x, want kill", arch, other, name, got)
				}
			}
			got, _ := interpret(c.prog, call{arch: 0x40000003 /* i386 */, nr: c.nr("read")})
			if got != retKillProcess {
				t.Errorf("%s filter: i386 not killed", arch)
			}
		}
	}
}

// x32 shares AUDIT_ARCH_X86_64 and marks itself with bit 30 of the number,
// so without this check an x32 call would be read as the x86-64 one.
func TestX32IsKilledOnAMD64(t *testing.T) {
	c := compile(t, AMD64, Proto, Errno)
	for _, name := range []string{"read", "write", "socket"} {
		got, _ := interpret(c.prog, call{arch: auditArchX86_64, nr: c.nr(name) | x32Bit})
		if got != retKillProcess {
			t.Errorf("x32 %s: %#x, want kill", name, got)
		}
	}
}

func TestCloneMakesThreadsButNeverProcesses(t *testing.T) {
	const (
		cloneVM      = 0x100
		cloneFS      = 0x200
		cloneFiles   = 0x400
		cloneSighand = 0x800
		cloneSysvsem = 0x40000
		cloneVfork   = 0x4000
		sigchld      = 17
	)
	runtimeThread := uint64(cloneVM | cloneFS | cloneFiles | cloneSighand | cloneSysvsem | cloneThread)
	for _, arch := range arches {
		for _, action := range []Action{Kill, Errno} {
			for _, role := range []Role{Proto, Emu} {
				c := compile(t, arch, role, action)
				c.expect("clone", []uint64{runtimeThread}, retAllow)
				c.expect("clone", []uint64{cloneVM | cloneVfork | sigchld}, action.ret()) // os/exec
				c.expect("clone", []uint64{sigchld}, action.ret())                        // fork
				// Junk in the high half changes nothing the kernel reads:
				// clone's flags are an unsigned long, but every flag lives
				// in the low 32 bits.
				c.expect("clone", []uint64{sigchld | 0xffffffff00000000}, action.ret())
				c.expect("clone3", nil, retErrno|errnoENOSYS)
				c.expect("prctl", []uint64{0x53564d41 /* PR_SET_VMA */}, retErrno|errnoEINVAL)
				c.expect("prctl", []uint64{4 /* PR_SET_DUMPABLE */, 1}, retErrno|errnoEINVAL)
			}
		}
	}
}

func TestIoctlOnlyOnThePTYMasterAndOnlyTCGETSOrTIOCSWINSZ(t *testing.T) {
	for _, arch := range arches {
		for _, action := range []Action{Kill, Errno} {
			c := compile(t, arch, Proto, action)
			c.expect("ioctl", []uint64{testPTY, ioctlTCGETS}, retAllow)
			c.expect("ioctl", []uint64{testPTY, ioctlTIOCSWIN}, retAllow)
			c.expect("ioctl", []uint64{testPTY | 0xdead00000000, ioctlTIOCSWIN}, retAllow)
			c.expect("ioctl", []uint64{testPTY, ioctlTIOCSWIN, 0xffffffffffffffff}, retAllow)
			c.expect("ioctl", []uint64{testPTY + 1, ioctlTCGETS}, action.ret())
			c.expect("ioctl", []uint64{0, ioctlTCGETS}, action.ret())
			c.expect("ioctl", []uint64{testPTY, 0x5412 /* TIOCSTI */}, action.ret())
			c.expect("ioctl", []uint64{testPTY, 0x540f /* TIOCGPGRP */}, action.ret())
			c.expect("ioctl", []uint64{testPTY, 0x5402 /* TCSETS */}, action.ret())
			c.expect("ioctl", []uint64{testPTY + 1, ioctlTCGETS, testPTY}, action.ret())
			c.expect("ioctl", []uint64{testPTY, 0x5402, ioctlTCGETS}, action.ret())

			e := compile(t, arch, Emu, action)
			e.expect("ioctl", []uint64{testPTY, ioctlTCGETS}, action.ret())
		}
	}
}

func TestTgkillOnlyAtTheRolesOwnPid(t *testing.T) {
	const sigurg, sigkill = 23, 9
	for _, arch := range arches {
		for _, action := range []Action{Kill, Errno} {
			for _, role := range []Role{Proto, Emu} {
				c := compile(t, arch, role, action)
				c.expect("tgkill", []uint64{testPid, testPid + 1, sigurg}, retAllow)
				c.expect("tgkill", []uint64{testPid | 0xffffffff00000000, testPid, sigurg}, retAllow)
				c.expect("tgkill", []uint64{testPid + 1, testPid + 1, sigkill}, action.ret())
				c.expect("tgkill", []uint64{1, 1, sigkill}, action.ret())
				c.expect("tgkill", []uint64{0, 0, sigkill}, action.ret())
				c.expect("tkill", []uint64{testPid}, action.ret())
				c.expect("tgkill", nil, action.ret())
			}
		}
	}
}

func TestFcntlOnlyWithCommandsThatCannotArmASignal(t *testing.T) {
	const fSetOwn, fSetSig, fSetOwnEx, fGetOwn, fSetLease, fNotify = 8, 10, 15, 9, 1024, 1026
	const oNonblock = 0x800
	for _, arch := range arches {
		for _, action := range []Action{Kill, Errno} {
			for _, role := range []Role{Proto, Emu} {
				c := compile(t, arch, role, action)
				for _, cmd := range []uint64{fGetFD, fSetFD, fGetFL, fDupFDCloexec} {
					c.expect("fcntl", []uint64{3, cmd, 0}, retAllow)
				}
				c.expect("fcntl", []uint64{3, fSetFL, oNonblock | 2 /* O_RDWR */}, retAllow)
				c.expect("fcntl", []uint64{3, fSetFL, oNonblock | 0xffffffff00000000}, retAllow)
				c.expect("fcntl", []uint64{3, fSetFL, oNonblock | oAsync}, action.ret())
				c.expect("fcntl", []uint64{3, fSetFL, oAsync}, action.ret())
				for _, cmd := range []uint64{fSetOwn, fSetSig, fSetOwnEx, fGetOwn, fSetLease, fNotify, 0, 0xffff} {
					c.expect("fcntl", []uint64{3, cmd, testPid}, action.ret())
				}
				// The command is an unsigned int: junk in its high half is
				// ignored by the kernel, and must not turn F_SETOWN into an
				// allowed command, nor an allowed one into a refusal.
				c.expect("fcntl", []uint64{3, fSetOwn | 0x100000000, testPid}, action.ret())
				c.expect("fcntl", []uint64{3, fGetFL | 0x100000000, 0}, retAllow)
			}
		}
	}
}

func TestAPolicyNeedsThePidAndForProtoThePTY(t *testing.T) {
	if _, err := Compile(AMD64, PolicyFor(Emu), Kill, Params{}); err == nil {
		t.Error("compiled tgkill's rule without a pid")
	}
	if _, err := Compile(AMD64, PolicyFor(Proto), Kill, Params{Pid: testPid}); err == nil {
		t.Error("compiled proto's ioctl rule without the pty's fd")
	}
	if _, err := Compile(AMD64, PolicyFor(Emu), Kill, Params{Pid: testPid}); err != nil {
		t.Errorf("emu needs no pty: %v", err)
	}
}

func TestANameAnArchitectureLacksIsAnErrorNotASkip(t *testing.T) {
	p := PolicyFor(Emu)
	p.Allow = append(p.Allow, "open")
	if _, err := Compile(ARM64, p, Kill, Params{Pid: testPid}); err == nil {
		t.Error("arm64 has no open(2), and Compile skipped it")
	}
	if _, err := Compile(AMD64, p, Kill, Params{Pid: testPid}); err != nil {
		t.Errorf("amd64 has open(2): %v", err)
	}
}

func TestASyscallListedTwiceIsRefused(t *testing.T) {
	p := PolicyFor(Emu)
	p.Allow = append(p.Allow, "read")
	if _, err := Compile(AMD64, p, Kill, Params{Pid: testPid}); err == nil {
		t.Error("read listed twice compiled")
	}
	p = PolicyFor(Emu)
	p.Allow = append(p.Allow, "fcntl")
	if _, err := Compile(AMD64, p, Kill, Params{Pid: testPid}); err == nil {
		t.Error("fcntl allowed outright beside its rule compiled")
	}
}

// cBPF's conditional jumps are 8 bits: a list long enough that the first
// JEQ cannot reach the shared ALLOW must be refused, never truncated.
func TestAListTooLongForAJumpIsRefused(t *testing.T) {
	p := Policy{Name: "huge"}
	for name := range sysnumAMD64 {
		p.Allow = append(p.Allow, name)
	}
	slices.Sort(p.Allow)
	_, err := Compile(AMD64, p, Kill, Params{Pid: testPid})
	if !errors.Is(err, ErrJumpTooLong) {
		t.Fatalf("got %v, want ErrJumpTooLong", err)
	}
}

func TestThePoliciesMatchTheSpec(t *testing.T) {
	emu := PolicyFor(Emu)
	proto := PolicyFor(Proto)
	extra := map[string]bool{}
	for _, n := range proto.Allow {
		extra[n] = true
	}
	for _, n := range emu.Allow {
		delete(extra, n)
	}
	want := map[string]bool{"recvfrom": true, "sendto": true, "recvmsg": true, "getrandom": true}
	if fmt.Sprint(extra) != fmt.Sprint(want) {
		t.Errorf("proto adds %v to emu's list, want %v", extra, want)
	}
	if !slices.Contains(proto.Rules, IoctlPTY) || slices.Contains(emu.Rules, IoctlPTY) {
		t.Errorf("ioctl rule: proto %v, emu %v", proto.Rules, emu.Rules)
	}
}
