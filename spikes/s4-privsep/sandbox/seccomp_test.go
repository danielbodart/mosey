package sandbox

import (
	"testing"

	"golang.org/x/sys/unix"
)

// run interprets the subset of classic BPF Program emits.
func run(t *testing.T, prog []unix.SockFilter, arch, nr uint32, arg0 uint64) uint32 {
	t.Helper()
	data := map[uint32]uint32{offNr: nr, offArch: arch, offArg0: uint32(arg0), offArg0 + 4: uint32(arg0 >> 32)}
	var A uint32
	for pc := 0; pc < len(prog); pc++ {
		in := prog[pc]
		switch in.Code {
		case bpfLD | bpfW | bpfABS:
			A = data[in.K]
		case bpfJMP | bpfJEQ | bpfK:
			if A == in.K {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case bpfJMP | bpfJGE | bpfK:
			if A >= in.K {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case bpfJMP | bpfJSET | bpfK:
			if A&in.K != 0 {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case bpfRET | bpfK:
			return in.K
		default:
			t.Fatalf("unknown op %#x at %d", in.Code, pc)
		}
	}
	t.Fatal("fell off the end")
	return 0
}

func TestNetPolicy(t *testing.T) {
	for _, a := range []Arch{AMD64, ARM64} {
		p := NetPolicy(KillProcess)
		prog, missing, err := Program(a, p)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: %d insns, skipped %v", a.Name, len(prog), missing)
		num := func(n string) uint32 {
			v, ok := a.Num(n)
			if !ok {
				t.Fatalf("%s has no %s", a.Name, n)
			}
			return v
		}
		check := func(name string, arg0 uint64, want uint32) {
			if got := run(t, prog, a.AuditArch, num(name), arg0); got != want {
				t.Errorf("%s %s(%#x) = %#x want %#x", a.Name, name, arg0, got, want)
			}
		}
		for _, n := range []string{"futex", "read", "write", "recvfrom", "sendto", "mmap", "rt_sigreturn", "pread64"} {
			check(n, 0, uint32(Allow))
		}
		for _, n := range []string{"socket", "connect", "openat", "execve", "ptrace", "io_uring_setup", "process_vm_readv", "pidfd_getfd", "kill", "ioctl", "unshare", "bind", "recvmsg", "sendmsg", "mprotect", "getrandom"} {
			check(n, 0, uint32(KillProcess))
		}
		check("clone3", 0, uint32(Errno(unix.ENOSYS)))
		check("prctl", unix.PR_SET_VMA, uint32(Errno(unix.EINVAL)))
		check("clone", unix.CLONE_VM|unix.CLONE_FS|unix.CLONE_FILES|unix.CLONE_SIGHAND|unix.CLONE_SYSVSEM|unix.CLONE_THREAD, uint32(Allow))
		check("clone", unix.CLONE_VM|unix.CLONE_VFORK|uint64(unix.SIGCHLD), uint32(KillProcess)) // Go's fork+exec
		check("clone", uint64(unix.SIGCHLD), uint32(KillProcess))                                // fork
		// wrong arch
		other := ARM64
		if a.Name == "arm64" {
			other = AMD64
		}
		if got := run(t, prog, other.AuditArch, num("read"), 0); got != uint32(KillProcess) {
			t.Errorf("%s: foreign arch not killed", a.Name)
		}
		if a.hasX32 {
			if got := run(t, prog, a.AuditArch, num("read")|x32SyscallBit, 0); got != uint32(KillProcess) {
				t.Errorf("x32 read not killed")
			}
		}
	}
}
