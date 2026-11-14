package sandbox

import (
	"testing"
)

// reference is what a role's filter must decide, in plain Go, written from
// server.md §6.3 rather than from the compiler, so the fuzzer can hold one
// against the other.
func reference(arch Arch, role Role, action Action, c call) uint32 {
	if c.arch != arch.audit() {
		return retKillProcess
	}
	if arch == AMD64 && c.nr >= x32Bit {
		return retKillProcess
	}
	name := ""
	table := sysnumAMD64
	if arch == ARM64 {
		table = sysnumARM64
	}
	for n, nr := range table {
		if nr == c.nr {
			name = n
			break
		}
	}
	low := func(i int) uint32 { return uint32(c.args[i]) }
	allowIf := func(ok bool) uint32 {
		if ok {
			return retAllow
		}
		return action.ret()
	}
	switch name {
	case "clone":
		return allowIf(low(0)&cloneThread != 0)
	case "tgkill":
		return allowIf(low(0) == testPid)
	case "fcntl":
		switch low(1) {
		case fGetFD, fSetFD, fGetFL, fDupFDCloexec:
			return retAllow
		case fSetFL:
			return allowIf(low(2)&oAsync == 0)
		}
		return action.ret()
	case "ioctl":
		if role != Proto {
			return action.ret()
		}
		return allowIf(low(0) == testPTY && (low(1) == ioctlTCGETS || low(1) == ioctlTIOCSWIN))
	case "clone3":
		return retErrno | errnoENOSYS
	case "prctl":
		return retErrno | errnoEINVAL
	}
	for _, n := range PolicyFor(role).Allow {
		if n == name {
			return retAllow
		}
	}
	return action.ret()
}

func FuzzCompile(f *testing.F) {
	f.Add(uint8(0), uint8(0), uint8(0), uint32(0), uint64(0), uint64(0), uint64(0), false)
	f.Add(uint8(0), uint8(1), uint8(1), uint32(16), uint64(testPTY), uint64(ioctlTIOCSWIN), uint64(0), false)
	f.Add(uint8(1), uint8(0), uint8(0), uint32(25), uint64(3), uint64(fSetFL), uint64(oAsync), false)
	f.Add(uint8(0), uint8(1), uint8(0), uint32(234), uint64(testPid), uint64(1), uint64(9), false)
	f.Add(uint8(0), uint8(1), uint8(0), uint32(56), uint64(cloneThread), uint64(0), uint64(0), false)
	f.Fuzz(func(t *testing.T, archSel, roleSel, actionSel uint8, nr uint32, a0, a1, a2 uint64, foreign bool) {
		arch := arches[int(archSel)%len(arches)]
		role := []Role{Proto, Emu}[int(roleSel)%2]
		action := []Action{Kill, Errno, Log}[int(actionSel)%3]
		prog, err := Compile(arch, PolicyFor(role), action, Params{PTY: testPTY, Pid: testPid})
		if err != nil {
			t.Fatal(err)
		}
		// Mostly real syscall numbers, so the rules are reached.
		if nr < 0x40000000 {
			nr %= 512
		}
		c := call{arch: arch.audit(), nr: nr, args: [6]uint64{a0, a1, a2, a0 ^ a1, a1 ^ a2, a2 ^ a0}}
		if foreign {
			c.arch = uint32(a0)
		}
		got, err := interpret(prog, c)
		if err != nil {
			t.Fatal(err)
		}
		if want := reference(arch, role, action, c); got != want {
			t.Fatalf("%s %s %s nr %d args %x: filter %#x, reference %#x", arch, role, action, nr, c.args[:3], got, want)
		}
	})
}
