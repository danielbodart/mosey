package pty

import (
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// macOS has no /proc (server.md §10). The name comes from sysctl
// kern.procargs2, the arguments the process runs with, and the directory
// from proc_pidinfo(PROC_PIDVNODEPATHINFO) in libproc. Both work for the
// user's own processes. For another user's process, or one that is gone,
// both fail [M] on dan-mac, 2026-11-27: the name is then p_comm from
// kinfo_proc, which any user can read, and the directory is "".
//
// mosey is built with CGO_ENABLED=0 (D1), so proc_pidinfo is reached as
// internal/sandbox reaches sandbox_init: a dynamic import from libSystem,
// and an assembly trampoline (program_darwin.s) that syscall6 calls on
// the system stack.

//go:cgo_import_dynamic libproc_pidinfo proc_pidinfo "/usr/lib/libSystem.B.dylib"

var libproc_pidinfo_trampoline_addr uintptr

// syscall6 is declared as internal/spawn declares it, with the types of
// syscall.syscall6 itself. Each package declares it, and there is no one
// shared wrapper: a Go wrapper could grow the stack between a
// uintptr(unsafe.Pointer(&x)) and the call, and the uintptr would then
// point at the old stack. syscall.syscall6 is nosplit (Go 1.27), so a
// direct call cannot.
//
//go:linkname syscall6 syscall.syscall6
func syscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)

// procPIDVnodePathInfo is PROC_PIDVNODEPATHINFO (sys/proc_info.h).
const procPIDVnodePathInfo = 9

func programOf(pid int) Program {
	var p Program
	if b, err := unix.SysctlRaw("kern.procargs2", pid); err == nil {
		if a, ok := procArgsArgv0(b); ok {
			p.Name = argv0Name(a)
		}
	}
	if p.Name == "" {
		// A zombie has no arguments; its kinfo_proc still has p_comm, as
		// Linux's comm stands in for an empty cmdline.
		if k, err := unix.SysctlKinfoProc("kern.proc.pid", pid); err == nil && int(k.Proc.P_pid) == pid {
			p.Name = cString(k.Proc.P_comm[:])
		}
	}
	p.Dir = processCwd(pid)
	return p
}

// processCwd calls proc_pidinfo, which returns the number of bytes it
// filled, and 0 on failure.
func processCwd(pid int) string {
	b := make([]byte, vnodePathInfoSize)
	r, _, _ := syscall6(libproc_pidinfo_trampoline_addr,
		uintptr(pid), procPIDVnodePathInfo, 0, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0)
	runtime.KeepAlive(b)
	return vnodePathCwd(b, int(int32(r)))
}

// cString is the bytes of c before its first NUL.
func cString(c []byte) string {
	for i, v := range c {
		if v == 0 {
			return string(c[:i])
		}
	}
	return string(c)
}
