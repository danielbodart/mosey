package sandbox

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// macOS confines a role with Seatbelt: sandbox_init(3) with our own SBPL
// profile and flags 0 (server.md §10 [D]). sandbox_init is deprecated but
// works on macOS 15 [M]. If Apple stops it, the fallback is the private
// sandbox_compile_string and sandbox_apply.
//
// mosey is built with CGO_ENABLED=0 (D1), so sandbox_init is reached the
// way golang.org/x/sys/unix reaches libSystem: a dynamic import, and an
// assembly trampoline (sandbox_darwin.s) that syscall.syscall calls on the
// system stack. S4 §3.11 found the pattern; this is a clean rewrite.

//go:cgo_import_dynamic libsandbox_init sandbox_init "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libsandbox_free_error sandbox_free_error "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libsandbox_check sandbox_check "/usr/lib/libSystem.B.dylib"

var libsandbox_init_trampoline_addr uintptr
var libsandbox_free_error_trampoline_addr uintptr
var libsandbox_check_trampoline_addr uintptr

//go:linkname syscall_syscall syscall.syscall
func syscall_syscall(fn, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno)

func enter(role Role, _ Action, params Params, _ func(string)) error {
	// Built first, so a bad port costs nothing half applied.
	profile, err := Profile(role, params)
	if err != nil {
		return err
	}
	// In place of PR_SET_DUMPABLE: no other process of the user's may
	// attach a debugger to read the keys (threat-model.md §4.10). Before
	// sandbox_init, which may deny ptrace.
	if err := unix.PtraceDenyAttach(); err != nil {
		return fmt.Errorf("ptrace(PT_DENY_ATTACH): %w", err)
	}
	if err := sandboxInit(profile); err != nil {
		return fmt.Errorf("sandbox_init(%s profile): %w", role, err)
	}
	return nil
}

// sandboxInit applies the SBPL text profile to the whole process, for
// good. Flags 0 says the text is a profile, not the name of a built-in
// one.
func sandboxInit(profile string) error {
	text := append([]byte(profile), 0)
	var errbuf *byte
	r, _, _ := syscall_syscall(libsandbox_init_trampoline_addr,
		uintptr(unsafe.Pointer(&text[0])), 0, uintptr(unsafe.Pointer(&errbuf)))
	runtime.KeepAlive(text)
	if r == 0 {
		return nil
	}
	if errbuf == nil {
		return errors.New("failed, with no reason given")
	}
	msg := cString(errbuf)
	syscall_syscall(libsandbox_free_error_trampoline_addr, uintptr(unsafe.Pointer(errbuf)), 0, 0)
	return errors.New(msg)
}

// cString copies the NUL-terminated C string at p, at most 4 KiB of it:
// sandbox_init's error text is a line or two.
func cString(p *byte) string {
	var b []byte
	for q := unsafe.Pointer(p); len(b) < 4096 && *(*byte)(q) != 0; q = unsafe.Add(q, 1) {
		b = append(b, *(*byte)(q))
	}
	return string(b)
}

// sandboxed says whether process pid runs under a Seatbelt profile:
// sandbox_check with no operation and SANDBOX_FILTER_NONE (0) is 1 for a
// sandboxed process. It passes no variadic argument, so the call is the
// same on amd64 and arm64. For tests, here and on a live session.
func sandboxed(pid int) bool {
	r, _, _ := syscall_syscall(libsandbox_check_trampoline_addr, uintptr(pid), 0, 0)
	return int32(r) == 1
}
