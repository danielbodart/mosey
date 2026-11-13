// Package seatbelt is a compile-only probe: can a CGO_ENABLED=0 Go binary
// call macOS's sandbox_init(3) (Seatbelt) the way golang.org/x/sys/unix
// calls libSystem, i.e. via //go:cgo_import_dynamic and an assembly
// trampoline? The spike machine is Linux; this was cross-compiled
// (GOOS=darwin GOARCH=arm64|amd64 CGO_ENABLED=0) but never run.
package seatbelt

import (
	"errors"
	"unsafe"
)

//go:cgo_import_dynamic libsb_sandbox_init sandbox_init "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libsb_sandbox_free_error sandbox_free_error "/usr/lib/libSystem.B.dylib"

var libsb_sandbox_init_trampoline_addr uintptr
var libsb_sandbox_free_error_trampoline_addr uintptr

//go:linkname syscall_syscall syscall.syscall
func syscall_syscall(fn, a1, a2, a3 uintptr) (r1, r2 uintptr, err uintptr)

// SANDBOX_NAMED: profile is the name of a built-in profile.
const sandboxNamed = 0x0001

// PureComputation is kSBXProfilePureComputation: no file system, no
// network, no IPC lookups; already-open descriptors keep working. It is what
// OpenSSH's sandbox-darwin uses for its pre-auth child.
const PureComputation = "pure-computation"

// Init applies a named built-in profile to the calling process (all
// threads; irreversible; inherited by children).
func Init(profile string) error {
	p := append([]byte(profile), 0)
	var errbuf *byte
	r, _, _ := syscall_syscall(libsb_sandbox_init_trampoline_addr,
		uintptr(unsafe.Pointer(&p[0])), sandboxNamed, uintptr(unsafe.Pointer(&errbuf)))
	if r != 0 {
		msg := "sandbox_init failed"
		if errbuf != nil {
			var b []byte
			for q := unsafe.Pointer(errbuf); *(*byte)(q) != 0; q = unsafe.Add(q, 1) {
				b = append(b, *(*byte)(q))
			}
			msg += ": " + string(b)
			syscall_syscall(libsb_sandbox_free_error_trampoline_addr, uintptr(unsafe.Pointer(errbuf)), 0, 0)
		}
		return errors.New(msg)
	}
	return nil
}
