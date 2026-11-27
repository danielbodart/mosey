// Package spawn starts a process with posix_spawn(2) and a memory limit
// that the kernel enforces. It is for the spawner on macOS, which starts
// emu this way (D23, server.md §10).
//
// Linux bounds emu with RLIMIT_DATA and a cgroup, and the spawner starts
// it with os/exec. macOS has neither: setrlimit of RLIMIT_DATA or
// RLIMIT_AS below 1 TiB gives EINVAL [M]. What macOS has is the jetsam
// memory limit, which posix_spawn sets for the new process through the
// private posix_spawnattr_setjetsam_ext. Dan chose it on 2026-11-27 [D]:
// private or deprecated APIs are acceptable when they are clearly better,
// and when Apple breaks one, mosey changes then. os/exec cannot pass a
// spawn attribute, so this package calls posix_spawn itself.
//
// The binary stays CGO_ENABLED=0 (D1). The libc functions are reached as
// golang.org/x/sys/unix reaches libSystem: //go:cgo_import_dynamic, an
// assembly trampoline, and the runtime's syscall.syscall6 (S4 §3.11).
//
// Only the darwin build has a Start that works. Elsewhere it gives
// errors.ErrUnsupported.
package spawn
