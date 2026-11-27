package spawn

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// libSystem's spawn functions, called through spawn_darwin.s's
// trampolines (S4 §3.11). posix_spawnattr_setjetsam_ext is private: it is
// in libSystem but in no public header.
//
//go:cgo_import_dynamic libc_posix_spawn posix_spawn "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_posix_spawnattr_init posix_spawnattr_init "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_posix_spawnattr_destroy posix_spawnattr_destroy "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_posix_spawnattr_setflags posix_spawnattr_setflags "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_posix_spawnattr_setsigmask posix_spawnattr_setsigmask "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_posix_spawnattr_setsigdefault posix_spawnattr_setsigdefault "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_posix_spawnattr_setjetsam_ext posix_spawnattr_setjetsam_ext "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_posix_spawn_file_actions_init posix_spawn_file_actions_init "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_posix_spawn_file_actions_destroy posix_spawn_file_actions_destroy "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_posix_spawn_file_actions_adddup2 posix_spawn_file_actions_adddup2 "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_posix_spawn_file_actions_addopen posix_spawn_file_actions_addopen "/usr/lib/libSystem.B.dylib"

var (
	libc_posix_spawn_trampoline_addr                      uintptr
	libc_posix_spawnattr_init_trampoline_addr             uintptr
	libc_posix_spawnattr_destroy_trampoline_addr          uintptr
	libc_posix_spawnattr_setflags_trampoline_addr         uintptr
	libc_posix_spawnattr_setsigmask_trampoline_addr       uintptr
	libc_posix_spawnattr_setsigdefault_trampoline_addr    uintptr
	libc_posix_spawnattr_setjetsam_ext_trampoline_addr    uintptr
	libc_posix_spawn_file_actions_init_trampoline_addr    uintptr
	libc_posix_spawn_file_actions_destroy_trampoline_addr uintptr
	libc_posix_spawn_file_actions_adddup2_trampoline_addr uintptr
	libc_posix_spawn_file_actions_addopen_trampoline_addr uintptr
)

// syscall6 is the runtime's call into libc on darwin, the one
// golang.org/x/sys/unix uses: it switches to the system stack and marks
// the goroutine as in a system call.
//
//go:linkname syscall6 syscall.syscall6
func syscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)

// Flags of posix_spawnattr_setflags, from <spawn.h> in the macOS SDK.
const (
	spawnSetSigDef      = 0x0004
	spawnSetSigMask     = 0x0008
	spawnCloexecDefault = 0x4000
)

// jetsamFatal is posix_spawnattr_setjetsam_ext's flags:
// POSIX_SPAWN_JETSAM_MEMLIMIT_ACTIVE_FATAL (0x4) and
// POSIX_SPAWN_JETSAM_MEMLIMIT_INACTIVE_FATAL (0x8), so the kernel kills
// the process at the limit whether it is in the foreground or not
// [D, M: dan-mac, 2026-11-27].
const jetsamFatal = 0xC

// jetsamPriorityDefault is the priority argument that leaves the jetsam
// band as it is [D, M: dan-mac, 2026-11-27].
const jetsamPriorityDefault = ^uintptr(0) // -1

// call calls a libSystem function that returns 0 or an errno value, as
// the posix_spawn family does.
func call(fn uintptr, args ...uintptr) error {
	var a [6]uintptr
	copy(a[:], args)
	r, _, _ := syscall6(fn, a[0], a[1], a[2], a[3], a[4], a[5])
	if r != 0 {
		return syscall.Errno(r)
	}
	return nil
}

func start(a Attr) (*os.Process, error) {
	if len(a.Args) == 0 {
		return nil, errors.New("spawn: no argv[0]")
	}
	path, err := unix.BytePtrFromString(a.Path)
	if err != nil {
		return nil, err
	}
	argv, err := cstrings(a.Args)
	if err != nil {
		return nil, err
	}
	envv, err := cstrings(a.Env)
	if err != nil {
		return nil, err
	}
	devNull, _ := unix.BytePtrFromString("/dev/null")

	// Each source is duplicated above the child's fd numbers first, so no
	// dup2 into fd i can overwrite a source that a later dup2 reads. The
	// copies are close-on-exec here and closed after the spawn.
	srcs := make([]int, len(a.Files))
	for i, f := range a.Files {
		srcs[i] = -1
		if f == nil {
			continue
		}
		fd, err := dupAbove(f, len(a.Files))
		if err != nil {
			closeAll(srcs)
			return nil, fmt.Errorf("spawn: fd %d: %w", i, err)
		}
		srcs[i] = fd
	}
	defer closeAll(srcs)

	// posix_spawnattr_t and posix_spawn_file_actions_t are pointers on
	// macOS; init allocates what they point to. They are on the heap, so
	// no stack move can change their address during a call.
	attr, actions := new(uintptr), new(uintptr)
	if err := call(libc_posix_spawnattr_init_trampoline_addr, uintptr(unsafe.Pointer(attr))); err != nil {
		return nil, fmt.Errorf("spawn: posix_spawnattr_init: %w", err)
	}
	defer call(libc_posix_spawnattr_destroy_trampoline_addr, uintptr(unsafe.Pointer(attr)))
	if err := call(libc_posix_spawn_file_actions_init_trampoline_addr, uintptr(unsafe.Pointer(actions))); err != nil {
		return nil, fmt.Errorf("spawn: posix_spawn_file_actions_init: %w", err)
	}
	defer call(libc_posix_spawn_file_actions_destroy_trampoline_addr, uintptr(unsafe.Pointer(actions)))

	// CLOEXEC_DEFAULT: the child gets only the fds the file actions name.
	// SETSIGMASK with an empty mask and SETSIGDEF for every signal: the
	// child starts as exec from a fresh shell would, whatever this
	// thread's mask or an inherited SIG_IGN. SIGKILL and SIGSTOP cannot
	// be changed, so they are left out.
	mask, deflt := new(uint32), new(uint32)
	*deflt = ^uint32(0) &^ (1<<(syscall.SIGKILL-1) | 1<<(syscall.SIGSTOP-1))
	steps := []step{
		{"posix_spawnattr_setflags", libc_posix_spawnattr_setflags_trampoline_addr,
			[]uintptr{uintptr(unsafe.Pointer(attr)), spawnCloexecDefault | spawnSetSigMask | spawnSetSigDef}},
		{"posix_spawnattr_setsigmask", libc_posix_spawnattr_setsigmask_trampoline_addr,
			[]uintptr{uintptr(unsafe.Pointer(attr)), uintptr(unsafe.Pointer(mask))}},
		{"posix_spawnattr_setsigdefault", libc_posix_spawnattr_setsigdefault_trampoline_addr,
			[]uintptr{uintptr(unsafe.Pointer(attr)), uintptr(unsafe.Pointer(deflt))}},
	}
	if a.MemoryLimitMiB > 0 {
		mib := uintptr(a.MemoryLimitMiB)
		steps = append(steps, step{"posix_spawnattr_setjetsam_ext", libc_posix_spawnattr_setjetsam_ext_trampoline_addr,
			[]uintptr{uintptr(unsafe.Pointer(attr)), jetsamFatal, jetsamPriorityDefault, mib, mib}})
	}
	for i, src := range srcs {
		if src < 0 {
			steps = append(steps, step{"posix_spawn_file_actions_addopen", libc_posix_spawn_file_actions_addopen_trampoline_addr,
				[]uintptr{uintptr(unsafe.Pointer(actions)), uintptr(i), uintptr(unsafe.Pointer(devNull)), unix.O_RDWR, 0}})
		} else {
			steps = append(steps, step{"posix_spawn_file_actions_adddup2", libc_posix_spawn_file_actions_adddup2_trampoline_addr,
				[]uintptr{uintptr(unsafe.Pointer(actions)), uintptr(src), uintptr(i)}})
		}
	}
	for _, s := range steps {
		if err := call(s.fn, s.args...); err != nil {
			return nil, fmt.Errorf("spawn: %s: %w", s.name, err)
		}
	}

	pid := new(int32)
	err = call(libc_posix_spawn_trampoline_addr,
		uintptr(unsafe.Pointer(pid)), uintptr(unsafe.Pointer(path)),
		uintptr(unsafe.Pointer(actions)), uintptr(unsafe.Pointer(attr)),
		uintptr(unsafe.Pointer(&argv[0])), uintptr(unsafe.Pointer(&envv[0])))
	runtime.KeepAlive(path)
	runtime.KeepAlive(argv)
	runtime.KeepAlive(envv)
	runtime.KeepAlive(devNull)
	runtime.KeepAlive(mask)
	runtime.KeepAlive(deflt)
	if err != nil {
		return nil, fmt.Errorf("spawn: posix_spawn %s: %w", a.Path, err)
	}
	return os.FindProcess(int(*pid))
}

// step is one libSystem call that sets up the spawn.
type step struct {
	name string
	fn   uintptr
	args []uintptr
}

// dupAbove duplicates f's fd to the lowest free fd at or above min,
// close-on-exec, in blocking mode. It goes through SyscallConn, not Fd,
// which would put f itself in blocking mode.
func dupAbove(f *os.File, min int) (int, error) {
	raw, err := f.SyscallConn()
	if err != nil {
		return -1, err
	}
	fd := -1
	var derr error
	if err := raw.Control(func(x uintptr) {
		fd, derr = unix.FcntlInt(x, unix.F_DUPFD_CLOEXEC, min)
	}); err != nil {
		return -1, err
	}
	if derr != nil {
		return -1, derr
	}
	// The flag is on the open file description, which f shares; the
	// caller hands f to the child and closes its own copy, as os/exec's
	// callers do.
	if err := unix.SetNonblock(fd, false); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// cstrings is ss as a NULL-terminated array of C strings, as execve
// takes argv and envp.
func cstrings(ss []string) ([]*byte, error) {
	out := make([]*byte, len(ss)+1)
	for i, s := range ss {
		p, err := unix.BytePtrFromString(s)
		if err != nil {
			return nil, err
		}
		out[i] = p
	}
	return out, nil
}

func closeAll(fds []int) {
	for _, fd := range fds {
		if fd >= 0 {
			unix.Close(fd)
		}
	}
}
