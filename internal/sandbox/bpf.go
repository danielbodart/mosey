package sandbox

// Arch is a seccomp audit architecture the compiler can target, so the
// filter for each architecture is built and tested on any host.
type Arch uint8

const (
	AMD64 Arch = iota + 1
	ARM64
)

// Instruction is one cBPF instruction, as struct sock_filter lays it out.
// It is the package's own type so the compiler and its interpreter test run
// on systems without seccomp.
type Instruction struct {
	Code   uint16
	JT, JF uint8
	K      uint32
}

// Policy is a role's allow-list: syscall names, resolved per architecture.
type Policy struct {
	Name     string
	Syscalls []string
}

// PolicyFor is role's allow-list: the Go runtime's set plus the role's own.
func PolicyFor(role Role) Policy {
	panic("TODO slice 1")
}

// Compile turns p into a filter for arch. The filter checks the audit
// architecture first and refuses x32 on amd64, allows clone only with
// CLONE_THREAD, answers clone3 with ENOSYS and prctl with EINVAL so the
// runtime falls back gracefully, allows p's syscalls, and applies action to
// the rest.
func Compile(arch Arch, p Policy, action Action) ([]Instruction, error) {
	panic("TODO slice 1")
}
