package sandbox

import (
	"fmt"
	"sort"

	"golang.org/x/sys/unix"
)

// Classic BPF opcodes (linux/filter.h, linux/bpf_common.h). Hand-assembled:
// the program is a flat allow-list plus two argument checks, which is small
// enough that pulling in golang.org/x/net/bpf's assembler buys nothing.
const (
	bpfLD  = 0x00
	bpfJMP = 0x05
	bpfRET = 0x06
	bpfW   = 0x00
	bpfABS = 0x20
	bpfJEQ = 0x10
	bpfJGE = 0x30
	bpfJSET = 0x40
	bpfK   = 0x00

	// offsets into struct seccomp_data
	offNr   = 0
	offArch = 4
	offArg0 = 16 // args[0] low 32 bits on little-endian (amd64, arm64)

	x32SyscallBit = 0x40000000
	cloneThread   = 0x00010000 // CLONE_THREAD
)

// Action is a seccomp return value.
type Action uint32

const (
	KillProcess Action = unix.SECCOMP_RET_KILL_PROCESS
	Allow       Action = unix.SECCOMP_RET_ALLOW
	Log         Action = unix.SECCOMP_RET_LOG
)

// Errno returns SECCOMP_RET_ERRNO with the given errno.
func Errno(e unix.Errno) Action { return Action(unix.SECCOMP_RET_ERRNO | (uint32(e) & unix.SECCOMP_RET_DATA)) }

// Arch is a target architecture for the filter.
type Arch struct {
	Name      string
	AuditArch uint32
	nums      map[string]uint32
	// x32 ABI shares AUDIT_ARCH_X86_64 and sets bit 30 of nr; must be refused.
	hasX32 bool
}

var (
	AMD64 = Arch{"amd64", unix.AUDIT_ARCH_X86_64, sysnums_amd64, true}
	ARM64 = Arch{"arm64", unix.AUDIT_ARCH_AARCH64, sysnums_arm64, false}
)

// Num returns a syscall's number on this arch.
func (a Arch) Num(name string) (uint32, bool) { n, ok := a.nums[name]; return n, ok }

// Policy is a seccomp allow-list policy, arch-independent by name.
type Policy struct {
	Name string
	// Allow lists syscalls allowed unconditionally. Names absent on an arch
	// (e.g. "open" on arm64) are skipped and reported by Program.
	Allow []string
	// Fail lists syscalls that fail with a chosen errno rather than hit
	// Default, because the Go runtime probes them and degrades gracefully:
	// clone3 -> ENOSYS (fall back to clone), prctl -> EINVAL (Go >= 1.25's
	// decoratemappings calls prctl(PR_SET_VMA) after mmaps and permanently
	// stops on EINVAL; KILL here would crash any kernel with
	// CONFIG_ANON_VMA_NAME=y).
	Fail map[string]unix.Errno
	// CloneThreadOnly allows clone(2) only with CLONE_THREAD set, i.e.
	// new threads but never new processes (no fork/vfork, no exec path).
	CloneThreadOnly bool
	Default         Action
}

func stmt(code uint16, k uint32) unix.SockFilter { return unix.SockFilter{Code: code, K: k} }
func jump(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}

// Program compiles p for arch a. missing lists names p uses that don't exist on a.
func Program(a Arch, p Policy) (prog []unix.SockFilter, missing []string, err error) {
	type entry struct {
		nr  uint32
		act uint32 // Allow, or ENOSYS errno
	}
	var allow []entry
	seen := map[uint32]bool{}
	add := func(name string, act uint32) {
		nr, ok := a.nums[name]
		if !ok {
			missing = append(missing, name)
			return
		}
		if seen[nr] {
			return
		}
		seen[nr] = true
		allow = append(allow, entry{nr, act})
	}
	for _, n := range p.Allow {
		add(n, uint32(Allow))
	}
	failNames := make([]string, 0, len(p.Fail))
	for n := range p.Fail {
		failNames = append(failNames, n)
	}
	sort.Strings(failNames)
	for _, n := range failNames {
		add(n, uint32(Errno(p.Fail[n])))
	}
	sort.Slice(allow, func(i, j int) bool { return allow[i].nr < allow[j].nr })

	// Prologue: refuse other arches (and x32), load nr.
	prog = append(prog,
		stmt(bpfLD|bpfW|bpfABS, offArch),
		jump(bpfJMP|bpfJEQ|bpfK, a.AuditArch, 1, 0),
		stmt(bpfRET|bpfK, uint32(KillProcess)),
		stmt(bpfLD|bpfW|bpfABS, offNr),
	)
	if a.hasX32 {
		prog = append(prog,
			jump(bpfJMP|bpfJGE|bpfK, x32SyscallBit, 0, 1),
			stmt(bpfRET|bpfK, uint32(KillProcess)),
		)
	}
	// clone: allowed iff CLONE_THREAD. Layout:
	//   jeq clone, 0, 3
	//   ld arg0
	//   jset CLONE_THREAD, 0, 1   (true: fall to ret allow; false: skip 1)
	//   ret ALLOW
	//   ret DEFAULT
	//   ld nr                     (reload for the list below)
	// The "not clone" path must skip ld/jset/ret/ret and land on the reload.
	if p.CloneThreadOnly {
		nr, ok := a.nums["clone"]
		if !ok {
			return nil, nil, fmt.Errorf("no clone on %s", a.Name)
		}
		prog = append(prog,
			jump(bpfJMP|bpfJEQ|bpfK, nr, 0, 4),
			stmt(bpfLD|bpfW|bpfABS, offArg0),
			jump(bpfJMP|bpfJSET|bpfK, cloneThread, 0, 1),
			stmt(bpfRET|bpfK, uint32(Allow)),
			stmt(bpfRET|bpfK, uint32(p.Default)),
			stmt(bpfLD|bpfW|bpfABS, offNr),
		)
	}
	// One jeq per syscall, each jumping to its return. Returns are grouped
	// at the end: [default][allow][each distinct errno action...].
	rets := []uint32{uint32(p.Default), uint32(Allow)}
	retIdx := map[uint32]int{uint32(Allow): 1}
	for _, e := range allow {
		if _, ok := retIdx[e.act]; !ok {
			retIdx[e.act] = len(rets)
			rets = append(rets, e.act)
		}
	}
	n := len(allow)
	if n+len(rets) > 255 {
		return nil, nil, fmt.Errorf("too many syscalls for 8-bit jumps: %d", n)
	}
	for i, e := range allow {
		rest := n - i - 1 // jeqs after this one
		prog = append(prog, jump(bpfJMP|bpfJEQ|bpfK, e.nr, uint8(rest+retIdx[e.act]), 0))
	}
	for _, r := range rets {
		prog = append(prog, stmt(bpfRET|bpfK, r))
	}
	return prog, missing, nil
}
