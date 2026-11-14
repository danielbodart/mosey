// Package sandbox confines the proto and emu roles (D22): Landlock with
// nothing allowed on the filesystem, a seccomp allow-list per role,
// installed on every thread with TSYNC, and PR_SET_DUMPABLE=0 so no other
// process of the user's can ptrace or read them.
//
// Be honest about what this buys (S4 §1). proto holds the pty master and
// the keys, so a compromised proto is the user whatever the sandbox does;
// for proto this is defence in depth against logic bugs. The emu process
// holds no key and no pty, and types into the shell only through a reply
// grammar proto enforces, so for emu the sandbox really contains an
// attacker. That is where the effort goes.
//
// The seccomp filter is cBPF, compiled here from a list of syscalls: there
// is no library to depend on (D19), and the compiler is checked by a small
// BPF interpreter in its tests, on every architecture, on any host. The
// allow-lists come from S4's traces of the real roles under load, plus the
// exceptions it explains (exit, pread64 under a CPU quota).
//
// Landlock is used through golang.org/x/sys/unix directly, about 150 lines,
// with no go-landlock dependency (S4 §1.5). Linux-only mechanisms sit
// behind Enter; on other systems it says ErrUnsupported, and the caller
// decides whether that is fatal (D22: macOS is parked, not ruled out).
package sandbox
