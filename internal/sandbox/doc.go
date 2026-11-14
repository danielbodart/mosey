// Package sandbox confines the proto and emu roles (D22): Landlock with
// nothing allowed, a seccomp allow-list per role, installed on every thread
// with TSYNC, and PR_SET_DUMPABLE=0 so no other process of the user's can
// ptrace or read them, and a seccomp kill leaves no core holding a key.
//
// Be honest about what this buys (S4 §1). proto holds the pty master and
// the keys, so a compromised proto is the user whatever the sandbox does;
// for proto this is defence in depth against logic bugs. emu holds no key
// and no pty, and types into the shell only through a reply grammar proto
// enforces, so for emu the sandbox really contains an attacker. That is
// where the effort goes: emu cannot open, connect, exec, or signal another
// process, on any kernel, with or without Landlock (server.md §1.2, §6.3).
//
// The seccomp filter is cBPF, compiled here from a list of syscall names
// and a few argument rules (clone only for threads, tgkill only at itself,
// fcntl only with commands that cannot arm a signal, and for proto ioctl
// only on its pty master). There is no library to depend on (D19), and the
// compiler is checked by a small BPF interpreter in its tests, for amd64
// and arm64, on any host. The allow-lists are S4's traces of the real
// roles under load (server.md §6.3).
//
// Landlock is used through golang.org/x/sys/unix directly, with no
// go-landlock dependency (S4 §1.5). Linux-only mechanisms sit behind Enter;
// on other systems it says errors.ErrUnsupported (D22: macOS is parked, not
// ruled out).
package sandbox
