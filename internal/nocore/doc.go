// Package nocore keeps a process that holds a secret from leaving it in a
// core dump, or in reach of the user's other processes (threat-model.md
// §4.10, B8).
//
// A crash of a process holding keys (a panic under GOTRACEBACK=crash, a
// runtime abort, a seccomp SIGSYS) would otherwise write them where the
// user, and anyone who later steals the user's machine, can read them, and
// recorded traffic from past epochs would then decrypt: exactly what D8
// rules out. S4 measured it: with DUMPABLE at 1 a SIGSYS left two core
// dumps behind, with 0 none [S4 §3.5].
//
// It is its own package, not part of internal/sandbox, because the client
// needs it too, and the client never imports the server's sandbox
// (architecture.md §1). There are two calls, because the processes differ
// in what their children inherit:
//
//   - Process, for the client, proto and emu: DUMPABLE 0 and RLIMIT_CORE 0.
//     Their only children are ssh (the client's, which loses nothing by
//     inheriting the rlimit) and none at all.
//   - NotDumpable, for the launcher and the spawner: DUMPABLE 0 only. An
//     rlimit is inherited across exec, and the login shell the spawner
//     starts must keep the user's own core-dump settings; DUMPABLE is reset
//     by execve, so the shell is untouched by it.
//
// Linux has prctl(PR_SET_DUMPABLE). darwin has only the rlimit, which is
// all Process does there; the server does not run on darwin yet (D22), so
// NotDumpable says errors.ErrUnsupported.
package nocore
