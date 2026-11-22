// Package startup is how this mosey process was started: its arguments,
// its own file, and how to start another program the same way.
//
// It is one value, made once in main by Detect and handed to everything
// that reads mosey's own file or starts a program, because on Android
// those facts are not what the operating system says they are. Termux may
// not exec a file from its own data directory, so it runs one as
// `/system/bin/linker64 PROGRAM ARGS...` (Dan's phone, 2026-11-22). The
// linker hides itself from a dynamic program, but mosey is static (D1),
// so for mosey:
//
//   - argv starts with the linker, and the client would take its own path
//     for the host;
//   - /proc/self/exe and os.Executable name the linker, not mosey, so a
//     role re-executed from it, or an upload read from it, is the linker;
//   - a program mosey starts directly (ssh, the login shell, its own
//     roles) may be refused for the same reason Termux used the linker.
//
// Detect undoes the first, Process.Path and Process.Image say where mosey
// really is, and Process.Prepare starts every program through the same
// linker. Everywhere else the zero Loader leaves all three as they were.
package startup
