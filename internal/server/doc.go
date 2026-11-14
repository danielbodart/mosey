// Package server is mosey-server's three roles, layout C of S4 (D22):
//
//   - spawner: tiny and unsandboxed. It reads the client's bootstrap line
//     from SSH stdin, binds the UDP socket, opens the pty and starts the
//     login shell, starts proto and emu by re-executing its own binary, hands
//     proto the socket and the pty master over SCM_RIGHTS, prints proto's
//     credential line on stdout and detaches so ssh can exit. It never reads
//     the network and never holds a key.
//   - proto: sandboxed. The keys, the UDP socket, the transport, SSP, the
//     pty master, and every protocol parser. It feeds pty output to emu and
//     keystrokes to the pty, and enforces the grammar of emu's replies.
//   - emu: sandboxed. The terminal emulator, and nothing else: no key, no
//     pty, no socket but its IPC.
//
// The process that is the parent of the shells has comm mosey-server; quoin
// relies on that name (D7, S3).
//
// Proto's logic is also callable in process, with an in-process emulator
// and any Terminal, which is how the end-to-end tests run the whole server
// on netsim without forking.
package server
