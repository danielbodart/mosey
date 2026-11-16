// Package client is mosey's client, `mosey host`: it bootstraps over SSH
// (docs/spec/bootstrap.md), connects over UDP, and then runs the session,
// sending what the user types as a userinput.Stream and drawing the
// screen.Grid the server sends. `mosey localhost` is this machine:
// the same bootstrap with the server binary run directly instead of over
// ssh (bootstrap.md §2.2), and everything after it unchanged.
//
// It never parses a remote escape sequence (D9). Bytes from the network
// reach the terminal only as a Grid that screen's Apply has validated and
// render has drawn, and bytes from ssh only through bootstrap.Sanitize.
// Until the handshake is done the terminal is left cooked, for ssh's
// prompts; after it, nothing but the renderer writes to it.
//
// A client that goes away by a signal or the end of its terminal detaches:
// the session runs on, and a plain `mosey HOST` (or `-s NAME`) resumes
// it with a fresh bootstrap and handshake (D8). One that is taken over by another exits saying so
// (D26). List is `mosey -list`.
//
// It is in two parts so the session can be tested without SSH: Run does
// the bootstrap and then hands a credential and a UDP socket to Session,
// which the end-to-end tests run directly over netsim (D18).
package client
