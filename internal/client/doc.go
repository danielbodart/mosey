// Package client is mosey's client, `mosey host`: it bootstraps over SSH
// (docs/spec/bootstrap.md), connects over UDP, and then runs the session,
// sending what the user types as a userinput.Stream and drawing the
// screen.Grid the server sends.
//
// It never parses a remote escape sequence (D9). Bytes from the network
// reach the terminal only as a Grid that screen's Apply has validated and
// render has drawn, and bytes from ssh only through bootstrap.Sanitize.
// Until the handshake is done the terminal is left cooked, for ssh's
// prompts; after it, nothing but the renderer writes to it.
//
// It is in two parts so the session can be tested without SSH: Run does
// the bootstrap and then hands a credential and a UDP socket to Session,
// which the end-to-end tests run directly over netsim (D18).
package client
