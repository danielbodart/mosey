// Package hostname is the one rule for the host name a client claims for
// itself when it attaches (bootstrap.md §6.2's host, §9.2.1's peer-host,
// transport.md §8.3's REVOKED name), and for a host in MOSEY_FROM
// (bootstrap.md §9.2.4).
//
// It is a package of its own, with nothing but the standard library under
// it, because the claim crosses layers that may not import each other
// (architecture.md "Imports"): the bootstrap lines, the IPC messages
// between the server's roles, and the transport's REVOKED frame. Each
// checks the claim with the same function, so a name one accepts is a
// name every other accepts.
//
// A claimed name is only a claim: the client says what it is called, and
// nothing checks it. The address beside it is an observation. So the name
// is never shown without the address (Label), and an invalid name is
// dropped, never fatal: it degrades to the address alone.
package hostname
