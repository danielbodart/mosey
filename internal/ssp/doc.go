// Package ssp is the State Synchronization Protocol: each side owns an
// object and keeps a copy of the other's, and SSP keeps the copies up to
// date over a lossy, reordering datagram path by sending, at a rate the
// path can bear, the diff from the newest version the peer has
// acknowledged to the newest it has. The client's object is what the user
// typed; the server's is the screen (Mosh paper, Winstein & Balakrishnan,
// USENIX ATC 2012, §2).
//
// It is written from docs/spec/ssp.md, which is in our own words from the
// paper, RFCs and black-box measurement, with every constant cited there
// (PLAN §4). No Mosh source is read, here or anywhere.
//
// SSP knows nothing of keys or addresses: it sends and receives payloads
// through a Datagrams, which the transport provides in production and a
// plain netsim socket can provide in SSP's own tests. Its timers are the
// time package's, so testing/synctest drives them.
package ssp
