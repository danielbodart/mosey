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
// time package's, so testing/synctest drives them. The one fact about
// addresses it is given is Config.Local, whether the peer is on loopback,
// which drops D11's network timing and the client's chaff (§6.2.1).
//
// Every payload SSP sees has been authenticated, so a malformed one comes
// from a peer that holds the keys and is broken or hostile. SSP does not
// drop it and wait for a retransmission that would fail the same way: Run
// ends with an error wrapping ErrProtocol. What a hostile peer can make an
// endpoint hold is bounded throughout: at most Window+1 versions each way,
// MaxPartials instructions under reassembly, and a decompressed diff of at
// most Config.MaxRemoteBytes.
//
// The files follow the spec: wire.go is the datagram and instruction
// formats (§3, §4), compress.go compression (§4.1), reassembly.go
// fragments (§5), timing.go the D11 timers and the RTT estimator (§6.2,
// §7.1), chaff.go the chaff schedule that hides keystroke timing (§9.1),
// and endpoint.go the sender and receiver (§6, §7).
package ssp
