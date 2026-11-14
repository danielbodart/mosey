// Package transport carries sealed frames between one client and one
// server over UDP, and keeps the connection alive as the network under it
// changes: it runs the handshake, seals and opens packets, refuses replays,
// rekeys, validates new paths before trusting them, and revokes a client
// that another has taken over from. docs/spec/transport.md is its
// specification.
//
// Above it, SSP sees only Send and Recv of payloads of at most MaxPayload
// bytes, and Events. Below it is any net.PacketConn: a real UDP socket, or a
// netsim socket under testing/synctest. It reads time only through the
// time package, so synctest's virtual clock drives every timer.
//
// # Packets
//
//	data: type(1)=0x04 | receiver index(4) | counter(8) | AEAD(kind(1) | body)
//
// The clear header is the AEAD's associated data and the counter is its
// nonce, under a key per direction, so a (key, nonce) pair can never repeat.
// Counters live only in memory (D8). The receive path keeps a fixed order:
// parse the header, look up the receiver index, check the replay window,
// open the AEAD, and only then commit the window, promote keys, move the
// peer address or act on the frame (D20, S1 §1.2).
//
// # Shape
//
// One engine per socket holds the lock everything on that socket happens
// under, the receiver-index table, and the datagrams to write once the lock
// is released. The server's Listener and every Conn it makes share one; a
// client's Conn has its own. A goroutine per socket reads, and a goroutine
// per Conn runs its timers (handshake and rekey resends, path challenges,
// the previous epoch's grace), so nothing waits on the network while
// holding the lock.
//
// # Rekeys (D20)
//
// Every 120 s (the server 10 s later as a backstop) or 2^60 packets, never
// on idleness, a side sends REKEY_INIT in two halves under the current
// keys; the peer answers REKEY_RESP and keeps the new keys for receiving
// until a packet under them arrives. Past RejectAfterTime without a
// completed rekey, terminal frames are held back (ErrBlocked) while the
// rekey keeps trying, so blocking only the rekey frames stalls the session
// rather than stretching one epoch without bound.
//
// # Paths (D21)
//
// The server follows the client to a new address only once the client has
// answered an encrypted PATH_CHALLENGE sent there, and the answer came from
// there (RFC 9000 §8.2, made stricter). Until then the new address gets at
// most three times the bytes that came from it (RFC 9000 §8.1), and the old
// one keeps everything. At confirmation the client's address is validated
// only if msg2 went there and nowhere else and the confirming packet came
// back from it: a round trip, as a challenge would be.
package transport
