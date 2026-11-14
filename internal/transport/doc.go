// Package transport carries sealed frames between one client and one
// server over UDP, and keeps the connection alive as the network under it
// changes: it runs the handshake, seals and opens packets, refuses replays,
// rekeys, validates new paths before trusting them, and revokes a client
// that another has taken over from.
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
// # Paths (D21)
//
// The server follows the client to a new address only once the client has
// answered an encrypted PATH_CHALLENGE sent there (RFC 9000 §8.2). Until
// then the new address gets at most three times the bytes that came from it
// (RFC 9000 §8.1), and the old one keeps everything else. The address msg1
// came from is validated by the first transport packet, since its keys
// depend on msg2, which went only there.
package transport

import "github.com/danielbodart/mosey/internal/wire"

// Overhead is what the transport adds to a payload: a 13-byte clear header
// (type, receiver index, counter), the 1-byte frame kind and the 16-byte
// Poly1305 tag.
const Overhead = 13 + 1 + 16

// MaxPayload is the largest payload Send accepts: what is left of a
// datagram (D5) once the transport has framed and sealed it.
const MaxPayload = wire.MaxDatagram - Overhead
