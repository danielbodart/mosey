// Package wire holds the size limits every layer of the protocol is built
// to, so that each layer checks against the same numbers rather than its
// own copy of them.
//
// The limits come from D5. A UDP payload of 1232 bytes is the largest that
// every IPv6 path must carry (the 1280-byte minimum MTU of RFC 8200, less a
// 40-byte IPv6 header and an 8-byte UDP header), and it fits inside a
// WireGuard tunnel with an MTU of 1280. Handshake and rekey messages are
// held to 1200 bytes, QUIC's floor (RFC 9000 §14), so that DPLPMTUD
// (RFC 8899, O9) can be added later with a 1200-byte base and no change on
// the wire.
package wire
