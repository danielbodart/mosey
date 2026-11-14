// Package channel is mosey's reliable, flow-controlled byte streams over
// the transport's CHANNEL frames (D15; docs/spec/agent.md §5): what the
// agent channel (D25) rides on, and what port forwarding will.
//
// SSP is the wrong tool here (ssp.md §1.2): it synchronises the newest
// state of one object, while an agent connection is a byte stream in which
// every byte matters and arrives in order. So this is a small stream
// protocol of its own, modelled on TCP's sequence numbers and windows (RFC
// 9293), RFC 6298's retransmission timer, and QUIC's stream ids (RFC 9000
// §2.1), and kept as simple as agent traffic allows: requests and answers
// of a few hundred bytes to a few KiB, rarely more than one in flight. Out
// of order data is dropped rather than reassembled; the sender goes back
// to its oldest unacknowledged byte on a timeout.
//
// A Mux runs the streams of one connection. It takes a Datagrams, which
// *transport.Conn satisfies with SendChannel and RecvChannel, and never
// imports transport (architecture.md §1). ParseFrame is the one parser of
// what the peer sends; it is strict, canonical and fuzzed, and a frame it
// refuses changes no stream.
package channel
