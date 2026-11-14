package transport

// Kind is the type of a frame inside a sealed packet. A receiver ignores
// kinds it does not know, so later slices can add frames without breaking
// an older peer.
type Kind uint8

const (
	// KindTerminal carries the terminal channel's SSP datagrams: the only
	// payloads Send and Recv deal in.
	KindTerminal Kind = 0x00
	// KindRekeyInit1 and KindRekeyInit2 are the two halves of REKEY_INIT
	// (D20): the new X-Wing public key does not fit in one.
	KindRekeyInit1 Kind = 0x01
	KindRekeyInit2 Kind = 0x02
	KindRekeyResp  Kind = 0x03
	// KindKeepalive with body 1 asks for an answer, which is one keepalive
	// with body 0 under the receiver's current keys. It confirms the
	// handshake (transport.md §3.9) and a rekey, so an idle responder still
	// confirms (S1 §1.3), and announces a local address change (§7.4). Body
	// 0 is never answered, so it amplifies nothing.
	KindKeepalive Kind = 0x04
	// KindPathChallenge and KindPathResponse validate a new path (D21).
	KindPathChallenge Kind = 0x05
	KindPathResponse  Kind = 0x06

	// Reserved for later slices, so no one else takes the numbers.

	// KindChaff is cover traffic while the user types (D11, O10).
	KindChaff Kind = 0x07
	// KindChannel is a datagram on a typed channel other than the terminal,
	// prefixed by its channel id (D15): the agent, later port forwarding.
	KindChannel Kind = 0x08
	// KindRevoked tells a client another has taken the session over (D26),
	// with the address and time, so it can say so and exit.
	KindRevoked Kind = 0x09

	// Added at integration, after the reserved numbers.

	// KindEnd says the session is over (transport.md §8.4): the server's
	// shell exited, or the client's user quit. Its body is one EndReason
	// byte. Without it neither side could tell a finished session from a
	// silent network (server.md §11 item 7).
	KindEnd Kind = 0x0A
)

// Packet types: the first byte of every datagram, in the clear.
const (
	TypeMsg1 = 0x01
	TypeMsg2 = 0x02
	TypeData = 0x04
	// TypeNATProbe is reserved for NAT traversal (O6).
	TypeNATProbe = 0x05
	// TypeCookie is reserved for a cookie reply under load.
	TypeCookie = 0x06
)
