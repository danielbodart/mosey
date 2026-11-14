package handshake

// Rekeys run inside the transport, under the current epoch's keys, every
// 120 s or N packets (D20; WireGuard's REKEY_AFTER_TIME). Never on idleness.
//
// REKEY_INIT carries a fresh X-Wing public key (1216 bytes), which with the
// transport's framing would exceed wire.MaxHandshake, so it is split across
// two datagrams, each sealed under the current keys. The responder acts
// only once it holds both halves of the same INIT.

// RekeyInitiator is one side's rekey in flight.
type RekeyInitiator struct{}

// StartRekey begins a rekey from the current root. The two parts are the
// bodies of the two REKEY_INIT frames.
func StartRekey(root [32]byte) (*RekeyInitiator, [2][]byte, error) {
	panic("TODO slice 1")
}

// Finish derives the next epoch's keys from the peer's REKEY_RESP.
func (r *RekeyInitiator) Finish(resp []byte) (Keys, error) {
	panic("TODO slice 1")
}

// RespondRekey answers a reassembled REKEY_INIT: the body of REKEY_RESP and
// the next epoch's keys, which the responder installs for receiving only
// until a packet under them authenticates.
func RespondRekey(root [32]byte, parts [2][]byte) (resp []byte, next Keys, err error) {
	panic("TODO slice 1")
}
