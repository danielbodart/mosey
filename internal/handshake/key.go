package handshake

// OneShotKey is an X-Wing key pair made for one handshake and dropped after
// it. Neither side keeps a long-term key (D20).
type OneShotKey struct{}

// NewOneShotKey makes a fresh key pair.
func NewOneShotKey() (*OneShotKey, error) {
	panic("TODO slice 1")
}

// PublicKey is the encapsulation key, 1216 bytes, for the bootstrap line.
func (k *OneShotKey) PublicKey() []byte {
	panic("TODO slice 1")
}

// Wipe drops the private key. Without runtimesecret this only drops the
// reference: crypto/hpke offers no way to erase it on demand (S1 §3.2).
func (k *OneShotKey) Wipe() {
	panic("TODO slice 1")
}
