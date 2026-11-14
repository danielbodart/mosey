package handshake

import (
	"crypto/hpke"
	"sync"
)

// OneShotKey is an X-Wing key pair made for one handshake and dropped after
// it. Neither side keeps a long-term key (D20).
//
// It is one-shot in the code as well as in name: NewInitiator takes the
// private key out of it, so a key can never start two handshakes.
type OneShotKey struct {
	mu     sync.Mutex
	sk     hpke.PrivateKey
	public []byte
}

// NewOneShotKey makes a fresh key pair.
func NewOneShotKey() (*OneShotKey, error) {
	var k OneShotKey
	var err error
	secretDo(func() {
		k.sk, k.public, err = generate()
	})
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// PublicKey is the encapsulation key, 1216 bytes, for the bootstrap line.
// It is public; the caller may keep it.
func (k *OneShotKey) PublicKey() []byte {
	return append([]byte(nil), k.public...)
}

// Wipe drops the private key. Without runtimesecret this only drops the
// reference: crypto/hpke offers no way to erase it on demand (S1 §3.2).
func (k *OneShotKey) Wipe() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.sk = nil
}

// take moves the private key out, leaving the key spent.
func (k *OneShotKey) take() hpke.PrivateKey {
	k.mu.Lock()
	defer k.mu.Unlock()
	sk := k.sk
	k.sk = nil
	return sk
}
