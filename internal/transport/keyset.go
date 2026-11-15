package transport

import (
	"crypto/cipher"
	"encoding/binary"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/danielbodart/mosey/internal/handshake"
	"github.com/danielbodart/mosey/internal/replay"
)

// Data packet layout (transport.md §4.1):
//
//	type(1)=0x04 | receiver index(4) | counter(8) | AEAD(kind(1) | body) | tag(16)
//
// The 13-byte clear header is the AEAD's associated data and the counter
// its nonce.
const headerSize = 1 + 4 + 8

// keyset is one epoch's keys for one direction pair: what transport.md
// §6.1 calls cur, next or prev.
type keyset struct {
	local, remote uint32
	send, recv    [chacha20poly1305.KeySize]byte
	// sealer and opener hold copies of the keys inside x/crypto, which has
	// no way to erase them. One of each per key set, dropped with it, keeps
	// those copies to one rather than one per packet.
	sealer, opener cipher.AEAD
	sendCounter    uint64
	window         replay.Window
	installed      time.Time
	failures       uint64
}

// newKeyset copies k's keys into a key set and erases them from k, so the
// only copy left is the one this side wipes by transport.md §9's rules.
// k.Root is the caller's to move.
func newKeyset(k *handshake.Keys, now time.Time) *keyset {
	ks := &keyset{local: k.LocalIndex, remote: k.RemoteIndex, send: k.Send, recv: k.Recv, installed: now}
	clear(k.Send[:])
	clear(k.Recv[:])
	ks.sealer = mustAEAD(&ks.send)
	ks.opener = mustAEAD(&ks.recv)
	return ks
}

func mustAEAD(key *[chacha20poly1305.KeySize]byte) cipher.AEAD {
	a, err := chacha20poly1305.New(key[:])
	if err != nil {
		panic("transport: " + err.Error()) // a [32]byte cannot be the wrong size
	}
	return a
}

func (ks *keyset) wipe() {
	clear(ks.send[:])
	clear(ks.recv[:])
	ks.sealer, ks.opener = nil, nil
}

// seal makes a data packet of one frame under this key set's next counter.
// It refuses rather than reuse a nonce or pass the counter limit.
func (ks *keyset) seal(kind Kind, body []byte) ([]byte, error) {
	if ks.sealer == nil {
		return nil, errWiped
	}
	if ks.sendCounter >= RejectAfterMessages {
		return nil, errExhausted
	}
	pkt := make([]byte, headerSize, headerSize+1+len(body)+chacha20poly1305.Overhead)
	pkt[0] = TypeData
	binary.LittleEndian.PutUint32(pkt[1:], ks.remote)
	binary.LittleEndian.PutUint64(pkt[5:], ks.sendCounter)
	plain := make([]byte, 0, 1+len(body))
	plain = append(plain, byte(kind))
	plain = append(plain, body...)
	pkt = ks.sealer.Seal(pkt, nonce(ks.sendCounter), plain, pkt[:headerSize])
	ks.sendCounter++
	return pkt, nil
}

// open checks and opens a data packet already routed to this key set by
// its index, in transport.md §5's order: the counter limit, the replay
// window, then the AEAD. It changes nothing but the failure count; the
// caller commits the counter once it has decided to keep the packet.
func (ks *keyset) open(pkt []byte) (plain []byte, counter uint64, why Reason, ok bool) {
	if ks.opener == nil {
		return nil, 0, UnknownIndex, false
	}
	counter = binary.LittleEndian.Uint64(pkt[5:])
	if counter >= RejectAfterMessages || !ks.window.Check(counter) {
		return nil, 0, Replay, false
	}
	plain, err := ks.opener.Open(nil, nonce(counter), pkt[headerSize:], pkt[:headerSize])
	if err != nil {
		ks.failures++
		return nil, 0, Auth, false
	}
	return plain, counter, 0, true
}

// nonce is NONCE(n): four zero bytes, then the counter little-endian, as
// Noise's ChaChaPoly lays it out (Noise §12.3).
func nonce(n uint64) []byte {
	var b [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(b[4:], n)
	return b[:]
}
