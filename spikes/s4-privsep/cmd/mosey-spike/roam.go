package main

import (
	"crypto/rand"
	"net/netip"
	"time"
)

// roamer decides where server output goes. Mosh's rule (paper §2.2: the
// server sends to the source address of the most recent authentic packet)
// is mode "trust". That rule hands the address to whoever labels incoming
// packets: an on-path attacker, or in layouts B/B2 the network process,
// which reads the datagram and tells the session where it came from. The
// AEAD covers the payload, not the UDP source address.
//
// Mode "validate" is QUIC-style path validation (RFC 9000 §8.2): an
// authenticated packet from a new address does not move the peer. The
// session instead sends a sealed 16-byte challenge to that address, at most
// once per 250 ms per address and 4 per second overall, and switches only
// when an authenticated response carrying that nonce arrives labelled with
// that address. Only a party that both receives at the address and holds
// the key can answer. In B2 and C the challenge leaves from the session's or
// proto's own socket, so the network process never sees where it went.
type roamer struct {
	validate bool
	peer     netip.AddrPort
	pending  map[netip.AddrPort][16]byte
	lastSent map[netip.AddrPort]time.Time
	tokens   float64
	lastFill time.Time

	Challenges, Switches, RateLimited int
}

func newRoamer(validate bool) *roamer {
	return &roamer{validate: validate, pending: map[netip.AddrPort][16]byte{},
		lastSent: map[netip.AddrPort]time.Time{}, tokens: 4, lastFill: time.Now()}
}

// onAuth takes an authenticated plaintext labelled with from. It returns
// keystroke bytes to deliver (authenticity does not depend on the address)
// and, if one should be sent, a challenge plaintext and its destination.
func (r *roamer) onAuth(from netip.AddrPort, pt []byte) (data, chal []byte, chalTo netip.AddrPort) {
	if len(pt) == 0 {
		return nil, nil, chalTo
	}
	if !r.validate {
		if r.peer != from {
			r.Switches++
		}
		r.peer = from
		if pt[0] == ptData {
			data = pt[1:]
		}
		return data, nil, chalTo
	}
	switch pt[0] {
	case ptResponse:
		if n, ok := r.pending[from]; ok && len(pt) == 17 && [16]byte(pt[1:17]) == n {
			r.peer = from
			r.Switches++
			delete(r.pending, from)
		}
		return nil, nil, chalTo
	case ptData:
		data = pt[1:]
	}
	if from == r.peer {
		return data, nil, chalTo
	}
	now := time.Now()
	r.tokens = min(4, r.tokens+now.Sub(r.lastFill).Seconds()*4)
	r.lastFill = now
	if now.Sub(r.lastSent[from]) < 250*time.Millisecond || r.tokens < 1 {
		r.RateLimited++
		return data, nil, chalTo
	}
	r.tokens--
	if len(r.pending) >= 8 { // bound state: forget the oldest-looking entries
		for k := range r.pending {
			delete(r.pending, k)
			delete(r.lastSent, k)
			break
		}
	}
	var n [16]byte
	rand.Read(n[:])
	r.pending[from] = n
	r.lastSent[from] = now
	r.Challenges++
	return data, append([]byte{ptChallenge}, n[:]...), from
}
