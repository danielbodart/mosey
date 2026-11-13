package ssp

import (
	"crypto/rand"
	"net/netip"
	"time"
)

// PathManager decides where the server sends (roaming, ssp-spec.md §2.1).
//
// Naive (Validate=false) is the paper's rule [P §2.2]: send to the source
// of the newest authentic datagram. An on-path attacker can race a copy of
// a genuine client datagram from another address and redirect the output
// stream there (reflection, and a temporary hijack of where output goes).
//
// Validate=true adds path validation in the manner of QUIC (RFC 9000
// §8.2, §9.3): a new source address only becomes the peer once it returns
// an authenticated response to a fresh random challenge sent to it. Until
// then the old peer keeps receiving everything, and the candidate address
// may receive at most AmpFactor times the bytes that arrived from it
// (anti-amplification, RFC 9000 §8.1 uses 3).
type PathManager struct {
	Validate  bool
	AmpFactor int

	Peer netip.AddrPort

	cand            netip.AddrPort
	candIn, candOut int
	token           [8]byte
	lastChallenge   time.Time

	// OnSwitch is called when Peer changes.
	OnSwitch func(addr netip.AddrPort)

	Switches, AmpLimited int
}

// NewPathManager returns a manager; validate selects the policy.
func NewPathManager(validate bool) *PathManager {
	return &PathManager{Validate: validate, AmpFactor: 3}
}

func (p *PathManager) switchTo(a netip.AddrPort) {
	p.Peer = a
	p.cand = netip.AddrPort{}
	p.Switches++
	if p.OnSwitch != nil {
		p.OnSwitch(a)
	}
}

// OnReceive is called for every datagram after tr.Receive. write sends raw
// bytes to an address.
func (p *PathManager) OnReceive(from netip.AddrPort, size int, info RecvInfo, tr *Transport, write func([]byte, netip.AddrPort)) {
	if !info.Authentic {
		return
	}
	if !p.Peer.IsValid() {
		// The first authentic datagram: in mosey the handshake has
		// already proved this address can receive (S1), so accept it.
		p.switchTo(from)
		return
	}
	if !p.Validate {
		if info.Newest && from != p.Peer {
			p.switchTo(from)
		}
		return
	}
	if info.PathResponse && p.cand.IsValid() && info.Token == p.token {
		// The response is authentic and carries the token we sent only to
		// cand. (Like QUIC we do not insist it arrives from cand.)
		p.switchTo(p.cand)
		return
	}
	if from == p.Peer {
		return
	}
	if from != p.cand {
		if !info.Newest {
			return // an old datagram from a new address: ignore
		}
		p.cand, p.candIn, p.candOut = from, 0, 0
		rand.Read(p.token[:])
		p.lastChallenge = time.Time{}
	}
	p.candIn += size
	now := time.Now()
	if p.lastChallenge.IsZero() || now.Sub(p.lastChallenge) >= tr.RTO() {
		p.lastChallenge = now
		p.sendCand(tr.SealPathChallenge(p.token), write)
	}
}

func (p *PathManager) sendCand(b []byte, write func([]byte, netip.AddrPort)) {
	if p.candOut+len(b) > p.AmpFactor*p.candIn {
		p.AmpLimited++
		return
	}
	p.candOut += len(b)
	write(b, p.cand)
}

// Send sends one transport datagram: to the peer, and (within the
// anti-amplification budget) to an address being validated, so a client
// that really has roamed is not kept waiting a round trip.
func (p *PathManager) Send(b []byte, write func([]byte, netip.AddrPort)) {
	if p.Peer.IsValid() {
		write(b, p.Peer)
	}
	if p.Validate && p.cand.IsValid() {
		p.sendCand(b, write)
	}
}
