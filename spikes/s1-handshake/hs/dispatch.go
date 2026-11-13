package hs

import (
	"encoding/binary"
	"net/netip"
)

// Dispatcher is the server's UDP demultiplexer: one socket, many terminal
// sessions, many credentials and transports. It is the piece review asked
// for:
//
//   - msg1 carries a cleartext, single-use credential id, so a msg1 is
//     matched to its credential with ONE map lookup before any mac1 or KEM
//     work, however many credentials are outstanding;
//   - an unused credential expires after CredentialTTL (Reap);
//   - each terminal session has at most MaxOutstanding unused credentials;
//     minting one more wipes the oldest;
//   - an attach may be EXCLUSIVE: when its transport confirms, every other
//     transport of that terminal session is revoked (keys wiped), which is
//     what makes "log in over SSH again" a recovery from a stolen client.
type Dispatcher struct {
	cfg            Config
	MaxOutstanding int

	creds   map[[credIDSize]byte]*credEntry
	byIdx   map[uint32]*Session
	byTerm  map[string]*termState
	Revoked uint64 // transports revoked by exclusive attach (stats)
}

type credEntry struct {
	srv       *BServer
	term      string
	exclusive bool
}

type termState struct {
	unused     [][credIDSize]byte // FIFO of outstanding credentials
	transports []*Session
}

func NewDispatcher(cfg Config) *Dispatcher {
	if cfg.Now == nil {
		cfg = DefaultConfig()
	}
	return &Dispatcher{
		cfg: cfg, MaxOutstanding: 2,
		creds:  map[[credIDSize]byte]*credEntry{},
		byIdx:  map[uint32]*Session{},
		byTerm: map[string]*termState{},
	}
}

// Mint creates a credential for terminal session term. clientPK is the
// client's one-shot key from SSH stdin (B3; nil otherwise). The caller
// writes cred.Marshal() to SSH stdout and must then Wipe both.
func (d *Dispatcher) Mint(term string, mode BMode, local Hello, clientPK []byte, exclusive bool) (BCredentials, error) {
	var pks [][]byte
	if clientPK != nil {
		pks = append(pks, clientPK)
	}
	srv, cred, err := NewBServer(mode, local, d.cfg, pks...)
	if err != nil {
		return BCredentials{}, err
	}
	if d.creds[cred.CredID] != nil { // 64-bit id: collisions are theoretical
		return d.Mint(term, mode, local, clientPK, exclusive)
	}
	ts := d.term(term)
	for len(ts.unused) >= d.MaxOutstanding {
		d.dropCred(ts.unused[0])
	}
	e := &credEntry{srv: srv, term: term, exclusive: exclusive}
	id := cred.CredID
	srv.OnConsume = func(winner *Session) { d.onConsume(id, e, winner) }
	d.creds[id] = e
	ts.unused = append(ts.unused, id)
	return cred, nil
}

func (d *Dispatcher) term(t string) *termState {
	ts := d.byTerm[t]
	if ts == nil {
		ts = &termState{}
		d.byTerm[t] = ts
	}
	return ts
}

func (d *Dispatcher) dropCred(id [credIDSize]byte) {
	e := d.creds[id]
	if e == nil {
		return
	}
	if !e.srv.consumed {
		e.srv.Wipe(nil) // revokes unconfirmed B3 responders too
		for _, p := range e.srv.pending {
			if p.sess != nil {
				d.forget(p.sess)
			}
		}
	}
	delete(d.creds, id)
	d.unlistUnused(e.term, id)
}

func (d *Dispatcher) unlistUnused(term string, id [credIDSize]byte) {
	ts := d.byTerm[term]
	for i, u := range ts.unused {
		if u == id {
			ts.unused = append(ts.unused[:i], ts.unused[i+1:]...)
			break
		}
	}
}

func (d *Dispatcher) onConsume(id [credIDSize]byte, e *credEntry, winner *Session) {
	ts := d.byTerm[e.term]
	if e.exclusive {
		for _, t := range ts.transports {
			if t != winner && !t.revoked {
				t.Revoke()
				d.forget(t)
				d.Revoked++
			}
		}
		ts.transports = ts.transports[:0]
	}
	ts.transports = append(ts.transports, winner)
	// Consumed: no longer counts as outstanding. The (secret-free) entry
	// stays until its TTL so a retransmitted msg1 still gets the cached
	// msg2; Reap removes it.
	d.unlistUnused(e.term, id)
}

// Reap removes credentials past their TTL: unused ones are wiped (and
// their unconfirmed B3 responders revoked); consumed ones just drop the
// msg2 retransmission cache. Call it from the event loop.
func (d *Dispatcher) Reap() (n int) {
	now := d.cfg.Now()
	for id, e := range d.creds {
		if now.After(e.srv.expires) {
			d.dropCred(id)
			n++
		}
	}
	return n
}

// Outstanding returns the number of live, unused credentials.
func (d *Dispatcher) Outstanding() (n int) {
	for _, ts := range d.byTerm {
		n += len(ts.unused)
	}
	return n
}

// Handle processes one datagram from `from`. It returns packets to send
// (each to its session's Peer, subject to AllowSend), any application
// payload, and the session it belongs to.
func (d *Dispatcher) Handle(pkt []byte, from netip.AddrPort) (out [][]byte, app []byte, sess *Session, err error) {
	if len(pkt) < 1 {
		return nil, nil, nil, ErrMalformed
	}
	switch pkt[0] {
	case TypeBInit:
		if len(pkt) < bInitHeader {
			return nil, nil, nil, ErrMalformed
		}
		var id [credIDSize]byte
		copy(id[:], pkt[2:])
		e := d.creds[id]
		if e == nil {
			return nil, nil, nil, ErrNoKey // O(1), before mac1
		}
		resp, s, _, err := e.srv.HandleInit(pkt)
		if err != nil {
			return nil, nil, nil, err
		}
		if s != nil {
			s.setUnvalidatedPeer(from)
			s.idxHook = func(i uint32) { d.byIdx[i] = s }
			d.byIdx[s.LocalIndex()] = s
		}
		return [][]byte{resp}, nil, s, nil
	case TypeData:
		if len(pkt) < 5 {
			return nil, nil, nil, ErrMalformed
		}
		s := d.byIdx[binary.LittleEndian.Uint32(pkt[1:])]
		if s == nil {
			return nil, nil, nil, ErrNoKey
		}
		app, err := s.Open(pkt, from)
		if s.revoked {
			d.forget(s)
		}
		return s.Outbox(), app, s, err
	}
	return nil, nil, nil, ErrMalformed
}

func (d *Dispatcher) forget(s *Session) {
	for i, v := range d.byIdx {
		if v == s {
			delete(d.byIdx, i)
		}
	}
}
