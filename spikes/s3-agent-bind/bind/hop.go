package bind

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// HopExt is option (c)'s extension, a placeholder name for the spike. It is
// sent on an agent connection right after the session-bind of the hop it
// describes, so a chain of hops reads, on the agent connection:
//
//	bind(B, fwd=1)  hop(B: requester chain on B)  bind(C, fwd=0)  sign
//
// It never replaces session-bind: an agent that does not know it answers
// failure and the relay carries on, so stock ssh-agent and today's quoin are
// unaffected (measured; see FINDINGS).
//
// Wire (SSH encoding, no trailing bytes):
//
//	string  transport            "mosey" or "ssh"
//	string  host key blob        must equal the preceding bind's host key
//	string  session              free text, shown only
//	uint32  n
//	n × ( uint32 pid, uint32 uid, string comm, uint32 argc, argc × string arg )
//	string  sig                  empty, or reserved for S7 (see Sig)
const HopExt = "hop-v0@mosey.spike"

// Hop is what one hop says about who asked on its side.
type Hop struct {
	Transport string
	HostKey   []byte
	Session   string
	Chain     []Link
	// Sig is reserved for S7. Empty means channel-bound only: it came down
	// the connection whose far end the preceding bind names, and says no
	// more than that host's software chose to say.
	//
	// It must NOT be a raw signature by the host key over SignedData: a
	// session-bind verifier (ssh-agent, quoin's parseBind) accepts any
	// host-key signature over any byte string as a bind with SID = that
	// string, so a raw host-key signature over hop data is also a valid
	// session-bind (cross-protocol oracle; review, minor #5). S7 must use a
	// separate key, or a format that cannot parse as a session id that the
	// verifiers enforce (an SSHSIG namespace, "SSHSIG" magic prefix).
	Sig []byte
}

func putStr(b []byte, s []byte) []byte {
	return append(binary.BigEndian.AppendUint32(b, uint32(len(s))), s...)
}

func (h *Hop) body() []byte {
	b := putStr(nil, []byte(h.Transport))
	b = putStr(b, h.HostKey)
	b = putStr(b, []byte(h.Session))
	b = binary.BigEndian.AppendUint32(b, uint32(len(h.Chain)))
	for _, l := range h.Chain {
		b = binary.BigEndian.AppendUint32(b, uint32(l.Pid))
		b = binary.BigEndian.AppendUint32(b, uint32(l.UID))
		b = putStr(b, []byte(l.Comm))
		b = binary.BigEndian.AppendUint32(b, uint32(len(l.Cmdline)))
		for _, a := range l.Cmdline {
			b = putStr(b, []byte(a))
		}
	}
	return b
}

func (h *Hop) Marshal() []byte { return putStr(h.body(), h.Sig) }

// SignedData is what Sig would cover (reserved for S7; see Sig for why it is
// never signed raw by the host key): a domain-separated
// prefix, a digest of the sign request's data the record vouches for, then
// the body. Not the bound session id: the far end never learns it (sshd
// does not expose it to the session, and a rootless mosey server only knows
// what the client tells it), while the request's data it has in hand.
func (h *Hop) SignedData(requestDigest []byte) []byte {
	b := putStr(nil, []byte("hop-v0"))
	b = putStr(b, requestDigest)
	return append(b, h.body()...)
}

var errShort = errors.New("hop: malformed")

type rd struct {
	b   []byte
	err error
}

func (r *rd) u32() uint32 {
	if r.err != nil || len(r.b) < 4 {
		r.err = errShort
		return 0
	}
	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v
}

func (r *rd) str() []byte {
	n := r.u32()
	if r.err != nil || uint64(n) > uint64(len(r.b)) {
		r.err = errShort
		return nil
	}
	s := r.b[:n:n]
	r.b = r.b[n:]
	return s
}

const maxHopLinks, maxArgs = 16, 64

func ParseHop(b []byte) (*Hop, error) {
	r := &rd{b: b}
	h := &Hop{Transport: string(r.str()), HostKey: r.str(), Session: string(r.str())}
	n := r.u32()
	if n > maxHopLinks {
		return nil, errShort
	}
	for i := uint32(0); i < n && r.err == nil; i++ {
		l := Link{Pid: int(r.u32()), UID: int(r.u32()), Comm: string(r.str())}
		argc := r.u32()
		if argc > maxArgs {
			return nil, errShort
		}
		for j := uint32(0); j < argc && r.err == nil; j++ {
			l.Cmdline = append(l.Cmdline, string(r.str()))
		}
		h.Chain = append(h.Chain, l)
	}
	h.Sig = r.str()
	if r.err != nil || len(r.b) != 0 {
		return nil, errShort
	}
	return h, nil
}

// SameHost is the check an agent makes before showing a hop: its host key
// is the one the preceding bind verified.
func (h *Hop) SameHost(b *Bind) bool { return bytes.Equal(h.HostKey, b.HostKey.Marshal()) }
