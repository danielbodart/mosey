package transport

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/danielbodart/mosey/internal/handshake"
)

// FuzzReceive feeds the server's receive path whatever the fuzzer makes,
// from the client's own address, on a live connection. The invariants
// (transport.md §5, §11): a datagram the server refuses changes neither the
// window, the keys, the epoch, the peer, the amplification counters nor any
// rekey or path state; and the only datagrams it accepts are genuine ones
// the client sealed, each once.
//
// It runs outside synctest (a fuzz worker lives for minutes), on a memNet
// with no delay, so the setup is a real, quick handshake.
func FuzzReceive(f *testing.F) {
	s := newSetup(f, 0)
	client, server, _ := s.connect(clientAddr.String())

	genuine := map[string]bool{}
	client.e.lock()
	for _, fr := range []struct {
		kind Kind
		body []byte
	}{
		{KindTerminal, []byte("keystrokes")},
		{KindTerminal, nil},
		{KindKeepalive, keepaliveAnswer},
		{KindKeepalive, keepaliveNone},
		{KindPathChallenge, []byte("12345678")},
		{KindPathResponse, []byte("87654321")},
		{KindRekeyInit1, make([]byte, handshake.RekeyPartSize)},
		{KindRekeyResp, make([]byte, handshake.RekeyRespSize)},
		{KindChaff, []byte("cover")},
		{Kind(0xee), []byte("a later slice")},
	} {
		pkt := must(client.cur.seal(fr.kind, fr.body))
		genuine[string(pkt)] = true
		f.Add(pkt)
	}
	client.e.unlock()
	f.Add([]byte{TypeData})
	f.Add([]byte{TypeMsg1, handshake.WireVersion})

	used := map[string]bool{}
	f.Fuzz(func(t *testing.T, pkt []byte) {
		s.l.e.lock()
		defer s.l.e.unlock()
		before := snapshotLocked(server)
		dropped := totalDrops(s.l.e.drops.count)
		s.l.handle(pkt, clientAddr)
		if totalDrops(s.l.e.drops.count) > dropped {
			if after := snapshotLocked(server); after != before {
				t.Fatalf("a refused datagram changed the connection: %+v → %+v", before, after)
			}
			return
		}
		if !genuine[string(pkt)] {
			t.Fatalf("a datagram the client never sealed was accepted: %x", pkt)
		}
		if used[string(pkt)] {
			t.Fatalf("a genuine datagram was accepted twice: %x", pkt)
		}
		used[string(pkt)] = true
	})
}

func totalDrops(d [reasons]uint64) uint64 {
	var n uint64
	for _, c := range d {
		n += c
	}
	return n
}

// FuzzInitSlot drives the responder's one reassembly slot for REKEY_INIT
// halves (transport.md §6.4) with any sequence of halves, checked against a
// reference written the obvious way: the slot hands over a pair only when
// it holds both halves of one idx_I', those are the latest of each half
// since the slot last started on that idx_I', they join into one INIT, and
// the slot is then empty. Whatever arrives, it holds at most two halves.
func FuzzInitSlot(f *testing.F) {
	f.Add([]byte{0, 1, 1, 1})
	f.Add([]byte{0, 1, 1, 2, 0, 1})
	f.Fuzz(func(t *testing.T, script []byte) {
		var slot initSlot
		type ref struct {
			idx  uint32
			half [2][]byte
		}
		var want ref
		// Each step is two bytes: which half, and a small idx_I' (0 is
		// allowed here: JoinRekeyInit is what refuses it).
		for i := 0; i+1 < len(script); i += 2 {
			which, idx := int(script[i]&1), uint32(script[i+1]%4)
			body := make([]byte, handshake.RekeyPartSize)
			binary.LittleEndian.PutUint32(body, idx)
			body[4], body[5] = byte(i), byte(which) // tell the halves apart

			if idx != want.idx {
				want = ref{idx: idx}
			}
			want.half[which] = body
			complete := want.half[0] != nil && want.half[1] != nil

			parts, ok := slot.add(which, body)
			if ok != complete {
				t.Fatalf("step %d: handed over %v, the reference says %v", i/2, ok, complete)
			}
			if !ok {
				continue
			}
			if !bytes.Equal(parts[0], want.half[0]) || !bytes.Equal(parts[1], want.half[1]) {
				t.Fatalf("step %d: handed over halves that were not the latest", i/2)
			}
			if _, _, err := handshake.JoinRekeyInit(parts); err != nil && idx != 0 {
				t.Fatalf("step %d: the halves do not join: %v", i/2, err)
			}
			if slot.half[0] != nil || slot.half[1] != nil {
				t.Fatalf("step %d: the slot kept halves after handing them over", i/2)
			}
			want = ref{}
		}
	})
}

// FuzzParseRevoked: a REVOKED body the client accepts re-encodes to the
// same bytes, so the parser accepts exactly the grammar of transport.md
// §8.3 and nothing looser.
func FuzzParseRevoked(f *testing.F) {
	f.Add(revokedBody(time.UnixMilli(1_700_000_000_000), netip.MustParseAddrPort("192.0.2.1:60001")))
	f.Add(revokedBody(time.UnixMilli(1), netip.MustParseAddrPort("[2001:db8::1]:22")))
	f.Fuzz(func(t *testing.T, b []byte) {
		by, at, ok := parseRevoked(b)
		if !ok {
			return
		}
		if again := revokedBody(at, by); !bytes.Equal(again, b) {
			t.Fatalf("%x parsed as %v at %v, which encodes as %x", b, by, at, again)
		}
	})
}
