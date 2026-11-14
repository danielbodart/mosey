package ssp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"slices"
	"testing"
	"testing/synctest"
	"time"
)

func TestPadmeRoundsAsTheAlgorithmPrints(t *testing.T) {
	// Worked by hand from PoPETs 2019(4) §4.4 Algorithm 1: E = floor(log2
	// L), S = floor(log2 E) + 1, z = E - S, then round L up to a multiple
	// of 2^z. 8, 9 and 10 are the paper's own Table 1.
	for l, want := range map[int]int{
		0: 0, 1: 1, 2: 2, 3: 3, 7: 7,
		8: 8, 9: 10, 10: 10, 15: 16, 16: 16, 17: 18, 31: 32,
		32: 32, 33: 36, 63: 64, 64: 64, 65: 72, 127: 128,
		128: 128, 129: 144, 511: 512, 513: 544, 1023: 1024,
		1024: 1024, 1025: 1088, 1153: 1216, 1203: 1216,
		65535: 65536,
	} {
		if got := padme(l); got != want {
			t.Errorf("padme(%d) = %d, want %d", l, got, want)
		}
	}
}

func TestPadmeNeverShrinksIsIdempotentAndCostsAtMostTwelvePercent(t *testing.T) {
	for l := 1; l <= 1<<17; l++ {
		p := padme(l)
		if p < l || padme(p) != p || float64(p-l) > 0.12*float64(l) {
			t.Fatalf("padme(%d) = %d", l, p)
		}
	}
}

func TestThePaddedLengthIsTheFloorThenPadmeThenTheLimit(t *testing.T) {
	limit := frameOverhead + maxPayload // 1203
	for _, c := range []struct{ u, floor, want int }{
		{9, clientPadFloor, 16},       // a client ack
		{16, clientPadFloor, 16},      // exactly the floor
		{17, clientPadFloor, 18},      // Padmé, 2-byte steps
		{29, clientPadFloor, 30},      // a keystroke with an echo
		{9, serverPadFloor, 64},       // a server ack
		{35, serverPadFloor, 64},      // an echo
		{65, serverPadFloor, 72},      // Padmé, 8-byte steps
		{300, serverPadFloor, 304},    // 16-byte steps
		{1152, serverPadFloor, 1152},  // the last length Padmé leaves under the limit
		{1153, serverPadFloor, limit}, // Padmé would say 1216: capped
		{limit, serverPadFloor, limit},
	} {
		if got := paddedLen(c.u, c.floor, limit); got != c.want {
			t.Errorf("paddedLen(%d, %d) = %d, want %d", c.u, c.floor, got, c.want)
		}
	}
}

func TestPaddingNeverPassesTheLimit(t *testing.T) {
	for _, limit := range []int{frameOverhead + maxPayload, HeaderMax + padTrailer + 8, 40, 1 << 16} {
		for _, floor := range []int{clientPadFloor, serverPadFloor} {
			for u := 1; u <= limit; u++ {
				if p := paddedLen(u, floor, limit); p < u || p > limit {
					t.Fatalf("limit %d floor %d: %d padded to %d", limit, floor, u, p)
				}
			}
		}
	}
	// The longest datagram there can be, a full chunk under the largest
	// header, still has room for the trailer and is padded to exactly
	// MaxPayload: the chunk leaves those two bytes (§3).
	for _, role := range []Role{Client, Server} {
		e := NewEndpoint(newScript(), Config{Role: role, MaxPayload: maxPayload, FrameOverhead: frameOverhead, MaxRemoteBytes: boardLimit},
			newBoard(""), newBoard(""))
		d := datagram{echo: 1, hasEcho: true, ack: 1<<64 - 1, frag: &fragment{count: 2, chunk: make([]byte, e.lim.chunk)}}
		e.pad(&d)
		if b := appendDatagram(nil, d); len(b) != maxPayload || d.pad != 0 {
			t.Errorf("role %d: the longest datagram is %d bytes with %d of padding, want %d and 0", role, len(b), d.pad, maxPayload)
		}
	}
}

// sealed is how long the transport's sealed plaintext is for a payload:
// the length an observer sees, less the clear header and the tag.
func sealed(p []byte) int { return frameOverhead + len(p) }

func TestEverySentDatagramFollowsThePaddingRuleInBothDirections(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, s := symmetric(30 * time.Millisecond)
		p := start(t, c, s)
		// A user types, and the server echoes each key a little later, as a
		// shell would: one changed cell, the board's newest key.
		for i := range 300 {
			k := string(rune('a' + i%26))
			p.typeKeys(k)
			time.Sleep(60 * time.Millisecond)
			p.server.Set(newBoard(k))
			time.Sleep(90 * time.Millisecond)
		}
		// Then idle long enough for heartbeats, and a redraw that needs
		// several full fragments.
		time.Sleep(10 * time.Second)
		echoes := len(s.sends(t))
		big := randomText(3, 4*1173)
		p.server.Set(newBoard(big))
		sleepUntil(t, 5*time.Second, "the redraw", func() bool { return p.screen() == big })
		time.Sleep(time.Second)

		limit := frameOverhead + maxPayload
		check := func(name string, log []decoded, floor int) map[int]int {
			sizes := map[int]int{}
			for _, d := range log {
				if !d.padded {
					t.Fatalf("%s sent an unpadded datagram", name)
				}
				u := sealed(d.payload) - d.pad
				want := max(floor, padme(u))
				if want > limit {
					want = limit
				}
				if sealed(d.payload) != want {
					t.Fatalf("%s sent %d sealed bytes for %d unpadded, want %d", name, sealed(d.payload), u, want)
				}
				if d.frag != nil && d.frag.index < d.frag.count-1 && len(d.payload) != maxPayload {
					t.Errorf("%s sent a full fragment of %d bytes, not %d", name, len(d.payload), maxPayload)
				}
				sizes[sealed(d.payload)]++
			}
			return sizes
		}
		ss := s.sends(t)
		serverSizes := check("server", ss, serverPadFloor)
		clientSizes := check("client", c.sends(t), clientPadFloor)
		// Every echo, every ack and every heartbeat from the server is one
		// size: the floor (§9.2, padding.md §3).
		for _, d := range ss[:echoes] {
			if sealed(d.payload) != serverPadFloor {
				t.Fatalf("the server sent %d sealed bytes while echoing keys, not %d", sealed(d.payload), serverPadFloor)
			}
		}
		t.Logf("server sealed sizes: %v", summary(serverSizes))
		t.Logf("client sealed sizes: %v", summary(clientSizes))
	})
}

func summary(sizes map[int]int) string {
	var out string
	for _, n := range slices.Sorted(maps.Keys(sizes)) {
		out += fmt.Sprintf(" %d×%d", n, sizes[n])
	}
	return out
}

func TestARefusedPaddingChangesNoState(t *testing.T) {
	ack := appendDatagram(nil, datagram{ts: 1, ack: 2, padded: true, pad: 4})
	nonZero := slices.Clone(ack)
	nonZero[len(nonZero)-3] = 1
	tooLong := slices.Clone(ack)
	binary.BigEndian.PutUint16(tooLong[len(tooLong)-2:], 5)
	huge := slices.Clone(ack)
	binary.BigEndian.PutUint16(huge[len(huge)-2:], 1<<16-1)
	keystroke := instr(1, 3, 4, encodingStored, []byte("four"))
	keystroke[0] |= flagPadded
	keystroke = append(keystroke, 7, 0, 1) // one byte of padding, and it is 7
	for name, p := range map[string][]byte{
		"non-zero padding":                 nonZero,
		"k reaching into the header":       tooLong,
		"k longer than the datagram":       huge,
		"a padded instruction, not zero":   keystroke,
		"P set with no room for a trailer": {flagPadded, 0, 0, 0, 0, 0},
	} {
		e := fuzzClient()
		before := snapshot(e)
		if err := e.receive(p, time.Now()); !errors.Is(err, ErrProtocol) {
			t.Errorf("%s: %v", name, err)
		}
		if after := snapshot(e); !equalState(before, after) {
			t.Errorf("%s changed %+v to %+v", name, before, after)
		}
	}
}
