package wire

import "testing"

// The limits are derived, not chosen, so the test derives them again: if
// either changes, it must be because D5 changed.
func TestLimitsAreDerivedFromTheIPv6MinimumMTU(t *testing.T) {
	const ipv6MinimumMTU, ipv6Header, udpHeader = 1280, 40, 8
	if MaxDatagram != ipv6MinimumMTU-ipv6Header-udpHeader {
		t.Errorf("MaxDatagram is %d", MaxDatagram)
	}
	const quicMinimumDatagram = 1200
	if MaxHandshake != quicMinimumDatagram {
		t.Errorf("MaxHandshake is %d", MaxHandshake)
	}
	if MaxHandshake > MaxDatagram {
		t.Error("a handshake message may not be bigger than a datagram")
	}
}
