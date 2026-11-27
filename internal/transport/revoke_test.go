package transport

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// A REVOKED body is §8.3's layout: the address part as it always was, and
// the name, when there is one, after it as a length byte and the name.
func TestARevokedBodyAppendsTheNameAfterTheAddress(t *testing.T) {
	at := time.UnixMilli(1_700_000_000_000)
	by := netip.MustParseAddrPort("192.0.2.1:60001")
	bare := revokedBody(at, by, "")
	if len(bare) != 15 {
		t.Fatalf("a nameless IPv4 body is %d bytes, not 15", len(bare))
	}
	named := revokedBody(at, by, "blade")
	if !bytes.Equal(named, append(append([]byte{}, bare...), "\x05blade"...)) {
		t.Fatalf("%x", named)
	}
	longest := revokedBody(at, netip.MustParseAddrPort("[2001:db8::1]:22"), strings.Repeat("h", 63))
	if len(longest) != 91 {
		t.Errorf("the longest body is %d bytes, not the 91 §8.3 says", len(longest))
	}
	if gotBy, host, gotAt, ok := parseRevoked(named); !ok || gotBy != by || host != "blade" || !gotAt.Equal(at) {
		t.Errorf("%v %q %v %v", gotBy, host, gotAt, ok)
	}
	// A name that is not a valid claim is never sent.
	if !bytes.Equal(revokedBody(at, by, "bad_name"), bare) {
		t.Error("a bad name was sent")
	}
}

// A malformed name part degrades to the address alone: the revoked client
// still learns that it was cut off, and from where (§8.3).
func TestARevokedBodyWithABadNameReadsAsTheAddressAlone(t *testing.T) {
	at := time.UnixMilli(1_700_000_000_000)
	by := netip.MustParseAddrPort("192.0.2.1:60001")
	bare := revokedBody(at, by, "")
	for name, tail := range map[string]string{
		"a bad byte":     "\x03a_b",
		"a long length":  "\x09blade",
		"a short length": "\x02blade",
		"no name":        "\x00",
		"a length alone": "\x05",
		"over 63 bytes":  "\x40" + strings.Repeat("h", 64),
		"a leading dash": "\x02-a",
		"an escape":      "\x02\x1b[",
		"one stray byte": "x",
		"an empty label": "\x03a..",
		"a trailing dot": "\x02a.",
	} {
		gotBy, host, gotAt, ok := parseRevoked(append(append([]byte{}, bare...), tail...))
		if !ok || gotBy != by || host != "" || !gotAt.Equal(at) {
			t.Errorf("%s: %v %q %v %v", name, gotBy, host, gotAt, ok)
		}
	}
	// A fault in the address part still refuses the body.
	if _, _, _, ok := parseRevoked(bare[:14]); ok {
		t.Error("accepted a short address part")
	}
}
