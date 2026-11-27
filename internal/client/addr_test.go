package client

import (
	"net/netip"
	"testing"
)

func TestALongIPv6AddressShowsItsFirstAndLastTwoWrittenGroups(t *testing.T) {
	for in, want := range map[string]string{
		"2a02:c7c:5a1b:e600:5e1f:9aff:fe3b:12cd": "2a02:c7c…fe3b:12cd",
		"fe80::5e1f:9aff:fe3b:12cd":              "fe80::5e1f…fe3b:12cd",
		"2001:db8:0:1:2::":                       "2001:db8…1:2::",
		"::a:b:c:d:e":                            "::a:b…d:e",
		"2001:db8::a:b:c":                        "2001:db8…b:c",
	} {
		if got := shownAddr(netip.MustParseAddr(in)); got != want {
			t.Errorf("shownAddr(%s) = %q, want %q", in, got, want)
		}
	}
}

func TestAnAddressOfFourWrittenGroupsOrFewerShowsWhole(t *testing.T) {
	for _, in := range []string{"::1", "2001:db8::1", "2001:db8:0:1::", "192.168.1.20", "255.255.255.255", "::ffff:10.0.0.1"} {
		want := netip.MustParseAddr(in).Unmap().String()
		if got := shownAddr(netip.MustParseAddr(in)); got != want {
			t.Errorf("shownAddr(%s) = %q, want %q", in, got, want)
		}
	}
}
