package bootstrap

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

// resolver is a fixed DNS for ChooseAddr's tests.
type resolver map[string][]string

func (r resolver) lookup(_ context.Context, host string) ([]netip.Addr, error) {
	names, ok := r[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	var out []netip.Addr
	for _, n := range names {
		out = append(out, netip.MustParseAddr(n))
	}
	return out, nil
}

var dns = resolver{
	"far":       {"198.51.100.9"},
	"localhost": {"127.0.0.1", "::1"},
	"mixed":     {"::", "224.0.0.1", "192.0.2.7"},
	"nothing":   {"0.0.0.0", "255.255.255.255"},
}

var lan = []netip.Prefix{netip.MustParsePrefix("10.1.2.3/24"), netip.MustParsePrefix("192.168.7.1/31")}

func lineWith(addr string) CredentialLine {
	l := sampleCredentialLine()
	l.Addr = netip.Addr{}
	if addr != "" {
		l.Addr = netip.MustParseAddr(addr)
	}
	return l
}

func choose(t *testing.T, addr, hostname string) (string, error) {
	t.Helper()
	c := Config{}
	if hostname != "" {
		c["hostname"] = []string{hostname}
	}
	a, err := ChooseAddr(context.Background(), lineWith(addr), c, dns.lookup, lan)
	if err != nil {
		return "", err
	}
	return a.String(), nil
}

// Each row of §7.2's table.
func TestTheUDPAddressIsChosenByTheRules(t *testing.T) {
	for _, c := range []struct {
		addr, hostname, want string
	}{
		{"203.0.113.5", "far", "203.0.113.5"},       // usable addr
		{"127.0.0.1", "far", "198.51.100.9"},        // loopback addr, far destination: fall back
		{"::1", "far", "198.51.100.9"},              //
		{"127.0.0.1", "localhost", "127.0.0.1"},     // loopback addr, loopback destination: kept
		{"127.0.0.1", "127.0.0.1", "127.0.0.1"},     // a literal hostname is its own result
		{"10.1.2.255", "far", "198.51.100.9"},       // a local directed broadcast
		{"10.1.3.255", "far", "10.1.3.255"},         // someone else's subnet: not ours to judge
		{"192.168.7.1", "far", "192.168.7.1"},       // a /31 has no broadcast
		{"fe80::1", "far", "198.51.100.9"},          // link-local with no zone
		{"fe80::1", "fe80::1%eth0", "fe80::1%eth0"}, // link-local, zoned by the user's hostname
		{"fe80::1", "fe80::2%eth0", "fe80::2%eth0"}, // another address: hostname's own result
		{"", "mixed", "192.0.2.7"},                  // "-": the first usable of hostname's
		{"", "far", "198.51.100.9"},
	} {
		got, err := choose(t, c.addr, c.hostname)
		if err != nil || got != c.want {
			t.Errorf("addr %q hostname %q: %q %v, want %q", c.addr, c.hostname, got, err, c.want)
		}
	}
}

func TestNoUsableAddressSaysWhy(t *testing.T) {
	_, err := choose(t, "127.0.0.1", "nothing")
	var ae *AddrError
	if !errors.As(err, &ae) || !errors.Is(err, ErrBadAddr) || ae.Refused.String() != "127.0.0.1" || ae.Rule == "" {
		t.Errorf("%v", err)
	}
	_, err = choose(t, "", "unknown.example")
	if !errors.As(err, &ae) || ae.Lookup == nil || ae.Refused.IsValid() {
		t.Errorf("%v", err)
	}
	if _, err = choose(t, "", ""); !errors.Is(err, ErrBadAddr) {
		t.Errorf("%v", err)
	}
}

// A usable addr needs no lookup: the client's DNS is not consulted when
// the server's answer is good.
func TestAUsableAddressNeedsNoLookup(t *testing.T) {
	fail := func(context.Context, string) ([]netip.Addr, error) {
		t.Error("looked up")
		return nil, nil
	}
	a, err := ChooseAddr(context.Background(), lineWith("203.0.113.5"), Config{"hostname": {"far"}}, fail, nil)
	if err != nil || a.String() != "203.0.113.5" {
		t.Errorf("%v %v", a, err)
	}
}

func TestLastAddrIsTheDirectedBroadcast(t *testing.T) {
	for p, want := range map[string]string{
		"10.1.2.3/24":   "10.1.2.255",
		"10.0.0.0/8":    "10.255.255.255",
		"192.0.2.9/30":  "192.0.2.11",
		"172.16.5.4/12": "172.31.255.255",
	} {
		if got := lastAddr(netip.MustParsePrefix(p)).String(); got != want {
			t.Errorf("%s: %s", p, got)
		}
	}
}
