package bootstrap

import (
	"context"
	"fmt"
	"net/netip"
)

// AddrError is ErrBadAddr (errors.Is) with what was tried: the address the
// server named and why it was refused, and what looking up hostname said.
type AddrError struct {
	// Refused is the line's addr if it was refused, else the zero Addr.
	Refused netip.Addr
	// Rule is why Refused was refused.
	Rule string
	// Hostname is ssh -G's hostname, and Lookup what resolving it said
	// if it failed.
	Hostname string
	Lookup   error
}

func (e *AddrError) Error() string {
	s := ErrBadAddr.Error()
	if e.Refused.IsValid() {
		s += fmt.Sprintf(" (the server said %s, which is %s)", e.Refused, e.Rule)
	}
	if e.Lookup != nil {
		s += fmt.Sprintf(" (looking up %s: %v)", e.Hostname, e.Lookup)
	}
	return s
}

func (e *AddrError) Unwrap() error { return ErrBadAddr }

// ChooseAddr is where the client sends UDP (§7.2): the line's addr if it
// is usable, else the first usable address ssh -G's hostname resolves to,
// else an *AddrError. The addr comes from the far host, which may be
// hostile (T5), so it is taken only if it could not aim the client's
// datagrams at a neighbour, a broadcast or the client's own host
// (threat-model §4.9).
//
// lookup resolves a host name (net.DefaultResolver.LookupNetIP in the
// client); local is the client's own interface prefixes, for their
// directed broadcasts. Both are injected so every rule is tested without
// a network.
func ChooseAddr(ctx context.Context, line CredentialLine, c Config,
	lookup func(ctx context.Context, host string) ([]netip.Addr, error),
	local []netip.Prefix) (netip.Addr, error) {
	hostname := c.Get("hostname")
	r := addrRules{local: local}
	// What hostname names is resolved once, and only when needed: a usable
	// non-loopback addr needs no lookup at all.
	var (
		resolved  []netip.Addr
		lookupErr error
		looked    bool
	)
	resolve := func() {
		if looked {
			return
		}
		looked = true
		if a, err := netip.ParseAddr(hostname); err == nil {
			resolved = []netip.Addr{a} // a literal address is its own result
			return
		}
		if hostname == "" {
			return
		}
		resolved, lookupErr = lookup(ctx, hostname)
	}
	destLoopback := func() bool {
		resolve()
		if len(resolved) == 0 {
			return false
		}
		for _, a := range resolved {
			if !a.Unmap().IsLoopback() {
				return false
			}
		}
		return true
	}
	fail := &AddrError{Hostname: hostname}

	if a := line.Addr; a.IsValid() {
		a = a.Unmap()
		rule := r.refuse(a)
		switch {
		case rule == "" && a.IsLoopback() && !destLoopback():
			rule = "loopback, and " + hostname + " is not"
		case rule == "" && a.Is6() && a.IsLinkLocalUnicast() && a.Zone() == "":
			// The server's zone means nothing here; only the user's own
			// hostname can say which interface, by naming the same address.
			if h, err := netip.ParseAddr(hostname); err == nil && h.Zone() != "" && h.WithZone("") == a {
				return h, nil
			}
			rule = "link-local with no zone"
		}
		if rule == "" {
			return a, nil
		}
		fail.Refused, fail.Rule = a, rule
	}

	resolve()
	loop := destLoopback()
	for _, a := range resolved {
		a = a.Unmap()
		if r.refuse(a) != "" {
			continue
		}
		if a.IsLoopback() && !loop {
			continue
		}
		if a.Is6() && a.IsLinkLocalUnicast() && a.Zone() == "" {
			continue
		}
		return a, nil
	}
	fail.Lookup = lookupErr
	return netip.Addr{}, fail
}

type addrRules struct{ local []netip.Prefix }

// refuse is why a may not be a server's address whoever names it, or "":
// the grammar's rules (unspecified, multicast, limited broadcast) and the
// directed broadcast of one of the client's own IPv4 interfaces, the one
// subnet broadcast the client can recognise.
func (r addrRules) refuse(a netip.Addr) string {
	if rule := addressRule(a); rule != "" {
		return rule
	}
	if a.Is4() {
		for _, p := range r.local {
			if p.Addr().Is4() && p.Bits() <= 30 && p.Bits() > 0 && a == lastAddr(p) {
				return "the broadcast address of " + p.Masked().String()
			}
		}
	}
	return ""
}

// lastAddr is the highest address in an IPv4 prefix: its directed
// broadcast.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v |= host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
