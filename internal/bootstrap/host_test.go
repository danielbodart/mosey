package bootstrap

import (
	"bytes"
	"net/netip"
	"regexp"
	"strings"
	"testing"
)

// maxHost is the longest name a client may claim (hostname.Max).
var maxHost = strings.Repeat("h", 31) + "." + strings.Repeat("h", 31)

// badHosts are host values the shared grammar lets through but a claim
// is not: each must leave the line as if it had no host.
var badHosts = []string{
	strings.Repeat("h", 64), "-dash", "dash-", "under_score", "a..b", "a.", ".a",
	"semi;colon", "dollar$x", "quote'x", strings.Repeat("a.", 32) + "a",
}

// A client's claimed name travels on its line and comes back as it went
// (§6.2).
func TestAClientLineCarriesTheClientsHostName(t *testing.T) {
	c := sampleClientLine()
	c.Host = "blade"
	line := MarshalClientLine(c)
	if !bytes.Contains(line, []byte(" host=blade ")) {
		t.Fatalf("no host field in %q", line)
	}
	got, err := ParseClientLine(line)
	if err != nil || got.Host != "blade" {
		t.Fatalf("%q gave host %q, %v", line, got.Host, err)
	}
}

// A host that is not a valid claim is dropped, never fatal: the line
// parses as the same line without it (§6.2).
func TestAnInvalidHostNameIsDroppedNotFatal(t *testing.T) {
	want := MarshalClientLine(sampleClientLine())
	for _, h := range badHosts {
		line := addField(string(want), "host="+h)
		got, err := ParseClientLine([]byte(line))
		if err != nil {
			t.Errorf("host %q refused the line: %v", h, err)
			continue
		}
		if got.Host != "" || !bytes.Equal(MarshalClientLine(got), want) {
			t.Errorf("host %q gave %q, which marshals to %q", h, got.Host, MarshalClientLine(got))
		}
	}
	// Marshal leaves a bad one out too, so this end never sends it.
	c := sampleClientLine()
	c.Host = "under_score"
	if !bytes.Equal(MarshalClientLine(c), want) {
		t.Errorf("marshalled a bad host: %q", MarshalClientLine(c))
	}
	// A marked host is a known field with the wrong mark: that is still
	// a malformed line, as for any field.
	if _, err := ParseClientLine([]byte(addField(string(want), "!host=blade"))); err == nil {
		t.Error("accepted a marked host")
	}
}

// The greeting and the list line carry the last client's claimed name
// beside its address, and never without it (§9.2.1, §9.4).
func TestTheGreetingAndTheListNameThePeersHostBesideItsAddress(t *testing.T) {
	s := sampleSessionLine()
	s.PeerHost = "desktop"
	got, err := ParseSessionLine(MarshalSessionLine(s))
	if err != nil || got.PeerHost != "desktop" || got.Peer != s.Peer {
		t.Fatalf("%+v, %v", got, err)
	}
	l := sampleListLine()
	l.Peer, l.PeerHost = netip.MustParseAddrPort("127.0.0.1:41234"), "desktop"
	line := MarshalListLine(l)
	if want := "MOSEY-LIST 1 name=quiet-heron peer=127.0.0.1:41234 peer-host=desktop since=1794651234 state=detached\n"; string(line) != want {
		t.Fatalf("%q, want %q", line, want)
	}
	if got, err := ParseListLine(line); err != nil || got != l {
		t.Fatalf("%+v, %v", got, err)
	}

	// No address, no name: Marshal leaves it out and the parser drops it.
	s.Peer = netip.AddrPort{}
	if bytes.Contains(MarshalSessionLine(s), []byte("peer-host")) {
		t.Errorf("a name without an address: %q", MarshalSessionLine(s))
	}
	s.PeerHost = ""
	bare := MarshalSessionLine(s)
	got, err = ParseSessionLine([]byte(addField(string(bare), "peer-host=desktop")))
	if err != nil || got.PeerHost != "" {
		t.Errorf("a greeting's name without an address gave %q, %v", got.PeerHost, err)
	}
	if got, err := ParseListLine([]byte(addField(string(MarshalListLine(sampleListLine())), "peer-host=desktop"))); err != nil || got.PeerHost != "" {
		t.Errorf("a list line's name without an address gave %q, %v", got.PeerHost, err)
	}
}

// A bad peer-host degrades to the address alone: it never costs the
// launcher a session or the list a row.
func TestAnInvalidPeerHostLeavesTheAddressAlone(t *testing.T) {
	s := sampleSessionLine()
	l := sampleListLine()
	l.Peer = s.Peer
	for _, h := range badHosts {
		got, err := ParseSessionLine([]byte(addField(string(MarshalSessionLine(s)), "peer-host="+h)))
		if err != nil || got.PeerHost != "" || got.Peer != s.Peer {
			t.Errorf("greeting with peer-host %q: %+v, %v", h, got, err)
		}
		gotL, err := ParseListLine([]byte(addField(string(MarshalListLine(l)), "peer-host="+h)))
		if err != nil || gotL.PeerHost != "" || gotL.Peer != l.Peer {
			t.Errorf("list line with peer-host %q: %+v, %v", h, gotL, err)
		}
	}
}

// referenceClaim is a claimed name written out by hand, as the fuzzers'
// reference for hostname.ValidClaim: at most 63 bytes of dot-separated
// labels of letters, digits and '-', none empty or starting or ending
// with '-'. 63 bytes in all keeps each label within its own 63.
var referenceClaim = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$`)

// withoutBadHost is the rule of §6.2 and §9.2.1 written out by hand: line
// with its key field left out unless it is a valid claim and, when
// needsPeer, the line has a peer.
func withoutBadHost(line []byte, key string, needsPeer bool) []byte {
	words := strings.Split(strings.TrimSuffix(string(line), "\n"), " ")
	hasPeer := false
	for _, w := range words {
		hasPeer = hasPeer || strings.HasPrefix(w, "peer=")
	}
	out := words[:0]
	for _, w := range words {
		if v, ok := strings.CutPrefix(w, key+"="); ok && (len(v) > 63 || !referenceClaim.MatchString(v) || needsPeer && !hasPeer) {
			continue
		}
		out = append(out, w)
	}
	return []byte(strings.Join(out, " ") + "\n")
}

// checkPeerHost is the fuzzers' check of an accepted peer-host: a valid
// claim, and only beside an address.
func checkPeerHost(t *testing.T, peer netip.AddrPort, host string) {
	t.Helper()
	if host != "" && (!peer.IsValid() || len(host) > 63 || !referenceClaim.MatchString(host)) {
		t.Fatalf("accepted peer-host %q beside peer %v", host, peer)
	}
}
