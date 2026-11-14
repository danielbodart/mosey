package server

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/danielbodart/mosey/internal/bootstrap"
	"github.com/danielbodart/mosey/internal/ipc"
)

// The spawner's check of proto's Credential (server.md §3.4, §12): the
// spawner is unsandboxed, so the line a compromised proto hands it reaches
// stdout only if it carries exactly the spawner's own address, port and
// version and is the canonical encoding of what it says.
func TestTheSpawnerTakesOnlyACredentialLineWithItsOwnFields(t *testing.T) {
	needs(t, "bootstrap", func() { bootstrap.MarshalCredentialLine(bootstrap.CredentialLine{}) })
	addr := netip.MustParseAddr("192.0.2.7")
	good := bootstrap.CredentialLine{
		SoftwareVersion: "v1",
		Addr:            addr,
		Port:            60001,
		CredentialID:    [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		SessionID:       [16]byte{9},
		PSK:             [32]byte{10},
		Public:          bytes.Repeat([]byte{0x5a}, ipc.PublicKeySize),
	}
	line := bootstrap.MarshalCredentialLine(good)
	if err := checkCredential(line, addr, 60001, "v1"); err != nil {
		t.Fatalf("the spawner refused its own session's line: %v", err)
	}
	for _, c := range []struct {
		name string
		line []byte
	}{
		{"another port", bootstrap.MarshalCredentialLine(with(good, func(l *bootstrap.CredentialLine) { l.Port = 60002 }))},
		{"another address", bootstrap.MarshalCredentialLine(with(good, func(l *bootstrap.CredentialLine) { l.Addr = netip.MustParseAddr("192.0.2.8") }))},
		{"no address", bootstrap.MarshalCredentialLine(with(good, func(l *bootstrap.CredentialLine) { l.Addr = netip.Addr{} }))},
		{"another version", bootstrap.MarshalCredentialLine(with(good, func(l *bootstrap.CredentialLine) { l.SoftwareVersion = "v2" }))},
		{"a control byte", append(bytes.TrimSuffix(line, []byte("\n")), '\x1b', '\n')},
		{"two lines", append(append([]byte(nil), line...), line...)},
		{"no newline", bytes.TrimSuffix(line, []byte("\n"))},
		{"empty", nil},
	} {
		if err := checkCredential(c.line, addr, 60001, "v1"); err == nil {
			t.Errorf("%s: accepted %q", c.name, c.line)
		}
	}
}

func with(l bootstrap.CredentialLine, f func(*bootstrap.CredentialLine)) bootstrap.CredentialLine {
	f(&l)
	return l
}
