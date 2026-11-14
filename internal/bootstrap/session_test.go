package bootstrap

import (
	"bytes"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func sampleSessionLine() SessionLine {
	return SessionLine{
		SoftwareVersion: "0.214.20261114093012",
		SessionID:       [16]byte{0x0f, 0x3a, 1, 2, 3},
		Started:         time.Unix(1794650000, 0),
		State:           SessionDetached,
		Since:           time.Unix(1794651234, 0),
		Peer:            netip.MustParseAddrPort("[2001:db8::7]:50123"),
	}
}

func TestASessionLineRoundTripsInEveryState(t *testing.T) {
	for _, st := range []SessionState{SessionNew, SessionAttached, SessionDetached} {
		for _, peer := range []netip.AddrPort{{}, netip.MustParseAddrPort("192.0.2.7:50000"), netip.MustParseAddrPort("[2001:db8::1]:1")} {
			s := sampleSessionLine()
			s.State, s.Peer = st, peer
			line := MarshalSessionLine(s)
			got, err := ParseSessionLine(line)
			if err != nil {
				t.Fatalf("%q: %v", line, err)
			}
			if got.SoftwareVersion != s.SoftwareVersion || got.SessionID != s.SessionID || !got.Started.Equal(s.Started) ||
				!got.Since.Equal(s.Since) || got.State != s.State || got.Peer != s.Peer {
				t.Fatalf("%q parsed as %+v, not %+v", line, got, s)
			}
			if v, err := SessionLineVersion(line); err != nil || v != s.SoftwareVersion {
				t.Fatalf("SessionLineVersion(%q) = %q, %v", line, v, err)
			}
		}
	}
}

func TestTheLongestSessionLineFitsItsBound(t *testing.T) {
	s := sampleSessionLine()
	s.SoftwareVersion = strings.Repeat("9", 64)
	s.Started, s.Since = time.Unix(999999999999, 0), time.Unix(999999999999, 0)
	s.State = SessionDetached
	s.Peer = netip.MustParseAddrPort("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe]:65535")
	line := MarshalSessionLine(s)
	if len(line) > MaxSessionLine {
		t.Fatalf("%d bytes, over %d", len(line), MaxSessionLine)
	}
	if _, err := ParseSessionLine(line); err != nil {
		t.Fatal(err)
	}
}

func TestASessionLineThatBreaksARuleIsRefused(t *testing.T) {
	good := string(MarshalSessionLine(sampleSessionLine()))
	cases := map[string]string{
		"no LF":            strings.TrimSuffix(good, "\n"),
		"CR":               strings.Replace(good, "\n", "\r\n", 1),
		"double space":     strings.Replace(good, " ", "  ", 1),
		"unknown state":    strings.Replace(good, "detached", "gone", 1),
		"leading zero":     strings.Replace(good, " 1794650000 ", " 01794650000 ", 1),
		"13-digit time":    strings.Replace(good, " 1794650000 ", " 1794650000000 ", 1),
		"zoned peer":       strings.Replace(good, "[2001:db8::7]", "[fe80::1%eth0]", 1),
		"port 0":           strings.Replace(good, ":50123", ":0", 1),
		"mapped peer":      strings.Replace(good, "[2001:db8::7]", "[::ffff:192.0.2.1]", 1),
		"short session id": strings.Replace(good, " DzoBAgM", " DzoB", 1),
		"another magic":    strings.Replace(good, "MOSEY-SESSION", "MOSEY-SESSIONS", 1),
		"extra field":      strings.Replace(good, "\n", " x\n", 1),
	}
	for name, line := range cases {
		if _, err := ParseSessionLine([]byte(line)); !errors.Is(err, ErrBadLine) {
			t.Errorf("%s: %q gave %v", name, line, err)
		}
	}
}

// The first two fields are frozen (§9.2.1): a later version's greeting,
// whatever follows them, still tells this launcher the session's version.
func TestALaterVersionsGreetingStillGivesItsVersion(t *testing.T) {
	for _, line := range []string{
		"MOSEY-SESSION 9.9.9\n",
		"MOSEY-SESSION 9.9.9 whatever a later version says=here\n",
	} {
		if v, err := SessionLineVersion([]byte(line)); err != nil || v != "9.9.9" {
			t.Errorf("%q: %q, %v", line, v, err)
		}
	}
	for _, line := range []string{"", "MOSEY-SESSION\n", "MOSEY-SESSION 9.9\x1b9\n", "MOSEY-CLIENT 9.9.9\n", "MOSEY-SESSION " + strings.Repeat("x", 300) + "\n"} {
		if _, err := SessionLineVersion([]byte(line)); !errors.Is(err, ErrBadLine) {
			t.Errorf("%q gave %v", line, err)
		}
	}
}

func TestTheAnySessionIdIsAllZeros(t *testing.T) {
	if AnySession != [16]byte{} {
		t.Fatal("AnySession is not the all-zero id")
	}
	line := MarshalClientLine(ClientLine{SoftwareVersion: "dev", Resume: true, SessionID: AnySession, Cols: 80, Rows: 24, Public: make([]byte, PublicKeySize)})
	if !bytes.Contains(line, []byte(" resume:AAAAAAAAAAAAAAAAAAAAAA ")) {
		t.Fatalf("%q", line)
	}
	if c, err := ParseClientLine(line); err != nil || !c.Resume || c.SessionID != AnySession {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestTheListRoleRunsServeEqualsList(t *testing.T) {
	s := SSH{Destination: "far", Server: "mosey", Role: RoleList}
	if err := s.Check(); err != nil {
		t.Fatal(err)
	}
	if got, want := s.RemoteCommand(), "exec /bin/sh -c 'exec mosey --serve=list'"; got != want {
		t.Fatalf("%q, want %q", got, want)
	}
	s.Role = "spawner"
	var u *UsageError
	if err := s.Check(); !errors.As(err, &u) {
		t.Fatalf("role spawner: %v", err)
	}
}

func FuzzParseSessionLine(f *testing.F) {
	f.Add(MarshalSessionLine(sampleSessionLine()))
	n := sampleSessionLine()
	n.State, n.Peer = SessionNew, netip.AddrPort{}
	f.Add(MarshalSessionLine(n))
	f.Add([]byte("MOSEY-SESSION 1.2.3 and more\n"))
	f.Fuzz(func(t *testing.T, line []byte) {
		v, verr := SessionLineVersion(line)
		s, err := ParseSessionLine(line)
		if err != nil {
			if !errors.Is(err, ErrBadLine) {
				t.Fatalf("an error that is not ErrBadLine: %v", err)
			}
			return
		}
		if !bytes.Equal(MarshalSessionLine(s), line) {
			t.Fatalf("accepted %q, which re-marshals differently", line)
		}
		if verr != nil || v != s.SoftwareVersion {
			t.Fatalf("SessionLineVersion disagrees on %q: %q, %v", line, v, verr)
		}
		if s.Peer.IsValid() && (s.Peer.Port() == 0 || s.Peer.Addr().Zone() != "" || s.Peer.Addr().Is4In6()) {
			t.Fatalf("accepted peer %s", s.Peer)
		}
	})
}
