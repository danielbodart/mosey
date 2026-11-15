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
		Name:            "quiet-heron",
		Started:         time.Unix(1794650000, 0),
		State:           SessionDetached,
		Since:           time.Unix(1794651234, 0),
		Peer:            netip.MustParseAddrPort("[2001:db8::7]:50123"),
		Holder:          [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		HasHolder:       true,
	}
}

func TestASessionLineRoundTripsInEveryState(t *testing.T) {
	for _, st := range []SessionState{SessionNew, SessionAttached, SessionDetached} {
		for _, peer := range []netip.AddrPort{{}, netip.MustParseAddrPort("192.0.2.7:50000"), netip.MustParseAddrPort("[2001:db8::1]:1")} {
			s := sampleSessionLine()
			s.State, s.Peer, s.HasHolder = st, peer, peer.IsValid()
			line := MarshalSessionLine(s)
			got, err := ParseSessionLine(line)
			if err != nil {
				t.Fatalf("%q: %v", line, err)
			}
			if got.SoftwareVersion != s.SoftwareVersion || got.SessionID != s.SessionID || !got.Started.Equal(s.Started) ||
				!got.Since.Equal(s.Since) || got.State != s.State || got.Peer != s.Peer ||
				got.Name != s.Name || got.HasHolder != s.HasHolder || got.HasHolder && got.Holder != s.Holder {
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
	s.Name = strings.Repeat("n", MaxSessionName)
	line := MarshalSessionLine(s)
	if len(line) != 230 || len(line) > MaxSessionLine {
		t.Fatalf("%d bytes, not the 230 §9.2.1 derives, or over %d", len(line), MaxSessionLine)
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
		"bad name":         strings.Replace(good, "quiet-heron", "-heron", 1),
		"short holder":     strings.Replace(good, " AQIDBAUGBwg\n", " AQID\n", 1),
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

// -kill runs --serve=kill NAME, and only with a name that needs no
// quoting (§9.5); -list takes no name.
func TestTheKillRoleRunsServeEqualsKillWithTheName(t *testing.T) {
	s := SSH{Destination: "far", Server: "mosey", Role: RoleKill, RoleArg: "quiet-heron"}
	if err := s.Check(); err != nil {
		t.Fatal(err)
	}
	if got, want := s.RemoteCommand(), "exec /bin/sh -c 'exec mosey --serve=kill quiet-heron'"; got != want {
		t.Fatalf("%q, want %q", got, want)
	}
	var u *UsageError
	for _, bad := range []SSH{
		{Destination: "far", Role: RoleKill, RoleArg: "a'b"},
		{Destination: "far", Role: RoleKill, RoleArg: ""},
		{Destination: "far", Role: RoleKill, RoleArg: "x;reboot"},
		{Destination: "far", Role: RoleList, RoleArg: "work"},
	} {
		if err := bad.Check(); !errors.As(err, &u) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
}

// R3's background reconnect runs ssh in batch mode, so it never puts a
// question (§9.2.2); nothing else does.
func TestOnlyABatchBootstrapRunsSSHInBatchMode(t *testing.T) {
	for _, batch := range []bool{false, true} {
		cmd := SSH{Destination: "far", Server: "mosey", Batch: batch}.Command(t.Context(), Config{})
		has := strings.Contains(strings.Join(cmd.Args, " "), "-o BatchMode=yes")
		if has != batch {
			t.Errorf("batch %v: argv %q", batch, cmd.Args)
		}
		detached := cmd.SysProcAttr != nil && cmd.SysProcAttr.Setsid
		if detached != batch {
			t.Errorf("batch %v: in a session of its own: %v", batch, detached)
		}
	}
}

func sampleListLine() ListLine {
	return ListLine{Name: "quiet-heron", State: SessionDetached, Since: time.Unix(1794651234, 0), SoftwareVersion: "0.214.20261114"}
}

// A list line round-trips, including another version's session whose
// name and state are unknown, and its longest form fits its bound (§9.4).
func TestAListLineRoundTripsAndFitsItsBound(t *testing.T) {
	longest := ListLine{Name: strings.Repeat("n", 32), State: SessionDetached, Since: time.Unix(999999999999, 0), SoftwareVersion: strings.Repeat("9", 64)}
	for _, l := range []ListLine{sampleListLine(), {SoftwareVersion: "9.9.9"}, longest} {
		line := MarshalListLine(l)
		got, err := ParseListLine(line)
		if err != nil || got.Name != l.Name || got.State != l.State || !got.Since.Equal(l.Since) || got.SoftwareVersion != l.SoftwareVersion {
			t.Errorf("%q: %+v, %v", line, got, err)
		}
	}
	if n := len(MarshalListLine(longest)); n != 133 || n > MaxListLine {
		t.Errorf("the longest list line is %d bytes, §9.4 says 133", n)
	}
	if got := string(MarshalListLine(sampleListLine())); got != "MOSEY-LIST 1 quiet-heron detached 1794651234 0.214.20261114\n" {
		t.Errorf("%q", got)
	}
}

// A hostile server's list line that would put anything but its grammar
// on the terminal is refused (§9.4, D9).
func TestAListLineThatBreaksARuleIsRefused(t *testing.T) {
	good := string(MarshalListLine(sampleListLine()))
	for name, line := range map[string]string{
		"an escape in the name": strings.Replace(good, "quiet-heron", "quiet\x1b[2Jheron", 1),
		"a name over 32":        strings.Replace(good, "quiet-heron", strings.Repeat("q", 33), 1),
		"a bad state":           strings.Replace(good, "detached", "dead", 1),
		"another version":       strings.Replace(good, "MOSEY-LIST 1", "MOSEY-LIST 2", 1),
		"a bidi control":        strings.Replace(good, "0.214", "0.\u202e214", 1),
		"a long line":           strings.TrimSuffix(good, "\n") + strings.Repeat("9", 200) + "\n",
		"no LF":                 strings.TrimSuffix(good, "\n"),
		"a leading zero":        strings.Replace(good, " 1794651234 ", " 01794651234 ", 1),
		"another magic":         strings.Replace(good, "MOSEY-LIST", "MOSEY-LISTS", 1),
		"a missing field":       strings.Replace(good, " detached", "", 1),
	} {
		if _, err := ParseListLine([]byte(line)); !errors.Is(err, ErrBadLine) {
			t.Errorf("%s: %q gave %v", name, line, err)
		}
	}
}

func FuzzParseListLine(f *testing.F) {
	f.Add(MarshalListLine(sampleListLine()))
	f.Add(MarshalListLine(ListLine{SoftwareVersion: "dev"}))
	f.Add([]byte("MOSEY-LIST 1 - - - dev\n"))
	f.Fuzz(func(t *testing.T, line []byte) {
		l, err := ParseListLine(line)
		if err != nil {
			if !errors.Is(err, ErrBadLine) {
				t.Fatalf("an error that is not ErrBadLine: %v", err)
			}
			return
		}
		if !bytes.Equal(MarshalListLine(l), line) || len(line) > MaxListLine {
			t.Fatalf("accepted %q, which re-marshals differently", line)
		}
		for _, field := range []string{l.Name, l.SoftwareVersion} {
			for i := 0; i < len(field); i++ {
				if field[i] <= ' ' || field[i] > '~' {
					t.Fatalf("accepted a field with byte 0x%02x: %q", field[i], line)
				}
			}
		}
		if l.Name != "" && !ValidSessionName(l.Name) {
			t.Fatalf("accepted name %q", l.Name)
		}
	})
}

func FuzzParseSessionLine(f *testing.F) {
	f.Add(MarshalSessionLine(sampleSessionLine()))
	n := sampleSessionLine()
	n.State, n.Peer, n.HasHolder = SessionNew, netip.AddrPort{}, false
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
		if !ValidSessionName(s.Name) {
			t.Fatalf("accepted name %q", s.Name)
		}
	})
}

// -list's output is read past a login shell's chatter, keeps only lines
// that parse, and stops at MaxListed (§9.4).
func TestReadListKeepsOnlyListLinesThatParse(t *testing.T) {
	good := MarshalListLine(sampleListLine())
	out := append([]byte("motd\r\nwelcome \x1b[31mred\x1b[0m\n"), good...)
	out = append(out, "MOSEY-LIST 1 bad\x1bname detached 1 v1\n"...)
	out = append(out, MarshalListLine(ListLine{SoftwareVersion: "v9"})...)
	rows, dropped := ReadList(out)
	if len(rows) != 2 || dropped != 1 || rows[0].Name != "quiet-heron" || rows[1].SoftwareVersion != "v9" {
		t.Fatalf("%+v, dropped %d", rows, dropped)
	}
	many := bytes.Repeat(good, MaxListed+3)
	if rows, dropped := ReadList(many); len(rows) != MaxListed || dropped != 3 {
		t.Errorf("%d rows, %d dropped", len(rows), dropped)
	}
}

func FuzzReadList(f *testing.F) {
	f.Add(append([]byte("noise\n"), MarshalListLine(sampleListLine())...))
	f.Add([]byte("MOSEY-LIST 1 a new 1 v\nMOSEY-LIST 1 - - - v"))
	f.Fuzz(func(t *testing.T, out []byte) {
		rows, _ := ReadList(out)
		if len(rows) > MaxListed {
			t.Fatalf("%d rows", len(rows))
		}
		for _, r := range rows {
			if len(r.Name) > MaxSessionName || len(r.SoftwareVersion) > maxSoftwareVersion ||
				r.Name != "" && !ValidSessionName(r.Name) || !ValidSoftwareVersion(r.SoftwareVersion) {
				t.Fatalf("row %+v", r)
			}
			if !bytes.Contains(out, MarshalListLine(r)) {
				t.Fatalf("row %+v is not a line of the input", r)
			}
		}
	})
}
