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
		AttachProtocol: 1, SessionID: [16]byte{0x0f, 0x3a, 1, 2, 3},
		Name:      "quiet-heron",
		Started:   time.Unix(1794650000, 0),
		State:     SessionDetached,
		Since:     time.Unix(1794651234, 0),
		Peer:      netip.MustParseAddrPort("[2001:db8::7]:50123"),
		Holder:    [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		HasHolder: true,
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
			if got.AttachProtocol != 1 || got.SessionID != s.SessionID || !got.Started.Equal(s.Started) ||
				!got.Since.Equal(s.Since) || got.State != s.State || got.Peer != s.Peer ||
				got.Name != s.Name || got.HasHolder != s.HasHolder || got.HasHolder && got.Holder != s.Holder {
				t.Fatalf("%q parsed as %+v, not %+v", line, got, s)
			}
		}
	}
}

func TestTheLongestSessionLineFitsItsBound(t *testing.T) {
	s := sampleSessionLine()
	s.AttachProtocol = 255
	s.Started, s.Since = time.Unix(999999999999, 0), time.Unix(999999999999, 0)
	s.State = SessionDetached
	s.Peer = netip.MustParseAddrPort("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe]:65535")
	s.Name = strings.Repeat("n", MaxSessionName)
	line := MarshalSessionLine(s)
	if len(line) != 169 || len(line) > MaxSessionLine {
		t.Fatalf("%d bytes, not the 169 §9.2.1 derives, or over %d", len(line), MaxSessionLine)
	}
	if _, err := ParseSessionLine(line); err != nil {
		t.Fatal(err)
	}
	// The optional command adds a space and at most 1366 (§9.2.1).
	s.Command = strings.Repeat("é", MaxStartText/2)
	line = MarshalSessionLine(s)
	if len(line) != 1536 || len(line) > MaxSessionLine {
		t.Fatalf("%d bytes with a command, not the 1536 §9.2.1 derives, or over %d", len(line), MaxSessionLine)
	}
	if got, err := ParseSessionLine(line); err != nil || got.Command != s.Command {
		t.Fatalf("%+v, %v", got, err)
	}
}

// A session started with a command says so in its greeting, as an
// optional last field, so that a plain `mosey HOST COMMAND` can find it
// again; one started without has the greeting of before commands, byte
// for byte (§9.2.1).
func TestAGreetingCarriesTheCommandOnlyWhenTheSessionHasOne(t *testing.T) {
	s := sampleSessionLine()
	without := string(MarshalSessionLine(s))
	if strings.Count(without, " ") != 8 {
		t.Fatalf("a greeting without a command has %d spaces: %q", strings.Count(without, " "), without)
	}
	s.Command = "claude --resume\tü"
	with := MarshalSessionLine(s)
	if want := strings.TrimSuffix(without, "\n") + " Y2xhdWRlIC0tcmVzdW1lCcO8\n"; string(with) != want {
		t.Fatalf("%q, want %q", with, want)
	}
	got, err := ParseSessionLine(with)
	if err != nil || got.Command != s.Command || got.Name != s.Name || got.Holder != s.Holder {
		t.Fatalf("%+v, %v", got, err)
	}
}

func TestASessionLineThatBreaksARuleIsRefused(t *testing.T) {
	good := string(MarshalSessionLine(sampleSessionLine()))
	cases := map[string]string{
		"no LF":                    strings.TrimSuffix(good, "\n"),
		"CR":                       strings.Replace(good, "\n", "\r\n", 1),
		"double space":             strings.Replace(good, " ", "  ", 1),
		"unknown state":            strings.Replace(good, "detached", "gone", 1),
		"leading zero":             strings.Replace(good, " 1794650000 ", " 01794650000 ", 1),
		"13-digit time":            strings.Replace(good, " 1794650000 ", " 1794650000000 ", 1),
		"zoned peer":               strings.Replace(good, "[2001:db8::7]", "[fe80::1%eth0]", 1),
		"port 0":                   strings.Replace(good, ":50123", ":0", 1),
		"mapped peer":              strings.Replace(good, "[2001:db8::7]", "[::ffff:192.0.2.1]", 1),
		"short session id":         strings.Replace(good, " DzoBAgM", " DzoB", 1),
		"another magic":            strings.Replace(good, "MOSEY-SESSION", "MOSEY-SESSIONS", 1),
		"extra field":              strings.Replace(good, "\n", " x\n", 1),
		"bad name":                 strings.Replace(good, "quiet-heron", "-heron", 1),
		"short holder":             strings.Replace(good, " AQIDBAUGBwg\n", " AQID\n", 1),
		"no aproto":                strings.Replace(good, "MOSEY-SESSION 1 ", "MOSEY-SESSION ", 1),
		"aproto 0":                 strings.Replace(good, "MOSEY-SESSION 1 ", "MOSEY-SESSION 0 ", 1),
		"aproto over 255":          strings.Replace(good, "MOSEY-SESSION 1 ", "MOSEY-SESSION 256 ", 1),
		"aproto zero-led":          strings.Replace(good, "MOSEY-SESSION 1 ", "MOSEY-SESSION 01 ", 1),
		"an attach range":          strings.Replace(good, "MOSEY-SESSION 1 ", "MOSEY-SESSION 1-1 ", 1),
		"a swver as well":          strings.Replace(good, "MOSEY-SESSION 1 ", "MOSEY-SESSION 0.1.2 1 ", 1),
		"a dash command":           strings.Replace(good, "\n", " -\n", 1),
		"a command with a newline": strings.Replace(good, "\n", " "+b64.EncodeToString([]byte("a\nb"))+"\n", 1),
		"a command with an escape": strings.Replace(good, "\n", " "+b64.EncodeToString([]byte("a\x1b[2J"))+"\n", 1),
		"a command not utf-8":      strings.Replace(good, "\n", " "+b64.EncodeToString([]byte("a\xff"))+"\n", 1),
		"a command over 1024":      strings.Replace(good, "\n", " "+b64.EncodeToString(bytes.Repeat([]byte("a"), MaxStartText+1))+"\n", 1),
		"a padded command":         strings.Replace(good, "\n", " YQ==\n", 1),
		"two commands":             strings.Replace(good, "\n", " YQ YQ\n", 1),
	}
	for name, line := range cases {
		if _, err := ParseSessionLine([]byte(line)); !errors.Is(err, ErrBadLine) {
			t.Errorf("%s: %q gave %v", name, line, err)
		}
	}
}

// The greeting of a session of another attach protocol is read in full,
// so a launcher can name it and refuse it with both numbers (§9.2 step 5);
// whether it is attachable is the launcher's, not the parser's.
func TestAGreetingOfAnotherAttachProtocolStillParses(t *testing.T) {
	s := sampleSessionLine()
	s.AttachProtocol = 2
	got, err := ParseSessionLine(MarshalSessionLine(s))
	if err != nil || got.AttachProtocol != 2 || got.Name != s.Name {
		t.Fatalf("%+v %v", got, err)
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
	return ListLine{Name: "quiet-heron", State: SessionDetached, Since: time.Unix(1794651234, 0)}
}

// A list line round-trips, and its longest form fits its bound (§9.4).
func TestAListLineRoundTripsAndFitsItsBound(t *testing.T) {
	longest := ListLine{Name: strings.Repeat("n", 32), State: SessionDetached, Since: time.Unix(999999999999, 0)}
	for _, l := range []ListLine{sampleListLine(), longest} {
		line := MarshalListLine(l)
		got, err := ParseListLine(line)
		if err != nil || got.Name != l.Name || got.State != l.State || !got.Since.Equal(l.Since) {
			t.Errorf("%q: %+v, %v", line, got, err)
		}
	}
	if n := len(MarshalListLine(longest)); n != 68 || n > MaxListLine {
		t.Errorf("the longest list line is %d bytes, §9.4 says 68", n)
	}
	if got := string(MarshalListLine(sampleListLine())); got != "MOSEY-LIST 1 quiet-heron detached 1794651234\n" {
		t.Errorf("%q", got)
	}
	longest.Command = strings.Repeat("é", MaxStartText/2)
	line := MarshalListLine(longest)
	if got, err := ParseListLine(line); err != nil || got.Command != longest.Command {
		t.Errorf("%+v, %v", got, err)
	}
	if n := len(line); n != 1435 || n > MaxListLine {
		t.Errorf("the longest list line with a command is %d bytes, §9.4 says 1435", n)
	}
}

// A session's command is listed as an optional last field, and a session
// without one is listed exactly as before commands (§9.4).
func TestAListLineCarriesTheCommandOnlyWhenTheSessionHasOne(t *testing.T) {
	l := sampleListLine()
	l.Command = "claude"
	if got := string(MarshalListLine(l)); got != "MOSEY-LIST 1 quiet-heron detached 1794651234 Y2xhdWRl\n" {
		t.Errorf("%q", got)
	}
	if got, err := ParseListLine(MarshalListLine(l)); err != nil || got != l {
		t.Errorf("%+v, %v", got, err)
	}
}

// A hostile server's list line that would put anything but its grammar
// on the terminal is refused (§9.4, D9).
func TestAListLineThatBreaksARuleIsRefused(t *testing.T) {
	good := string(MarshalListLine(sampleListLine()))
	for name, line := range map[string]string{
		"an escape in the name":    strings.Replace(good, "quiet-heron", "quiet\x1b[2Jheron", 1),
		"a name over 32":           strings.Replace(good, "quiet-heron", strings.Repeat("q", 33), 1),
		"a bad state":              strings.Replace(good, "detached", "dead", 1),
		"another version":          strings.Replace(good, "MOSEY-LIST 1", "MOSEY-LIST 2", 1),
		"a bidi control":           strings.Replace(good, "quiet-heron", "quiet\u202eheron", 1),
		"a version as well":        strings.Replace(good, "\n", " 0.214.20261114\n", 1),
		"a long line":              strings.TrimSuffix(good, "\n") + strings.Repeat("9", 200) + "\n",
		"no LF":                    strings.TrimSuffix(good, "\n"),
		"a leading zero":           strings.Replace(good, " 1794651234\n", " 01794651234\n", 1),
		"another magic":            strings.Replace(good, "MOSEY-LIST", "MOSEY-LISTS", 1),
		"a missing field":          strings.Replace(good, " detached", "", 1),
		"no name":                  strings.Replace(good, "quiet-heron", "-", 1),
		"no state":                 strings.Replace(good, "detached", "-", 1),
		"no since":                 strings.Replace(good, " 1794651234\n", " -\n", 1),
		"a dash command":           strings.Replace(good, "\n", " -\n", 1),
		"an escape in the command": strings.Replace(good, "\n", " "+b64.EncodeToString([]byte("claude\x1b]0;pwned\x07"))+"\n", 1),
		"a C1 in the command":      strings.Replace(good, "\n", " "+b64.EncodeToString([]byte("claude\u009b2J"))+"\n", 1),
		"a newline in the command": strings.Replace(good, "\n", " "+b64.EncodeToString([]byte("a\rb"))+"\n", 1),
		"a command not utf-8":      strings.Replace(good, "\n", " "+b64.EncodeToString([]byte("\xc0\xaf"))+"\n", 1),
		"a command over 1024":      strings.Replace(good, "\n", " "+b64.EncodeToString(bytes.Repeat([]byte("a"), MaxStartText+1))+"\n", 1),
		"a command, not canonical": strings.Replace(good, "\n", " YR\n", 1),
	} {
		if _, err := ParseListLine([]byte(line)); !errors.Is(err, ErrBadLine) {
			t.Errorf("%s: %q gave %v", name, line, err)
		}
	}
}

func FuzzParseListLine(f *testing.F) {
	f.Add(MarshalListLine(sampleListLine()))
	f.Add([]byte("MOSEY-LIST 1 - - - dev\n"))
	withCommand := sampleListLine()
	withCommand.Command = "claude --resume\tü"
	f.Add(MarshalListLine(withCommand))
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
		for _, field := range []string{l.Name} {
			for i := 0; i < len(field); i++ {
				if field[i] <= ' ' || field[i] > '~' {
					t.Fatalf("accepted a field with byte 0x%02x: %q", field[i], line)
				}
			}
		}
		if !ValidSessionName(l.Name) {
			t.Fatalf("accepted name %q", l.Name)
		}
		if l.Command != "" && !referenceText(l.Command, true) {
			t.Fatalf("accepted command %q", l.Command)
		}
	})
}

func FuzzParseSessionLine(f *testing.F) {
	f.Add(MarshalSessionLine(sampleSessionLine()))
	n := sampleSessionLine()
	n.State, n.Peer, n.HasHolder = SessionNew, netip.AddrPort{}, false
	f.Add(MarshalSessionLine(n))
	n.Command = "sh -c 'echo $((6*7))'\tü"
	f.Add(MarshalSessionLine(n))
	f.Add([]byte("MOSEY-SESSION 1.2.3 and more\n"))
	f.Fuzz(func(t *testing.T, line []byte) {
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
		if s.Peer.IsValid() && (s.Peer.Port() == 0 || s.Peer.Addr().Zone() != "" || s.Peer.Addr().Is4In6()) {
			t.Fatalf("accepted peer %s", s.Peer)
		}
		if s.AttachProtocol < 1 || s.AttachProtocol > 255 {
			t.Fatalf("accepted attach protocol %d", s.AttachProtocol)
		}
		if !ValidSessionName(s.Name) {
			t.Fatalf("accepted name %q", s.Name)
		}
		if s.Command != "" && !referenceText(s.Command, true) || len(line) > MaxSessionLine {
			t.Fatalf("accepted command %q in %d bytes", s.Command, len(line))
		}
	})
}

// -list's output is read past a login shell's chatter, keeps only lines
// that parse, and stops at MaxListed (§9.4).
func TestReadListKeepsOnlyListLinesThatParse(t *testing.T) {
	good := MarshalListLine(sampleListLine())
	out := append([]byte("motd\r\nwelcome \x1b[31mred\x1b[0m\n"), good...)
	out = append(out, "MOSEY-LIST 1 bad\x1bname detached 1 v1\n"...)
	out = append(out, MarshalListLine(ListLine{Name: "other", State: SessionNew, Since: time.Unix(1, 0)})...)
	rows, dropped := ReadList(out)
	if len(rows) != 2 || dropped != 1 || rows[0].Name != "quiet-heron" || rows[1].Name != "other" {
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
	f.Add([]byte("MOSEY-LIST 1 a new 1 Y2xhdWRl\nMOSEY-LIST 1 b detached 2\n"))
	f.Fuzz(func(t *testing.T, out []byte) {
		rows, _ := ReadList(out)
		if len(rows) > MaxListed {
			t.Fatalf("%d rows", len(rows))
		}
		for _, r := range rows {
			if len(r.Name) > MaxSessionName ||
				r.Name != "" && !ValidSessionName(r.Name) ||
				r.Command != "" && !referenceText(r.Command, true) {
				t.Fatalf("row %+v", r)
			}
			if !bytes.Contains(out, MarshalListLine(r)) {
				t.Fatalf("row %+v is not a line of the input", r)
			}
		}
	})
}
