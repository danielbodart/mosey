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
	s.Command = strings.Repeat("é", MaxStartText/2)
	line := MarshalSessionLine(s)
	// 1588 with a 5-digit number (§9.2.1); 255 is three.
	if len(line) != 1588-2 || len(line) > MaxSessionLine {
		t.Fatalf("%d bytes, not the 1586 §9.2.1 derives for aproto 255, or over %d", len(line), MaxSessionLine)
	}
	if got, err := ParseSessionLine(line); err != nil || got.Command != s.Command {
		t.Fatalf("%+v, %v", got, err)
	}
}

// A session started with a command says so in its greeting, as an
// optional critical field, so that a plain `mosey HOST COMMAND` can find
// it again (§9.2.1).
func TestAGreetingCarriesTheCommandOnlyWhenTheSessionHasOne(t *testing.T) {
	s := sampleSessionLine()
	without := string(MarshalSessionLine(s))
	if want := "MOSEY-SESSION 1 !holder=AQIDBAUGBwg !name=quiet-heron peer=[2001:db8::7]:50123 !sid=DzoBAgMAAAAAAAAAAAAAAA since=1794651234 started=1794650000 !state=detached\n"; without != want {
		t.Fatalf("%q, want %q", without, want)
	}
	s.Command = "claude --resume\tü"
	with := MarshalSessionLine(s)
	if want := addField(without, "!cmd=Y2xhdWRlIC0tcmVzdW1lCcO8"); string(with) != want {
		t.Fatalf("%q, want %q", with, want)
	}
	got, err := ParseSessionLine(with)
	if err != nil || got.Command != s.Command || got.Name != s.Name || got.Holder != s.Holder {
		t.Fatalf("%+v, %v", got, err)
	}
}

func TestASessionLineThatBreaksARuleIsRefused(t *testing.T) {
	good := string(MarshalSessionLine(sampleSessionLine()))
	set := func(key, word string) string { return setField(t, good, key, word) }
	cases := map[string]string{
		"no LF":                    strings.TrimSuffix(good, "\n"),
		"CR":                       strings.Replace(good, "\n", "\r\n", 1),
		"double space":             strings.Replace(good, " ", "  ", 1),
		"unknown state":            set("state", "!state=gone"),
		"leading zero":             set("started", "started=01794650000"),
		"13-digit time":            set("started", "started=1794650000000"),
		"zoned peer":               set("peer", "peer=[fe80::1%eth0]:50123"),
		"port 0":                   set("peer", "peer=[2001:db8::7]:0"),
		"mapped peer":              set("peer", "peer=[::ffff:192.0.2.1]:50123"),
		"a dash peer":              set("peer", "peer=-"),
		"short session id":         set("sid", "!sid=DzoB"),
		"another magic":            strings.Replace(good, "MOSEY-SESSION", "MOSEY-SESSIONS", 1),
		"a positional word":        strings.Replace(good, "\n", " x\n", 1),
		"bad name":                 set("name", "!name=-heron"),
		"short holder":             set("holder", "!holder=AQID"),
		"no name":                  set("name", ""),
		"no sid":                   set("sid", ""),
		"no state":                 set("state", ""),
		"no since":                 set("since", ""),
		"no started":               set("started", ""),
		"state unmarked":           set("state", "state=detached"),
		"holder unmarked":          set("holder", "holder=AQIDBAUGBwg"),
		"peer marked":              set("peer", "!peer=[2001:db8::7]:50123"),
		"no aproto":                strings.Replace(good, "MOSEY-SESSION 1 ", "MOSEY-SESSION ", 1),
		"aproto 0":                 strings.Replace(good, "MOSEY-SESSION 1 ", "MOSEY-SESSION 0 ", 1),
		"aproto over 255":          strings.Replace(good, "MOSEY-SESSION 1 ", "MOSEY-SESSION 256 ", 1),
		"aproto zero-led":          strings.Replace(good, "MOSEY-SESSION 1 ", "MOSEY-SESSION 01 ", 1),
		"an attach range":          strings.Replace(good, "MOSEY-SESSION 1 ", "MOSEY-SESSION 1-1 ", 1),
		"a dash command":           addField(good, "!cmd=-"),
		"a command with a newline": addField(good, "!cmd="+b64.EncodeToString([]byte("a\nb"))),
		"a command with an escape": addField(good, "!cmd="+b64.EncodeToString([]byte("a\x1b[2J"))),
		"a command not utf-8":      addField(good, "!cmd="+b64.EncodeToString([]byte("a\xff"))),
		"a command over 1024":      addField(good, "!cmd="+b64.EncodeToString(bytes.Repeat([]byte("a"), MaxStartText+1))),
		"a padded command":         addField(good, "!cmd=YQ=="),
		"an unmarked command":      addField(good, "cmd=YQ"),
		"two commands":             addField(addField(good, "!cmd=YQ"), "!cmd=YQ"),
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

// A greeting is open like every line (versioning.md §7): an unknown field
// changes nothing, and an unknown critical one is refused, but with every
// known field still read and Unknown set, so the launcher can name the
// session it will not attach (§9.2 step 5).
func TestAGreetingWithAnUnknownCriticalFieldIsNamedButRefused(t *testing.T) {
	s := sampleSessionLine()
	s.Command = "ls"
	good := string(MarshalSessionLine(s))
	same := func(a, b SessionLine) bool { return bytes.Equal(MarshalSessionLine(a), MarshalSessionLine(b)) }
	for _, f := range unknownFields {
		got, err := ParseSessionLine([]byte(addField(good, f)))
		if err != nil || !same(got, s) || got.Unknown != "" {
			t.Errorf("with %s: %+v, %v", f, got, err)
		}
		got, err = ParseSessionLine([]byte(addField(good, "!"+f)))
		var ce *CriticalError
		k := f[:strings.IndexByte(f, '=')]
		if !errors.As(err, &ce) || ce.Key != k || got.Unknown != k || !same(got, s) {
			t.Errorf("with !%s: %+v, %v", f, got, err)
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
	if got := string(MarshalListLine(sampleListLine())); got != "MOSEY-LIST 1 name=quiet-heron since=1794651234 state=detached\n" {
		t.Errorf("%q", got)
	}
	longest.Command = strings.Repeat("é", MaxStartText/2)
	line := MarshalListLine(longest)
	if got, err := ParseListLine(line); err != nil || got.Command != longest.Command {
		t.Errorf("%+v, %v", got, err)
	}
	// 1460 with a 5-digit number (§9.4); this one has one digit.
	if n := len(line); n != 1460-4 || n > MaxListLine {
		t.Errorf("the longest list line is %d bytes, §9.4 says 1456 for number 1", n)
	}
}

// A session's command is listed as an optional field (§9.4).
func TestAListLineCarriesTheCommandOnlyWhenTheSessionHasOne(t *testing.T) {
	l := sampleListLine()
	l.Command = "claude"
	if got := string(MarshalListLine(l)); got != "MOSEY-LIST 1 cmd=Y2xhdWRl name=quiet-heron since=1794651234 state=detached\n" {
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
	set := func(key, word string) string { return setField(t, good, key, word) }
	for name, line := range map[string]string{
		"an escape in the name":    set("name", "name=quiet\x1b[2Jheron"),
		"a name over 32":           set("name", "name="+strings.Repeat("q", 33)),
		"a bad state":              set("state", "state=dead"),
		"another version":          strings.Replace(good, "MOSEY-LIST 1", "MOSEY-LIST 2", 1),
		"a bidi control":           set("name", "name=quiet‮heron"),
		"a positional word":        strings.Replace(good, "\n", " 0.214.20261114\n", 1),
		"a long line":              addField(good, "zz="+strings.Repeat("9", MaxListLine)),
		"no LF":                    strings.TrimSuffix(good, "\n"),
		"a leading zero":           set("since", "since=01794651234"),
		"another magic":            strings.Replace(good, "MOSEY-LIST", "MOSEY-LISTS", 1),
		"no name":                  set("name", ""),
		"no state":                 set("state", ""),
		"no since":                 set("since", ""),
		"a dash name":              set("name", "name=-"),
		"a marked name":            set("name", "!name=quiet-heron"),
		"a dash command":           addField(good, "cmd=-"),
		"an escape in the command": addField(good, "cmd="+b64.EncodeToString([]byte("claude\x1b]0;pwned\x07"))),
		"a C1 in the command":      addField(good, "cmd="+b64.EncodeToString([]byte("claude\u009b2J"))),
		"a newline in the command": addField(good, "cmd="+b64.EncodeToString([]byte("a\rb"))),
		"a command not utf-8":      addField(good, "cmd="+b64.EncodeToString([]byte("\xc0\xaf"))),
		"a command over 1024":      addField(good, "cmd="+b64.EncodeToString(bytes.Repeat([]byte("a"), MaxStartText+1))),
		"a command, not canonical": addField(good, "cmd=YR"),
	} {
		if _, err := ParseListLine([]byte(line)); !errors.Is(err, ErrBadLine) {
			t.Errorf("%s: %q gave %v", name, line, err)
		}
	}
}

func FuzzParseListLine(f *testing.F) {
	f.Add(MarshalListLine(sampleListLine()))
	f.Add([]byte("MOSEY-LIST 1 name=a since=1 state=new zz=dev\n"))
	f.Add([]byte("MOSEY-LIST 1 name=a since=1 state=new !zz=dev\n"))
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
		if len(line) > MaxListLine {
			t.Fatalf("accepted %d bytes", len(line))
		}
		fuzzLine(t, line, MaxListLine, listMagic, false, listSpec, ParseListLine, MarshalListLine, l)
		for i := 0; i < len(l.Name); i++ {
			if l.Name[i] <= ' ' || l.Name[i] > '~' {
				t.Fatalf("accepted a name with byte 0x%02x: %q", l.Name[i], line)
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
	f.Add([]byte(addField(string(MarshalSessionLine(n)), "later=1")))
	f.Add([]byte(addField(string(MarshalSessionLine(n)), "!later=1")))
	f.Add([]byte("MOSEY-SESSION 1.2.3 and more\n"))
	f.Add([]byte("MOSEY-SESSION 1 a0=0 !name=0 !sid=000000000000000000000A since=0 started=0 !state=new\n"))
	f.Fuzz(func(t *testing.T, line []byte) {
		s, err := ParseSessionLine(line)
		var ce *CriticalError
		if errors.As(err, &ce) {
			// Refused, but named: every known field read, Unknown its key.
			if s.Unknown != ce.Key || !ValidSessionName(s.Name) {
				t.Fatalf("refused %q as %v with %+v", line, err, s)
			}
			return
		}
		if err != nil {
			if !errors.Is(err, ErrBadLine) {
				t.Fatalf("an error that is not ErrBadLine: %v", err)
			}
			return
		}
		fuzzLine(t, line, MaxSessionLine, sessionMagic, true, sessionSpec,
			func(b []byte) (SessionLine, error) {
				s, err := ParseSessionLine(b)
				if s.Unknown != "" && err == nil {
					t.Fatalf("Unknown %q set on an accepted line", s.Unknown)
				}
				return s, err
			}, MarshalSessionLine, s)
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
	out = append(out, "MOSEY-LIST 1 name=bad\x1bname since=1 state=detached\n"...)
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
	f.Add([]byte("MOSEY-LIST 1 name=a since=1 state=new zz=v\nMOSEY-LIST 1 name=- state=- v"))
	f.Add([]byte("MOSEY-LIST 1 cmd=Y2xhdWRl name=a since=1 state=new\nMOSEY-LIST 1 name=b since=2 state=detached\n"))
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
		}
	})
}
