package bootstrap

import (
	"bytes"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func key(fill byte) []byte { return bytes.Repeat([]byte{fill}, PublicKeySize) }

func sampleClientLine() ClientLine {
	return ClientLine{
		Cols:   211,
		Rows:   58,
		Env:    map[string]string{"TERM": "xterm-256color", "LANG": "en_GB.UTF-8", "COLORTERM": "truecolor"},
		Public: key(7),
	}
}

func sampleCredentialLine() CredentialLine {
	return CredentialLine{
		Addr:         netip.MustParseAddr("192.0.2.7"),
		Port:         60001,
		CredentialID: [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		SessionID:    [16]byte{9: 9},
		Name:         "quiet-heron",
		PSK:          [32]byte{31: 0xff},
		Public:       key(3),
	}
}

func TestAClientLineSurvivesARoundTrip(t *testing.T) {
	max := ClientLine{
		Attach:    AttachResume,
		SessionID: [16]byte{1, 2, 3},
		Holder:    [8]byte{4, 5},
		HasHolder: true,
		Agent:     true,
		Cols:      65535,
		Rows:      65535,
		Env:       map[string]string{},
		Dir:       strings.Repeat("d", MaxStartText),
		Type:      strings.Repeat("t", MaxStartText),
		Public:    key(0xee),
	}
	for _, n := range EnvNames {
		max.Env[n] = strings.Repeat("x", 64)
	}
	for _, c := range []ClientLine{sampleClientLine(), max, {Cols: 1, Rows: 1, Public: key(0)}} {
		line := MarshalClientLine(c)
		got, err := ParseClientLine(line)
		if err != nil {
			t.Fatalf("%s: %v", line[:60], err)
		}
		if !bytes.Equal(MarshalClientLine(got), line) {
			t.Errorf("round trip changed %s", line[:60])
		}
		if len(line) > MaxClientLine {
			t.Errorf("line of %d bytes over MaxClientLine", len(line))
		}
	}
	// The longest legal line is the size §6.2 derives.
	if n := len(MarshalClientLine(max)); n != 5708 {
		t.Errorf("longest client line is %d bytes, §6.2 says 5708", n)
	}
}

// Every attach of §6.2 survives a round trip as the field the spec shows.
func TestEveryAttachIsWrittenAsTheSpecShows(t *testing.T) {
	sid := [16]byte{1}
	for want, c := range map[string]ClientLine{
		" auto ":                          {Attach: AttachAuto},
		" new ":                           {Attach: AttachNew},
		" new:work ":                      {Attach: AttachNew, Name: "work"},
		" name:a.b_c ":                    {Attach: AttachName, Name: "a.b_c"},
		" resume:AQAAAAAAAAAAAAAAAAAAAA ": {Attach: AttachResume, SessionID: sid},
		" resume:AQAAAAAAAAAAAAAAAAAAAA:CQAAAAAAAAA ": {Attach: AttachResume, SessionID: sid, Holder: [8]byte{9}, HasHolder: true},
	} {
		c.Cols, c.Rows, c.Public = 80, 24, key(1)
		line := MarshalClientLine(c)
		if !bytes.Contains(line, []byte(want)) {
			t.Errorf("%+v: %q has no %q", c, line[:60], want)
		}
		got, err := ParseClientLine(line)
		if err != nil || got.Attach != c.Attach || got.Name != c.Name || got.SessionID != c.SessionID ||
			got.Holder != c.Holder || got.HasHolder != c.HasHolder {
			t.Errorf("%q parsed as %+v, %v", want, got, err)
		}
	}
}

// A name that is not an sname, an empty holder and the all-zero session
// id are each refused (§6.2).
func TestABadAttachIsRefused(t *testing.T) {
	good := string(MarshalClientLine(ClientLine{Attach: AttachName, Name: "work", Cols: 80, Rows: 24, Public: key(1)}))
	for name, attach := range map[string]string{
		"leading dash":   "name:-work",
		"leading dot":    "name:.work",
		"empty name":     "name:",
		"33 bytes":       "name:" + strings.Repeat("a", 33),
		"a slash":        "name:a/b",
		"a colon":        "name:a:b",
		"empty new name": "new:",
		"zero sid":       "resume:AAAAAAAAAAAAAAAAAAAAAA",
		"empty holder":   "resume:AQAAAAAAAAAAAAAAAAAAAA:",
		"short holder":   "resume:AQAAAAAAAAAAAAAAAAAAAA:CQAA",
		"two holders":    "resume:AQAAAAAAAAAAAAAAAAAAAA:CQAAAAAAAAA:CQAAAAAAAAA",
		"upper case":     "AUTO",
	} {
		line := strings.Replace(good, "name:work", attach, 1)
		if _, err := ParseClientLine([]byte(line)); !errors.Is(err, ErrBadLine) {
			t.Errorf("%s: %q gave %v", name, attach, err)
		}
	}
	for _, n := range []string{"a", "A9", "quiet-heron", "x.y_z-1", strings.Repeat("z", 32)} {
		if !ValidSessionName(n) {
			t.Errorf("%q refused", n)
		}
	}
}

func TestTheClientLineIsWhatTheSpecShows(t *testing.T) {
	line := string(MarshalClientLine(sampleClientLine()))
	want := "MOSEY-CLIENT 2 new no 211 58 COLORTERM=truecolor,LANG=en_GB.UTF-8,TERM=xterm-256color - - "
	if !strings.HasPrefix(line, want) || !strings.HasSuffix(line, "\n") {
		t.Errorf("got %q", line[:len(want)])
	}
}

func TestACredentialLineSurvivesARoundTrip(t *testing.T) {
	longest := sampleCredentialLine()
	longest.Addr = netip.MustParseAddr("2001:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	longest.Port = 65535
	longest.Name = strings.Repeat("n", MaxSessionName)
	noAddr := sampleCredentialLine()
	noAddr.Addr = netip.Addr{}
	for _, c := range []CredentialLine{sampleCredentialLine(), longest, noAddr} {
		line := MarshalCredentialLine(c)
		got, err := ParseCredentialLine(line)
		if err != nil {
			t.Fatalf("%s: %v", line[:60], err)
		}
		if got.Addr != c.Addr || got.Port != c.Port || got.CredentialID != c.CredentialID ||
			got.SessionID != c.SessionID || got.PSK != c.PSK || !bytes.Equal(got.Public, c.Public) ||
			got.Name != c.Name {
			t.Errorf("round trip changed %+v", got)
		}
	}
	if n := len(MarshalCredentialLine(longest)); n != 1797 {
		t.Errorf("longest credential line is %d bytes, §6.3 says 1797", n)
	}
}

// Each rule of §6.1 broken once, on a line that is otherwise good.
func TestEveryRuleOfAClientLineIsEnforced(t *testing.T) {
	good := string(MarshalClientLine(sampleClientLine()))
	pub := string(MarshalClientLine(sampleClientLine()))
	pub = pub[strings.LastIndexByte(pub, ' ')+1 : len(pub)-1]
	head := "MOSEY-CLIENT 2 new no 80 24 "
	for name, line := range map[string]string{
		"CR before LF":         strings.TrimSuffix(good, "\n") + "\r\n",
		"no LF":                strings.TrimSuffix(good, "\n"),
		"double space":         strings.Replace(good, " new", "  new", 1),
		"trailing space":       strings.TrimSuffix(good, "\n") + " \n",
		"leading space":        " " + good,
		"tab":                  strings.Replace(good, " new", "\tnew", 1),
		"padding":              head + "- - - " + pub + "==\n",
		"short key":            head + "- - - " + pub[1:] + "\n",
		"trailing bits":        head + "- - - " + pub[:len(pub)-1] + "B\n",
		"not base64url":        head + "- - - " + strings.Replace(pub, pub[:1], "+", 1) + "\n",
		"leading zero cols":    "MOSEY-CLIENT 2 new no 080 24 - - - " + pub + "\n",
		"zero cols":            "MOSEY-CLIENT 2 new no 0 24 - - - " + pub + "\n",
		"cols 65536":           "MOSEY-CLIENT 2 new no 65536 24 - - - " + pub + "\n",
		"negative rows":        "MOSEY-CLIENT 2 new no 80 -24 - - - " + pub + "\n",
		"unknown env name":     head + "HOME=x - - " + pub + "\n",
		"unsorted env":         head + "TERM=x,LANG=y - - " + pub + "\n",
		"repeated env":         head + "LANG=x,LANG=y - - " + pub + "\n",
		"empty env value":      head + "LANG= - - " + pub + "\n",
		"env value with ;":     head + "LANG=a;b - - " + pub + "\n",
		"env with no =":        head + "LANG - - " + pub + "\n",
		"long env value":       head + "LANG=" + strings.Repeat("x", 65) + " - - " + pub + "\n",
		"attach other":         "MOSEY-CLIENT 2 old no 80 24 - - - " + pub + "\n",
		"short session id":     "MOSEY-CLIENT 2 resume:AAAA no 80 24 - - - " + pub + "\n",
		"agent maybe":          "MOSEY-CLIENT 2 new maybe 80 24 - - - " + pub + "\n",
		"a swver as well":      "MOSEY-CLIENT 2 dev new no 80 24 - - - " + pub + "\n",
		"missing field":        "MOSEY-CLIENT 2 new no 80 24 - - " + pub + "\n",
		"extra field":          head + "- - - " + pub + " x\n",
		"wrong magic":          strings.Replace(good, "MOSEY-CLIENT", "MOSEY-CLIENTS", 1),
		"version zero-led":     strings.Replace(good, "CLIENT 2", "CLIENT 02", 1),
		"non-ASCII":            strings.Replace(good, "new", "néw", 1),
		"over MaxClientLine":   head + "- - - " + pub + strings.Repeat("A", MaxClientLine) + "\n",
		"empty":                "",
		"just LF":              "\n",
		"credential, not ours": string(MarshalCredentialLine(sampleCredentialLine())),
	} {
		if _, err := ParseClientLine([]byte(line)); !errors.Is(err, ErrBadLine) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ParseClientLine([]byte(head + "- - - " + pub + "\n")); err != nil {
		t.Errorf("the good base line was refused: %v", err)
	}
}

func TestALineOfAnotherVersionSaysWhichVersion(t *testing.T) {
	for _, line := range []string{
		strings.Replace(string(MarshalClientLine(sampleClientLine())), "CLIENT 2", "CLIENT 3", 1),
		"MOSEY-CLIENT 7 whatever the rest may be\n",
		"MOSEY-CLIENT 7\n",
	} {
		_, err := ParseClientLine([]byte(line))
		var v *VersionError
		if !errors.As(err, &v) || v.Got != 3 && v.Got != 7 || !errors.Is(err, ErrBadLine) {
			t.Errorf("%.30q: %v", line, err)
		}
	}
	_, err := ParseCredentialLine([]byte("MOSEY-CONNECT 3 x\n"))
	var v *VersionError
	if !errors.As(err, &v) || v.Got != 3 {
		t.Errorf("credential line of version 3: %v", err)
	}
}

func TestACredentialLineRefusesAddressesNoServerHas(t *testing.T) {
	for _, addr := range []string{
		"0.0.0.0", "::", "224.0.0.1", "239.255.255.250", "ff02::1", "255.255.255.255",
		"::ffff:192.0.2.1", "fe80::1%eth0", "0192.0.2.1", "192.0.2.01", "2001:DB8::1",
		"2001:db8:0:0:0:0:0:1", "localhost", "[::1]",
	} {
		line := strings.Replace(string(MarshalCredentialLine(sampleCredentialLine())), " 192.0.2.7 ", " "+addr+" ", 1)
		if _, err := ParseCredentialLine([]byte(line)); !errors.Is(err, ErrBadLine) {
			t.Errorf("addr %s: %v", addr, err)
		}
	}
	// Addresses §7.2 refuses later, not the grammar: they need the client's
	// own state to judge.
	for _, addr := range []string{"127.0.0.1", "::1", "fe80::1", "10.0.0.255", "2001:db8::1"} {
		line := strings.Replace(string(MarshalCredentialLine(sampleCredentialLine())), " 192.0.2.7 ", " "+addr+" ", 1)
		if _, err := ParseCredentialLine([]byte(line)); err != nil {
			t.Errorf("addr %s: %v", addr, err)
		}
	}
}

func TestEveryRuleOfACredentialLineIsEnforced(t *testing.T) {
	s := sampleCredentialLine()
	good := string(MarshalCredentialLine(s))
	for name, line := range map[string]string{
		"port 0":          strings.Replace(good, " 60001 ", " 0 ", 1),
		"port 65536":      strings.Replace(good, " 60001 ", " 65536 ", 1),
		"port zero-led":   strings.Replace(good, " 60001 ", " 060001 ", 1),
		"short psk":       strings.Replace(good, " "+b64.EncodeToString(s.PSK[:])+" ", " AAAA ", 1),
		"long cred id":    strings.Replace(good, " "+b64.EncodeToString(s.CredentialID[:])+" ", " AAAAAAAAAAAAAAAA ", 1),
		"CRLF":            strings.TrimSuffix(good, "\n") + "\r\n",
		"no LF":           strings.TrimSuffix(good, "\n"),
		"one field short": strings.Replace(good, " 60001 ", " ", 1),
	} {
		if _, err := ParseCredentialLine([]byte(line)); !errors.Is(err, ErrBadLine) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestAnErrorLineOfAnyCodeAndVersionParses(t *testing.T) {
	for _, e := range []ErrorLine{
		{Proto: 1, Code: CodeLine},
		{Proto: 2, Code: CodeVersion},
		{Proto: 1, Code: CodeAttach, Detail: "2"},
		{Proto: 1, Code: CodeUnsupported, Detail: "attach"},
		{Proto: 1, Code: CodeSession},
		{Proto: 1, Code: CodeInternal},
		{Proto: 0, Code: "abcdefghijklmnop"},
		{Proto: 99999, Code: "later", Detail: strings.Repeat("v", 64)},
	} {
		line := MarshalErrorLine(e)
		got, err := ParseErrorLine(line)
		if err != nil || got != e {
			t.Errorf("%q: %+v %v", line, got, err)
		}
		if len(line) > 100 {
			t.Errorf("%q is over the 100 bytes §6.4 derives", line)
		}
	}
}

func TestAnErrorLineOutsideTheFrozenGrammarIsRefused(t *testing.T) {
	for _, line := range []string{
		"MOSEY-ERROR 1 abcdefghijklmnopq -\n",
		"MOSEY-ERROR 1 Version -\n",
		"MOSEY-ERROR 1 ver1 -\n",
		"MOSEY-ERROR 123456 line -\n",
		"MOSEY-ERROR 01 line -\n",
		"MOSEY-ERROR 1 line\n",
		"MOSEY-ERROR 1 line - x\n",
		"MOSEY-ERROR 1 line a/b\n",
		"MOSEY-ERROR 1 version " + strings.Repeat("v", 65) + "\n",
		"MOSEY-ERROR 1 line -",
		"MOSEY-ERROR 1 line " + strings.Repeat("v", 120) + "\n",
	} {
		if _, err := ParseErrorLine([]byte(line)); !errors.Is(err, ErrBadLine) {
			t.Errorf("%.40q: %v", line, err)
		}
	}
}

func TestClientEnvKeepsOnlyWhatTheLineCanCarry(t *testing.T) {
	vars := map[string]string{
		"TERM":     "xterm-256color",
		"LANG":     "en_GB.UTF-8",
		"LC_ALL":   "",
		"LC_CTYPE": "a b",
		"LC_TIME":  strings.Repeat("x", 65),
		"HOME":     "/home/me",
	}
	env, dropped := ClientEnv(func(n string) string { return vars[n] })
	if len(env) != 2 || env["TERM"] != "xterm-256color" || env["LANG"] != "en_GB.UTF-8" {
		t.Errorf("env %v", env)
	}
	if strings.Join(dropped, ",") != "LC_CTYPE,LC_TIME" {
		t.Errorf("dropped %v", dropped)
	}
	c := sampleClientLine()
	c.Env = env
	if _, err := ParseClientLine(MarshalClientLine(c)); err != nil {
		t.Errorf("a line with ClientEnv's env: %v", err)
	}
}

// The session's name comes from the server, which may be hostile, and the
// client prints it: anything but an sname is refused (§6.3).
func TestACredentialLineWithABadNameIsRefused(t *testing.T) {
	good := string(MarshalCredentialLine(sampleCredentialLine()))
	for _, name := range []string{"quiet\x1bheron", "-heron", strings.Repeat("n", 33), "a/b"} {
		line := strings.Replace(good, " quiet-heron ", " "+name+" ", 1)
		if _, err := ParseCredentialLine([]byte(line)); !errors.Is(err, ErrBadLine) {
			t.Errorf("%q gave %v", name, err)
		}
	}
}

// -dir and -type travel base64url, so spaces and any letter survive, and
// the text inside is still held to §6.2: one line of ordinary text, tab
// allowed in -type only, at most 1024 bytes (§9.2.3).
func TestDirAndTypeCarryOneLineOfTextAndNothingElse(t *testing.T) {
	for _, c := range []struct{ dir, typ string }{
		{"src/my project", "claude -w feature x"},
		{"/srv/données", "echo 'hi there'\tand a tab"},
		{strings.Repeat("d", MaxStartText), strings.Repeat("t", MaxStartText)},
		{"", "vim"},
		{"work", ""},
	} {
		l := ClientLine{Attach: AttachName, Name: "work", Cols: 80, Rows: 24, Dir: c.dir, Type: c.typ, Public: key(1)}
		got, err := ParseClientLine(MarshalClientLine(l))
		if err != nil || got.Dir != c.dir || got.Type != c.typ {
			t.Errorf("%q, %q came back as %q, %q, %v", c.dir, c.typ, got.Dir, got.Type, err)
		}
	}
	for name, s := range map[string]string{
		"1025 bytes": strings.Repeat("x", MaxStartText+1),
		"NUL":        "a\x00b",
		"LF":         "echo a\necho b",
		"CR":         "echo a\r",
		"ESC":        "\x1b[A",
		"DEL":        "a\x7f",
		"Ctrl-C":     "\x03",
		"C1 NEL":     "a\u0085b",
		"bad UTF-8":  "a\xffb",
	} {
		if ValidDir(s) || ValidType(s) {
			t.Errorf("%s: accepted", name)
		}
		line := MarshalClientLine(ClientLine{Cols: 80, Rows: 24, Type: s, Public: key(1)})
		if _, err := ParseClientLine(line); !errors.Is(err, ErrBadLine) {
			t.Errorf("%s: a line carrying it gave %v", name, err)
		}
	}
	if !ValidType("a\tb") || ValidDir("a\tb") {
		t.Error("a tab is for -type only")
	}
	good := string(MarshalClientLine(ClientLine{Cols: 80, Rows: 24, Dir: "src", Public: key(1)}))
	for name, field := range map[string]string{
		"padding":       "c3Jj==",
		"trailing bits": "c3J", // "sr" is c3I: J leaves an unused bit set
		"not base64url": "c3J+",
		"empty text":    "",
	} {
		line := strings.Replace(good, " c3Jj ", " "+field+" ", 1)
		if _, err := ParseClientLine([]byte(line)); !errors.Is(err, ErrBadLine) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
