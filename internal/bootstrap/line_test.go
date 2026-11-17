package bootstrap

import (
	"bytes"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
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

// setField returns line with the field of key (marked or not) replaced by
// word, or removed when word is "". It fails the test if there is no such
// field, so a test never passes by editing nothing.
func setField(t *testing.T, line, key, word string) string {
	t.Helper()
	words := strings.Split(strings.TrimSuffix(line, "\n"), " ")
	for i, w := range words[2:] {
		if strings.HasPrefix(strings.TrimPrefix(w, "!"), key+"=") {
			if word == "" {
				words = slices.Delete(words, i+2, i+3)
			} else {
				words[i+2] = word
			}
			return strings.Join(words, " ") + "\n"
		}
	}
	t.Fatalf("no field %s in %.60q", key, line)
	return ""
}

// addField returns line with word added among its fields in key order
// (versioning.md §6), as a later release would write it.
func addField(line, word string) string {
	words := strings.Split(strings.TrimSuffix(line, "\n"), " ")
	// Keys, not whole words: "a0=0" sorts before "a=1" as words but after it as keys.
	k := func(w string) string { w, _, _ = strings.Cut(strings.TrimPrefix(w, "!"), "="); return w }
	i := 2
	for i < len(words) && k(words[i]) < k(word) {
		i++
	}
	words = slices.Insert(words, i, word)
	return strings.Join(words, " ") + "\n"
}

// unknownFields are fields no build defines, which sort first, between
// and last among the known ones of every line.
var unknownFields = []string{"aaa=1", "later-thing=x=y!", "zz9=" + strings.Repeat("v", 40)}

// mustIgnore checks versioning.md §7 on one line: parse gives the same
// value with an unknown field added, and refuses it as a *CriticalError
// naming the key when the field is marked critical.
func mustIgnore[T any](t *testing.T, line string, parse func([]byte) (T, error), same func(a, b T) bool) {
	t.Helper()
	want, err := parse([]byte(line))
	if err != nil {
		t.Fatalf("the line itself: %v", err)
	}
	for _, f := range unknownFields {
		got, err := parse([]byte(addField(line, f)))
		if err != nil || !same(got, want) {
			t.Errorf("with %s: %+v, %v", f, got, err)
		}
		_, err = parse([]byte(addField(line, "!"+f)))
		var ce *CriticalError
		if !errors.As(err, &ce) || ce.Key != f[:strings.IndexByte(f, '=')] || !errors.Is(err, ErrBadLine) {
			t.Errorf("with !%s: %v", f, err)
		}
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
	// A command and a type exclude each other.
	maxCommand := max
	maxCommand.Type, maxCommand.Command = "", strings.Repeat("c", MaxStartText)
	for _, c := range []ClientLine{sampleClientLine(), max, maxCommand, {Cols: 1, Rows: 1, Public: key(0)}} {
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
	// The longest legal line is the size §6.2 derives: the type's key is
	// a byte longer than the command's.
	if n := len(MarshalClientLine(max)); n != 5756 {
		t.Errorf("longest client line is %d bytes, §6.2 says 5756", n)
	}
	if n := len(MarshalClientLine(maxCommand)); n != 5755 {
		t.Errorf("longest client line with a command is %d bytes, not 5755", n)
	}
}

// A command is an optional, critical field (§6.2): a line without one has
// no cmd field at all, and one with a command carries it in base64url,
// which survives the trip.
func TestACommandIsAnOptionalCriticalField(t *testing.T) {
	plain := sampleClientLine()
	without := string(MarshalClientLine(plain))
	c := plain
	c.Command = "claude --resume 'my work'\tü"
	with := string(MarshalClientLine(c))
	if strings.Contains(without, "cmd=") || with != addField(without, "!cmd="+b64.EncodeToString([]byte(c.Command))) {
		t.Errorf("a command is not one critical field:\n%q\n%q", without, with)
	}
	got, err := ParseClientLine([]byte(with))
	if err != nil || got.Command != c.Command {
		t.Errorf("%q, %v", got.Command, err)
	}
	if got, err := ParseClientLine([]byte(without)); err != nil || got.Command != "" {
		t.Errorf("no command: %q, %v", got.Command, err)
	}
	both := c
	both.Type = "vim"
	if _, err := ParseClientLine(MarshalClientLine(both)); !errors.Is(err, ErrBadLine) {
		t.Errorf("a command and a type: %v", err)
	}
	for name, value := range map[string]string{
		"a dash":          "-",
		"not base64url":   "a+b/",
		"padding":         "Y2xhdWRl=",
		"a newline":       b64.EncodeToString([]byte("ls\nrm -rf ~")),
		"an escape":       b64.EncodeToString([]byte("\x1b[A")),
		"a NUL":           b64.EncodeToString([]byte("ls\x00")),
		"not UTF-8":       b64.EncodeToString([]byte("\xff")),
		"over 1024 bytes": b64.EncodeToString([]byte(strings.Repeat("c", MaxStartText+1))),
	} {
		if _, err := ParseClientLine([]byte(setField(t, with, "cmd", "!cmd="+value))); !errors.Is(err, ErrBadLine) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Unmarked, a known critical field is a sender's bug, and refused.
	if _, err := ParseClientLine([]byte(setField(t, with, "cmd", "cmd="+b64.EncodeToString([]byte("ls"))))); !errors.Is(err, ErrBadLine) {
		t.Errorf("cmd without its mark: %v", err)
	}
}

// existing is an optional, not critical field of the CredentialLine (§6.3).
func TestExistingIsAnOptionalFieldOfTheCredentialLine(t *testing.T) {
	c := sampleCredentialLine()
	without := string(MarshalCredentialLine(c))
	c.Existing = true
	with := string(MarshalCredentialLine(c))
	if with != addField(without, "existing=yes") {
		t.Errorf("%q", with)
	}
	if got, err := ParseCredentialLine([]byte(with)); err != nil || !got.Existing {
		t.Errorf("%+v, %v", got.Existing, err)
	}
	if got, err := ParseCredentialLine([]byte(without)); err != nil || got.Existing {
		t.Errorf("%+v, %v", got.Existing, err)
	}
	for _, word := range []string{"existing=no", "existing=Yes", "existing=-", "!existing=yes"} {
		if _, err := ParseCredentialLine([]byte(setField(t, with, "existing", word))); !errors.Is(err, ErrBadLine) {
			t.Errorf("%q: %v", word, err)
		}
	}
}

// Every attach of §6.2 survives a round trip as the field the spec shows.
func TestEveryAttachIsWrittenAsTheSpecShows(t *testing.T) {
	sid := [16]byte{1}
	for want, c := range map[string]ClientLine{
		" !attach=auto ":                                      {Attach: AttachAuto},
		" !attach=new ":                                       {Attach: AttachNew},
		" !attach=new:work ":                                  {Attach: AttachNew, Name: "work"},
		" !attach=name:a.b_c ":                                {Attach: AttachName, Name: "a.b_c"},
		" !attach=resume:AQAAAAAAAAAAAAAAAAAAAA ":             {Attach: AttachResume, SessionID: sid},
		" !attach=resume:AQAAAAAAAAAAAAAAAAAAAA:CQAAAAAAAAA ": {Attach: AttachResume, SessionID: sid, Holder: [8]byte{9}, HasHolder: true},
	} {
		c.Cols, c.Rows, c.Public = 80, 24, key(1)
		line := MarshalClientLine(c)
		if !bytes.Contains(line, []byte(want)) {
			t.Errorf("%q has no %q", line[:60], want)
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
	c := sampleClientLine()
	c.Dir = "src"
	line := string(MarshalClientLine(c))
	want := "MOSEY-CLIENT 1 !attach=new cols=211 !dir=c3Jj env=COLORTERM=truecolor,LANG=en_GB.UTF-8,TERM=xterm-256color !public="
	if !strings.HasPrefix(line, want) || !strings.HasSuffix(line, " rows=58\n") {
		t.Errorf("got %q", line[:len(want)])
	}
	c.Agent, c.Dir = true, ""
	if line := string(MarshalClientLine(c)); !strings.HasPrefix(line, "MOSEY-CLIENT 1 !agent=yes !attach=new cols=211 env=") {
		t.Errorf("got %.60q", line)
	}
}

func TestACredentialLineSurvivesARoundTrip(t *testing.T) {
	longest := sampleCredentialLine()
	longest.Addr = netip.MustParseAddr("2001:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	longest.Port = 65535
	longest.Name = strings.Repeat("n", MaxSessionName)
	longest.Existing = true
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
			got.Name != c.Name || got.Existing != c.Existing {
			t.Errorf("round trip changed %+v", got)
		}
	}
	if n := len(MarshalCredentialLine(longest)); n != 1853 {
		t.Errorf("longest credential line is %d bytes, §6.3 says 1853", n)
	}
	if line := string(MarshalCredentialLine(noAddr)); strings.Contains(line, "addr=") {
		t.Errorf("no address is no field: %.60q", line)
	}
}

// Each rule of §6.1 broken once, on a line that is otherwise good.
func TestEveryRuleOfAClientLineIsEnforced(t *testing.T) {
	good := string(MarshalClientLine(sampleClientLine()))
	pub := b64.EncodeToString(sampleClientLine().Public)
	set := func(key, word string) string { return setField(t, good, key, word) }
	for name, line := range map[string]string{
		"CR before LF":          strings.TrimSuffix(good, "\n") + "\r\n",
		"no LF":                 strings.TrimSuffix(good, "\n"),
		"double space":          strings.Replace(good, " cols", "  cols", 1),
		"trailing space":        strings.TrimSuffix(good, "\n") + " \n",
		"leading space":         " " + good,
		"tab":                   strings.Replace(good, " cols", "\tcols", 1),
		"padding":               set("public", "!public="+pub+"=="),
		"short key":             set("public", "!public="+pub[1:]),
		"trailing bits":         set("public", "!public="+pub[:len(pub)-1]+"B"),
		"not base64url":         set("public", "!public=+"+pub[1:]),
		"public unmarked":       set("public", "public="+pub),
		"no public":             set("public", ""),
		"no attach":             set("attach", ""),
		"attach unmarked":       set("attach", "attach=new"),
		"no cols":               set("cols", ""),
		"no rows":               set("rows", ""),
		"cols marked":           set("cols", "!cols=211"),
		"leading zero cols":     set("cols", "cols=080"),
		"zero cols":             set("cols", "cols=0"),
		"cols 65536":            set("cols", "cols=65536"),
		"negative rows":         set("rows", "rows=-24"),
		"empty value":           set("rows", "rows="),
		"unknown env name":      set("env", "env=HOME=x"),
		"unsorted env":          set("env", "env=TERM=x,LANG=y"),
		"repeated env":          set("env", "env=LANG=x,LANG=y"),
		"empty env value":       set("env", "env=LANG="),
		"env value with ;":      set("env", "env=LANG=a;b"),
		"env with no =":         set("env", "env=LANG"),
		"env of a dash":         set("env", "env=-"),
		"long env value":        set("env", "env=LANG="+strings.Repeat("x", 65)),
		"attach other":          set("attach", "!attach=old"),
		"short session id":      set("attach", "!attach=resume:AAAA"),
		"agent no":              addField(good, "!agent=no"),
		"agent unmarked":        addField(good, "agent=yes"),
		"dir of a dash":         addField(good, "!dir=-"),
		"fields out of order":   strings.Replace(good, "!attach=new cols=211", "cols=211 !attach=new", 1),
		"a field repeated":      addField(good, "cols=80"),
		"marked and unmarked":   addField(good, "!cols=80"),
		"upper-case key":        addField(good, "Later=1"),
		"key with a digit head": addField(good, "9later=1"),
		"key of 17 bytes":       addField(good, strings.Repeat("k", 17)+"=1"),
		"key with _":            addField(good, "la_ter=1"),
		"no =":                  addField(good, "later"),
		"bare !":                addField(good, "!"),
		"a positional word":     strings.Replace(good, "MOSEY-CLIENT 1 ", "MOSEY-CLIENT 1 new ", 1),
		"wrong magic":           strings.Replace(good, "MOSEY-CLIENT", "MOSEY-CLIENTS", 1),
		"number zero-led":       strings.Replace(good, "CLIENT 1", "CLIENT 01", 1),
		"non-ASCII":             strings.Replace(good, "new", "néw", 1),
		"over MaxClientLine":    addField(good, "zz="+strings.Repeat("A", MaxClientLine)),
		"over MaxFields":        strings.TrimSuffix(good, "\n") + strings.Repeat(" zz=1", MaxFields) + "\n",
		"empty":                 "",
		"just LF":               "\n",
		"no fields":             "MOSEY-CLIENT 1\n",
		"credential, not ours":  string(MarshalCredentialLine(sampleCredentialLine())),
	} {
		if _, err := ParseClientLine([]byte(line)); !errors.Is(err, ErrBadLine) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ParseClientLine([]byte(good)); err != nil {
		t.Errorf("the good base line was refused: %v", err)
	}
}

// Must-ignore (versioning.md §7) on every line of §6, and on the probe's
// and -list's.
func TestAnUnknownFieldIsIgnoredUnlessItIsCritical(t *testing.T) {
	c := sampleClientLine()
	c.Agent, c.Dir, c.Command = true, "src", "ls"
	mustIgnore(t, string(MarshalClientLine(c)), ParseClientLine, func(a, b ClientLine) bool {
		return bytes.Equal(MarshalClientLine(a), MarshalClientLine(b))
	})
	cl := sampleCredentialLine()
	cl.Existing = true
	mustIgnore(t, string(MarshalCredentialLine(cl)), ParseCredentialLine, func(a, b CredentialLine) bool {
		return bytes.Equal(MarshalCredentialLine(a), MarshalCredentialLine(b))
	})
	mustIgnore(t, string(MarshalErrorLine(ErrorLine{Proto: 3, Code: CodeAttach, Detail: "2-1"})), ParseErrorLine,
		func(a, b ErrorLine) bool { return a == b })
	mustIgnore(t, string(MarshalProbeLine(ProbeLine{System: "Linux", Machine: "x86_64"})), ParseProbeLine,
		func(a, b ProbeLine) bool { return a == b })
	mustIgnore(t, string(MarshalListLine(ListLine{Name: "quiet-heron", State: SessionDetached, Since: time.Unix(1, 0), Command: "ls"})), ParseListLine,
		func(a, b ListLine) bool { return a == b })
}

func TestALineOfAnotherVersionSaysWhichVersion(t *testing.T) {
	for _, line := range []string{
		strings.Replace(string(MarshalClientLine(sampleClientLine())), "CLIENT 1", "CLIENT 3", 1),
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
	good := string(MarshalCredentialLine(sampleCredentialLine()))
	for _, addr := range []string{
		"0.0.0.0", "::", "224.0.0.1", "239.255.255.250", "ff02::1", "255.255.255.255",
		"::ffff:192.0.2.1", "fe80::1%eth0", "0192.0.2.1", "192.0.2.01", "2001:DB8::1",
		"2001:db8:0:0:0:0:0:1", "localhost", "[::1]", "-",
	} {
		if _, err := ParseCredentialLine([]byte(setField(t, good, "addr", "!addr="+addr))); !errors.Is(err, ErrBadLine) {
			t.Errorf("addr %s: %v", addr, err)
		}
	}
	// Addresses §7.2 refuses later, not the grammar: they need the client's
	// own state to judge.
	for _, addr := range []string{"127.0.0.1", "::1", "fe80::1", "10.0.0.255", "2001:db8::1"} {
		if _, err := ParseCredentialLine([]byte(setField(t, good, "addr", "!addr="+addr))); err != nil {
			t.Errorf("addr %s: %v", addr, err)
		}
	}
}

func TestEveryRuleOfACredentialLineIsEnforced(t *testing.T) {
	good := string(MarshalCredentialLine(sampleCredentialLine()))
	set := func(key, word string) string { return setField(t, good, key, word) }
	for name, line := range map[string]string{
		"port 0":          set("port", "!port=0"),
		"port 65536":      set("port", "!port=65536"),
		"port zero-led":   set("port", "!port=060001"),
		"port unmarked":   set("port", "port=60001"),
		"no port":         set("port", ""),
		"short psk":       set("psk", "!psk=AAAA"),
		"no psk":          set("psk", ""),
		"long cred id":    set("credid", "!credid=AAAAAAAAAAAAAAAA"),
		"no cred id":      set("credid", ""),
		"no sid":          set("sid", ""),
		"no public":       set("public", ""),
		"no name":         set("name", ""),
		"name marked":     set("name", "!name=quiet-heron"),
		"addr unmarked":   set("addr", "addr=192.0.2.7"),
		"CRLF":            strings.TrimSuffix(good, "\n") + "\r\n",
		"no LF":           strings.TrimSuffix(good, "\n"),
		"a positional -":  strings.Replace(good, "CONNECT 1 ", "CONNECT 1 - ", 1),
		"over the bound":  addField(good, "zz="+strings.Repeat("v", MaxCredentialLine)),
		"repeated psk":    addField(good, "!psk=AAAA"),
		"psk not b64":     set("psk", "!psk="+strings.Repeat("+", 43)),
		"psk with spaces": set("psk", "!psk=AAAA AAAA"),
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
		{Proto: 1, Code: CodeAttach, Detail: "2-1"},
		{Proto: 1, Code: CodeUnsupported, Detail: "cmd"},
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
		if len(line) > 112 {
			t.Errorf("%q is over the 112 bytes §6.4 derives", line)
		}
	}
	if got := string(MarshalErrorLine(ErrorLine{Proto: 1, Code: CodeDir})); got != "MOSEY-ERROR 1 !code=dir\n" {
		t.Errorf("%q", got)
	}
}

func TestAnErrorLineOutsideTheFrozenGrammarIsRefused(t *testing.T) {
	for _, line := range []string{
		"MOSEY-ERROR 1 !code=abcdefghijklmnopq\n",
		"MOSEY-ERROR 1 !code=Version\n",
		"MOSEY-ERROR 1 !code=ver1\n",
		"MOSEY-ERROR 1 code=line\n",
		"MOSEY-ERROR 1 detail=x\n",
		"MOSEY-ERROR 123456 !code=line\n",
		"MOSEY-ERROR 01 !code=line\n",
		"MOSEY-ERROR 1 line -\n",
		"MOSEY-ERROR 1 !code=line detail=-\n" + "x",
		"MOSEY-ERROR 1 !code=line detail=a/b\n",
		"MOSEY-ERROR 1 !code=version detail=" + strings.Repeat("v", 65) + "\n",
		"MOSEY-ERROR 1 !code=line",
		"MOSEY-ERROR 1 !code=line zz=" + strings.Repeat("v", MaxErrorLine) + "\n",
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
	c.Env = nil
	if line := string(MarshalClientLine(c)); strings.Contains(line, "env=") {
		t.Errorf("no env is no field: %.60q", line)
	}
}

// The session's name comes from the server, which may be hostile, and the
// client prints it: anything but an sname is refused (§6.3).
func TestACredentialLineWithABadNameIsRefused(t *testing.T) {
	good := string(MarshalCredentialLine(sampleCredentialLine()))
	for _, name := range []string{"quiet\x1bheron", "-heron", strings.Repeat("n", 33), "a/b"} {
		if _, err := ParseCredentialLine([]byte(setField(t, good, "name", "name="+name))); !errors.Is(err, ErrBadLine) {
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
		if _, err := ParseClientLine([]byte(setField(t, good, "dir", "!dir="+field))); !errors.Is(err, ErrBadLine) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
