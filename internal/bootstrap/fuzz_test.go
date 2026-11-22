package bootstrap

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

// fuzzLine checks what every line's fuzz target owes beyond its own
// fields (versioning.md §7, bootstrap.md §12) for a line parse accepted:
// that marshalling the value gives the line less its unknown fields; that
// an unknown field added first, among, or last changes nothing; and that
// the same field marked critical is refused as a *CriticalError naming it.
func fuzzLine[T any](t *testing.T, line []byte, max int, tag string, anyNumber bool, spec lineSpec,
	parse func([]byte) (T, error), marshal func(T) []byte, v T) {
	t.Helper()
	p, err := parseLine(line, max, tag, anyNumber, spec)
	if err != nil {
		t.Fatalf("accepted %q, which the grammar refuses: %v", line, err)
	}
	if !bytes.Equal(marshal(v), p.stripped) {
		t.Fatalf("accepted %q, which re-marshals to %q", line, marshal(v))
	}
	for _, f := range []string{"a=1", "m-later=x", "zzzzzzzzzzzzzzzz=!="} {
		k := f[:strings.IndexByte(f, '=')]
		if _, known := spec[k]; known || strings.Contains(string(line), " "+k+"=") || strings.Contains(string(line), " !"+k+"=") {
			continue
		}
		with := addField(string(line), f)
		if len(with) > max || strings.Count(with, " ")-1 > MaxFields {
			continue
		}
		got, err := parse([]byte(with))
		if err != nil || !bytes.Equal(marshal(got), marshal(v)) {
			t.Fatalf("an unknown %s changed %q: %v", f, line, err)
		}
		_, err = parse([]byte(addField(string(line), "!"+f)))
		var ce *CriticalError
		if !errors.As(err, &ce) || ce.Key != k {
			t.Fatalf("an unknown !%s in %q was not refused: %v", f, line, err)
		}
	}
}

func FuzzParseClientLine(f *testing.F) {
	f.Add(MarshalClientLine(sampleClientLine()))
	r := sampleClientLine()
	r.Attach, r.SessionID, r.Agent, r.Env = AttachResume, [16]byte{1}, true, nil
	f.Add(MarshalClientLine(r))
	r.Holder, r.HasHolder = [8]byte{2}, true
	f.Add(MarshalClientLine(r))
	r.Attach, r.Name, r.HasHolder = AttachName, "quiet-heron", false
	f.Add(MarshalClientLine(r))
	r.Attach = AttachAuto
	f.Add(MarshalClientLine(r))
	r.Dir, r.Type = "src/my project", "claude -w x\tü"
	f.Add(MarshalClientLine(r))
	r.Attach, r.Dir, r.Type = AttachNew, "/tmp", ""
	f.Add(MarshalClientLine(r))
	r.Command = "sh -c 'echo ran-$((6*7)); exit 3'\tü"
	f.Add(MarshalClientLine(r))
	r.Attach, r.Name, r.Dir = AttachName, "work", ""
	f.Add(MarshalClientLine(r))
	f.Add([]byte(addField(string(MarshalClientLine(r)), "later=1")))
	f.Add([]byte(addField(string(MarshalClientLine(r)), "!later=1")))
	f.Add([]byte("MOSEY-CLIENT 1 !attach=new cols=80 rows=24 !public=AAAA\n"))
	f.Add([]byte("MOSEY-CLIENT 2\n"))
	f.Fuzz(func(t *testing.T, line []byte) {
		c, err := ParseClientLine(line)
		if err != nil {
			if !errors.Is(err, ErrBadLine) {
				t.Fatalf("an error that is not ErrBadLine: %v", err)
			}
			return
		}
		fuzzLine(t, line, MaxClientLine, clientMagic, false, clientSpec, ParseClientLine, MarshalClientLine, c)
		if c.Cols == 0 || c.Rows == 0 || len(c.Public) != PublicKeySize {
			t.Fatalf("accepted %+v", c)
		}
		if c.Name != "" && !ValidSessionName(c.Name) || c.Attach == AttachResume && c.SessionID == ([16]byte{}) {
			t.Fatalf("accepted attach %+v", c)
		}
		for n, v := range c.Env {
			if _, ok := slices.BinarySearch(EnvNames, n); !ok || !ValidEnvValue(v) {
				t.Fatalf("accepted env %s=%q", n, v)
			}
		}
		if c.Dir != "" && !referenceText(c.Dir, false) || c.Type != "" && !referenceText(c.Type, true) ||
			c.Command != "" && (!referenceText(c.Command, true) || c.Type != "") {
			t.Fatalf("accepted dir %q, type %q, command %q", c.Dir, c.Type, c.Command)
		}
	})
}

// referenceText is §6.2's dirtext and typetext written out by hand, rune
// by rune, as the fuzzer's reference for ValidDir and ValidType: 1 to
// 1024 bytes, valid UTF-8, and none of Unicode's Cc controls (U+0000 to
// U+001F and U+007F to U+009F), but a tab where tab is allowed.
func referenceText(s string, tab bool) bool {
	if len(s) < 1 || len(s) > 1024 {
		return false
	}
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && n <= 1 {
			return false
		}
		if (r < 0x20 || r >= 0x7f && r <= 0x9f) && !(tab && r == '\t') {
			return false
		}
		i += n
	}
	return true
}

// Agreement with the reference, on any text: what the line's grammar
// takes is exactly what §6.2 says.
func FuzzValidDirAndType(f *testing.F) {
	for _, s := range []string{"src", "a b", "\t", "x\ty", "\x00", "\xc2\x85", "\xff", "é", strings.Repeat("x", 1025)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if ValidDir(s) != referenceText(s, false) || ValidType(s) != referenceText(s, true) || ValidCommand(s) != referenceText(s, true) {
			t.Fatalf("%q: ValidDir %v, ValidType %v, ValidCommand %v", s, ValidDir(s), ValidType(s), ValidCommand(s))
		}
	})
}

func FuzzParseCredentialLine(f *testing.F) {
	f.Add(MarshalCredentialLine(sampleCredentialLine()))
	l := sampleCredentialLine()
	l.Addr = netip.MustParseAddr("2001:db8::1")
	f.Add(MarshalCredentialLine(l))
	l.Addr = netip.Addr{}
	f.Add(MarshalCredentialLine(l))
	l.Existing = true
	f.Add(MarshalCredentialLine(l))
	f.Add([]byte(addField(string(MarshalCredentialLine(l)), "later=1")))
	f.Add([]byte(addField(string(MarshalCredentialLine(l)), "!later=1")))
	f.Fuzz(func(t *testing.T, line []byte) {
		c, err := ParseCredentialLine(line)
		if err != nil {
			if !errors.Is(err, ErrBadLine) {
				t.Fatalf("an error that is not ErrBadLine: %v", err)
			}
			return
		}
		fuzzLine(t, line, MaxCredentialLine, credentialMagic, false, credentialSpec, ParseCredentialLine, MarshalCredentialLine, c)
		if a := c.Addr; a.IsValid() && (addressRule(a) != "" || a.Zone() != "" || a.Is4In6()) {
			t.Fatalf("accepted address %s", a)
		}
		if c.Port == 0 || len(c.Public) != PublicKeySize || !ValidSessionName(c.Name) {
			t.Fatalf("accepted %+v", c)
		}
	})
}

func FuzzParseErrorLine(f *testing.F) {
	f.Add([]byte("MOSEY-ERROR 1 !code=version detail=0.1.2\n"))
	f.Add([]byte("MOSEY-ERROR 0 !code=line\n"))
	f.Add([]byte("MOSEY-ERROR 99999 !code=abcdefghijklmnop\n"))
	f.Add([]byte("MOSEY-ERROR 2 !code=attach detail=2-1 later=x\n"))
	f.Add([]byte("MOSEY-ERROR 2 !code=attach !later=x\n"))
	f.Fuzz(func(t *testing.T, line []byte) {
		e, err := ParseErrorLine(line)
		if err != nil {
			if !errors.Is(err, ErrBadLine) {
				t.Fatalf("an error that is not ErrBadLine: %v", err)
			}
			return
		}
		if len(line) > MaxErrorLine || len(e.Code) < 1 || len(e.Code) > 16 {
			t.Fatalf("accepted %q", line)
		}
		fuzzLine(t, line, MaxErrorLine, errorMagic, true, errorSpec, ParseErrorLine, MarshalErrorLine, e)
	})
}

// countingReader counts what ReadCredential takes from it.
type countingReader struct {
	r *bytes.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func FuzzReadCredential(f *testing.F) {
	line := MarshalCredentialLine(sampleCredentialLine())
	f.Add(line)
	f.Add(append([]byte("motd\r\nMOSE\nMOSEY\n"), line...))
	f.Add([]byte("MOSEY-ERROR 2 !code=version\n"))
	f.Add(append(bytes.Repeat([]byte("x"), 70000), line...))
	f.Add([]byte("rc noise\nMOSEY-PROBE 1 machine=x86_64 system=Linux\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		r := &countingReader{r: bytes.NewReader(data)}
		c, err := ReadCredential(r)
		if r.n > MaxPreamble+MaxCredentialLine {
			t.Fatalf("read %d bytes", r.n)
		}
		// Whatever line was returned is in what was read, at a line start,
		// and it is the end of what was read.
		read := data[:r.n]
		lastLine := func(got []byte) {
			if !bytes.HasSuffix(read, got) || len(read) > len(got) && read[len(read)-len(got)-1] != '\n' {
				t.Fatalf("returned a line that is not the last line read")
			}
		}
		if err != nil {
			var re *RemoteError
			var nl *NoLineError
			var ns *NoServerError
			switch {
			case errors.As(err, &ns):
				lastLine(MarshalProbeLine(ns.Probe))
			case errors.As(err, &re):
				lastLine(MarshalErrorLine(re.ErrorLine))
			case errors.Is(err, ErrBadLine), errors.As(err, &nl):
			default:
				t.Fatalf("unexpected error %v", err)
			}
			return
		}
		lastLine(MarshalCredentialLine(c))
	})
}

func FuzzParseProbeLine(f *testing.F) {
	f.Add([]byte("MOSEY-PROBE 1 machine=x86_64 system=Linux\n"))
	f.Add([]byte("MOSEY-PROBE 1 machine=unknown system=unknown\n"))
	f.Add([]byte("MOSEY-PROBE 2 machine=aarch64 system=Linux\n"))
	f.Add([]byte("MOSEY-PROBE 1 machine=aarch64 os=none system=Linux\n"))
	f.Add([]byte("MOSEY-PROBE 1 machine=aarch64 !os=none system=Linux\n"))
	f.Fuzz(func(t *testing.T, line []byte) {
		p, err := ParseProbeLine(line)
		if err != nil {
			if !errors.Is(err, ErrBadLine) {
				t.Fatalf("an error that is not ErrBadLine: %v", err)
			}
			return
		}
		if len(line) > MaxProbeLine {
			t.Fatalf("accepted %q", line)
		}
		fuzzLine(t, line, MaxProbeLine, probeMagic, false, probeSpec, ParseProbeLine, MarshalProbeLine, p)
		if len(p.System) < 1 || len(p.System) > 64 || len(p.Machine) < 1 || len(p.Machine) > 64 {
			t.Fatalf("accepted fields %q %q", p.System, p.Machine)
		}
	})
}

// ParseSums is fed a release's SHA256SUMS from the network (§4.7.4): it
// never panics, and a hash it returns is that of a line of the input that
// names exactly name, in a file every line of which is in the grammar.
func FuzzParseSums(f *testing.F) {
	sums := []byte(strings.Repeat("0", 64) + "  mosey-0.1.2-darwin-arm64\n" + strings.Repeat("a", 64) + "  mosey-0.1.2-linux-amd64\n")
	f.Add(sums, "mosey-0.1.2-linux-amd64")
	f.Add(sums, "SHA256SUMS")
	f.Add([]byte(strings.Repeat("A", 64)+"  x\n"), "x")
	f.Fuzz(func(t *testing.T, sums []byte, name string) {
		h, err := ParseSums(sums, name)
		if err != nil {
			return
		}
		want := []byte(hex.EncodeToString(h[:]) + "  " + name + "\n")
		if !bytes.HasPrefix(sums, want) && !bytes.Contains(sums, append([]byte("\n"), want...)) {
			t.Fatalf("returned %x for %q, which no line says", h, name)
		}
		for _, line := range bytes.SplitAfter(sums, []byte("\n")) {
			if len(line) == 0 {
				continue
			}
			if len(line) < 68 || line[64] != ' ' || line[65] != ' ' || line[len(line)-1] != '\n' || !lowerHex(line[:64]) || !validAsset(line[66:len(line)-1]) {
				t.Fatalf("accepted a file with the line %q", line)
			}
		}
	})
}

func FuzzSanitize(f *testing.F) {
	f.Add([]byte("\x1b[31mred\x1b[0m\r\n"), 3)
	f.Add([]byte("caf\xc3\xa9 \u202e \xc2\x9b"), 4)
	f.Add(bytes.Repeat([]byte("ab\x01"), 600), 7)
	f.Fuzz(func(t *testing.T, data []byte, split int) {
		var b bytes.Buffer
		w := Sanitize(&b)
		if split <= 0 || split > len(data) {
			split = len(data)
		}
		for len(data) > 0 {
			n := min(split, len(data))
			w.Write(data[:n])
			data = data[n:]
		}
		w.Close()
		checkSanitized(t, b.String())
	})
}

func FuzzSSHOptions(f *testing.F) {
	f.Add("-4vC\x00-p2222\x00-o\x00User=x\x00-A")
	f.Add("-L\x008080:x:80")
	f.Add("-o\x00-X\x00-a")
	f.Fuzz(func(t *testing.T, joined string) {
		args := strings.Split(joined, "\x00")
		// The split loses nothing, and what it leaves starts at a word
		// that is not an option.
		opts, rest := SplitSSHOptions(args)
		if !slices.Equal(append(slices.Clone(opts), rest...), args) || len(rest) > 0 && len(rest[0]) > 1 && rest[0][0] == '-' {
			t.Fatalf("%q split into %q and %q", args, opts, rest)
		}
		o, err := ParseSSHOptions(args)
		if err != nil {
			return
		}
		again, err := ParseSSHOptions(o.Args)
		if err != nil || !slices.Equal(again.Args, o.Args) || again.Agent != 0 {
			t.Fatalf("%q normalised to %q, which re-parses to %q, %v", args, o.Args, again.Args, err)
		}
		// Walk the normalised options: every one is a letter we pass, and
		// each that takes a value has one.
		for i := 0; i < len(o.Args); i++ {
			a := o.Args[i]
			if len(a) != 2 || a[0] != '-' {
				t.Fatalf("%q in %q", a, o.Args)
			}
			switch {
			case strings.IndexByte(passFlags, a[1]) >= 0:
			case strings.IndexByte(passValues, a[1]) >= 0:
				i++
			default:
				t.Fatalf("refused letter %q passed in %q", a, o.Args)
			}
		}
	})
}

func FuzzChooseAddr(f *testing.F) {
	f.Add([]byte{127, 0, 0, 1}, "far", []byte{198, 51, 100, 9})
	f.Add([]byte{}, "fe80::1%eth0", []byte{})
	f.Add(netip.MustParseAddr("fe80::1").AsSlice(), "x", netip.MustParseAddr("::1").AsSlice())
	f.Fuzz(func(t *testing.T, addr []byte, hostname string, resolved []byte) {
		line := sampleCredentialLine()
		line.Addr, _ = netip.AddrFromSlice(addr)
		if line.Addr.IsValid() && addressRule(line.Addr) != "" {
			return // the grammar refuses these before ChooseAddr runs
		}
		var res []netip.Addr
		for len(resolved) >= 4 {
			n := 4
			if resolved[0]&1 == 1 && len(resolved) >= 16 {
				n = 16
			}
			a, _ := netip.AddrFromSlice(resolved[:n])
			res = append(res, a)
			resolved = resolved[n:]
		}
		lookup := func(context.Context, string) ([]netip.Addr, error) { return res, nil }
		c := Config{"hostname": {hostname}}
		a, err := ChooseAddr(context.Background(), line, c, lookup)
		if err != nil {
			if !errors.Is(err, ErrBadAddr) {
				t.Fatalf("%v", err)
			}
			return
		}
		if why := addressRule(a); why != "" {
			t.Fatalf("chose %s, which is %s", a, why)
		}
		if a.Is6() && a.IsLinkLocalUnicast() && a.Zone() == "" {
			t.Fatalf("chose link-local %s with no zone", a)
		}
		if a.IsLoopback() {
			all := res
			if h, err := netip.ParseAddr(hostname); err == nil {
				all = []netip.Addr{h}
			}
			if len(all) == 0 {
				t.Fatalf("chose loopback %s with no destination", a)
			}
			for _, d := range all {
				if !d.Unmap().IsLoopback() {
					t.Fatalf("chose loopback %s for a destination with %s", a, d)
				}
			}
		}
	})
}
