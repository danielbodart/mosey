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
)

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
	f.Add([]byte("MOSEY-CLIENT 1 dev new no 80 24 - AAAA\n"))
	f.Add([]byte("MOSEY-CLIENT 2\n"))
	f.Fuzz(func(t *testing.T, line []byte) {
		c, err := ParseClientLine(line)
		if err != nil {
			if !errors.Is(err, ErrBadLine) {
				t.Fatalf("an error that is not ErrBadLine: %v", err)
			}
			return
		}
		if !bytes.Equal(MarshalClientLine(c), line) {
			t.Fatalf("accepted %q, which re-marshals differently", line)
		}
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
	})
}

func FuzzParseCredentialLine(f *testing.F) {
	f.Add(MarshalCredentialLine(sampleCredentialLine()))
	l := sampleCredentialLine()
	l.Addr = netip.MustParseAddr("2001:db8::1")
	f.Add(MarshalCredentialLine(l))
	l.Addr = netip.Addr{}
	f.Add(MarshalCredentialLine(l))
	f.Fuzz(func(t *testing.T, line []byte) {
		c, err := ParseCredentialLine(line)
		if err != nil {
			if !errors.Is(err, ErrBadLine) {
				t.Fatalf("an error that is not ErrBadLine: %v", err)
			}
			return
		}
		if !bytes.Equal(MarshalCredentialLine(c), line) {
			t.Fatalf("accepted %q, which re-marshals differently", line)
		}
		if a := c.Addr; a.IsValid() && (addressRule(a) != "" || a.Zone() != "" || a.Is4In6()) {
			t.Fatalf("accepted address %s", a)
		}
		if c.Port == 0 || len(c.Public) != PublicKeySize || !ValidSessionName(c.Name) {
			t.Fatalf("accepted %+v", c)
		}
	})
}

func FuzzParseErrorLine(f *testing.F) {
	f.Add([]byte("MOSEY-ERROR 1 version 0.1.2\n"))
	f.Add([]byte("MOSEY-ERROR 0 line -\n"))
	f.Add([]byte("MOSEY-ERROR 99999 abcdefghijklmnop -\n"))
	f.Fuzz(func(t *testing.T, line []byte) {
		e, err := ParseErrorLine(line)
		if err != nil {
			if !errors.Is(err, ErrBadLine) {
				t.Fatalf("an error that is not ErrBadLine: %v", err)
			}
			return
		}
		if !bytes.Equal(MarshalErrorLine(e), line) || len(line) > MaxErrorLine {
			t.Fatalf("accepted %q", line)
		}
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
	f.Add([]byte("MOSEY-ERROR 2 version -\n"))
	f.Add(append(bytes.Repeat([]byte("x"), 70000), line...))
	f.Add([]byte("rc noise\nMOSEY-PROBE 1 Linux x86_64\n"))
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
	f.Add([]byte("MOSEY-PROBE 1 Linux x86_64\n"))
	f.Add([]byte("MOSEY-PROBE 1 unknown unknown\n"))
	f.Add([]byte("MOSEY-PROBE 2 Linux aarch64\n"))
	f.Add([]byte("MOSEY-PROBE 1 Linux aarch64 none\n"))
	f.Fuzz(func(t *testing.T, line []byte) {
		p, err := ParseProbeLine(line)
		if err != nil {
			if !errors.Is(err, ErrBadLine) {
				t.Fatalf("an error that is not ErrBadLine: %v", err)
			}
			return
		}
		if !bytes.Equal(MarshalProbeLine(p), line) || len(line) > MaxProbeLine {
			t.Fatalf("accepted %q", line)
		}
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
	f.Add([]byte{127, 0, 0, 1}, "far", []byte{198, 51, 100, 9}, []byte{10, 1, 2, 3, 24})
	f.Add([]byte{}, "fe80::1%eth0", []byte{}, []byte{})
	f.Add(netip.MustParseAddr("fe80::1").AsSlice(), "x", netip.MustParseAddr("::1").AsSlice(), []byte{})
	f.Fuzz(func(t *testing.T, addr []byte, hostname string, resolved []byte, local []byte) {
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
		var prefixes []netip.Prefix
		for len(local) >= 5 {
			a, _ := netip.AddrFromSlice(local[:4])
			if p, err := a.Prefix(int(local[4] % 33)); err == nil {
				prefixes = append(prefixes, p)
			}
			local = local[5:]
		}
		lookup := func(context.Context, string) ([]netip.Addr, error) { return res, nil }
		c := Config{"hostname": {hostname}}
		a, err := ChooseAddr(context.Background(), line, c, lookup, prefixes)
		if err != nil {
			if !errors.Is(err, ErrBadAddr) {
				t.Fatalf("%v", err)
			}
			return
		}
		if why := (addrRules{local: prefixes}).refuse(a); why != "" {
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
