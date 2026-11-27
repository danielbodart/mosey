package pty

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// procArgs builds a kern.procargs2 buffer as macOS lays it out.
func procArgs(argc int32, exec string, pad int, rest ...string) []byte {
	b := binary.LittleEndian.AppendUint32(nil, uint32(argc))
	b = append(b, exec...)
	b = append(b, 0)
	b = append(b, make([]byte, pad)...)
	for _, s := range rest {
		b = append(b, s...)
		b = append(b, 0)
	}
	return b
}

// Buffers measured on dan-mac (macOS 15.7.4, 2026-11-27), with the
// environment cut: a plain run, sshd-session's rewritten title, and a
// login-shell argv[0] given with exec -a.
var measuredProcArgs = map[string]string{
	"\x01\x00\x00\x00./probe\x00./probe\x00USER=dan\x00HOME=/Users/dan\x00":                                    "./probe",
	"\x03\x00\x00\x00/usr/libexec/sshd-session\x00\x00\x00\x00\x00\x00\x00sshd-session: dan@notty\x00\x00\x00": "sshd-session: dan@notty",
	"\x02\x00\x00\x00/bin/sleep\x00\x00\x00\x00\x00\x00-zsh\x005\x00":                                          "-zsh",
}

func TestArgv0IsReadFromMeasuredProcArgs(t *testing.T) {
	for in, want := range measuredProcArgs {
		if got, ok := procArgsArgv0([]byte(in)); !ok || got != want {
			t.Errorf("%q: %q, %v; want %q", in, got, ok, want)
		}
	}
}

func TestAProcArgsBufferThatDoesNotParseGivesNoName(t *testing.T) {
	for name, b := range map[string][]byte{
		"empty":                   nil,
		"short argc":              {1, 0, 0},
		"argc 0":                  procArgs(0, "/bin/sh", 2, "sh"),
		"argc negative":           procArgs(-1, "/bin/sh", 2, "sh"),
		"exec path with no NUL":   []byte("\x01\x00\x00\x00/bin/sh"),
		"no argv after padding":   procArgs(1, "/bin/sh", 5),
		"argv[0] with no NUL":     append(procArgs(1, "/bin/sh", 1), "sh"...),
		"only padding after argc": {1, 0, 0, 0, 0, 0, 0},
	} {
		if got, ok := procArgsArgv0(b); ok || got != "" {
			t.Errorf("%s: %q, %v", name, got, ok)
		}
	}
}

func TestTheCwdIsReadFromAFullProcVnodePathInfo(t *testing.T) {
	b := make([]byte, vnodePathInfoSize)
	copy(b[vnodeInfoSize:], "/Users/u/src\x00junk")
	copy(b[2*vnodeInfoSize+maxPathLen:], "/\x00")
	if got := vnodePathCwd(b, len(b)); got != "/Users/u/src" {
		t.Errorf("%q", got)
	}
	if got := vnodePathCwd(b, 0); got != "" {
		t.Errorf("a failed call: %q", got)
	}
	if got := vnodePathCwd(b[:100], 100); got != "" {
		t.Errorf("a short buffer: %q", got)
	}
	full := bytes.Repeat([]byte{'a'}, vnodePathInfoSize)
	if got := vnodePathCwd(full, len(full)); got != "" {
		t.Errorf("a path with no NUL: %q", got)
	}
}

// referenceArgv0 is procArgsArgv0 written another way: split at every
// NUL; the first part is the exec path, and argv[0] is the first non-empty
// part after it that a NUL ends.
func referenceArgv0(b []byte) (string, bool) {
	if len(b) < 4 || int32(binary.LittleEndian.Uint32(b)) < 1 {
		return "", false
	}
	parts := strings.Split(string(b[4:]), "\x00")
	// The last part has no NUL after it, so argv[0] needs three parts.
	if len(parts) < 3 {
		return "", false
	}
	for _, p := range parts[1 : len(parts)-1] {
		if p != "" {
			return p, true
		}
	}
	return "", false
}

// The parser agrees with the reference on any buffer, and a buffer built
// from an exec path, padding and a non-empty argv[0] gives that argv[0].
func FuzzProcArgs(f *testing.F) {
	for in := range measuredProcArgs {
		f.Add([]byte(in), "", 0, "")
	}
	f.Add([]byte{}, "/bin/zsh", 3, "-zsh")
	f.Add([]byte{0xff, 0xff, 0xff, 0x7f, 'a', 0}, "/a", 0, "b")
	f.Fuzz(func(t *testing.T, b []byte, exec string, pad int, argv0 string) {
		got, ok := procArgsArgv0(b)
		want, wantOK := referenceArgv0(b)
		if got != want || ok != wantOK {
			t.Fatalf("%q: %q, %v; the reference gives %q, %v", b, got, ok, want, wantOK)
		}
		if strings.IndexByte(got, 0) >= 0 {
			t.Fatalf("%q: argv[0] %q holds a NUL", b, got)
		}
		if strings.IndexByte(exec, 0) >= 0 || strings.IndexByte(argv0, 0) >= 0 || argv0 == "" {
			return
		}
		pad = pad & 15
		built := procArgs(2, exec, pad, argv0, "x=y")
		if got, ok := procArgsArgv0(built); !ok || got != argv0 {
			t.Fatalf("%q: %q, %v; want %q", built, got, ok, argv0)
		}
	})
}

// Any buffer and fill count gives a directory with no NUL in it, and
// only a full fill gives one at all: then it is the bytes at the
// directory's offset, up to their first NUL. A buffer built around a
// path gives that path.
func FuzzVnodePathCwd(f *testing.F) {
	full := make([]byte, vnodePathInfoSize)
	copy(full[vnodePathInfoCwdOff:], "/Users/u/src\x00junk")
	f.Add(full, vnodePathInfoSize, "/Users/u/src")
	f.Add(full, 0, "/")
	f.Add(bytes.Repeat([]byte{'a'}, vnodePathInfoSize), vnodePathInfoSize, "")
	f.Add([]byte{}, vnodePathInfoSize, "/private/tmp/x")
	f.Fuzz(func(t *testing.T, b []byte, n int, path string) {
		got := vnodePathCwd(b, n)
		if strings.IndexByte(got, 0) >= 0 {
			t.Fatalf("n=%d: %q holds a NUL", n, got)
		}
		if got != "" {
			if n != vnodePathInfoSize || len(b) < vnodePathInfoSize {
				t.Fatalf("n=%d, len %d: %q from a short fill", n, len(b), got)
			}
			p := b[vnodePathInfoCwdOff : vnodePathInfoCwdOff+maxPathLen]
			if want, _, _ := bytes.Cut(p, []byte{0}); got != string(want) {
				t.Fatalf("%q; the record holds %q", got, want)
			}
		}
		if strings.IndexByte(path, 0) >= 0 || len(path) >= maxPathLen {
			return
		}
		built := bytes.Repeat([]byte{0xff}, vnodePathInfoSize)
		copy(built[vnodePathInfoCwdOff:], path+"\x00")
		if got := vnodePathCwd(built, len(built)); got != path {
			t.Fatalf("%q from a record of %q", got, path)
		}
	})
}
