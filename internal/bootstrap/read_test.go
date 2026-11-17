package bootstrap

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

// strictReader fails the test if anything reads past its first limit
// bytes, which is how ReadCredential is shown never to consume what
// follows the line.
type strictReader struct {
	t     *testing.T
	data  []byte
	limit int
	read  int
}

func (r *strictReader) Read(p []byte) (int, error) {
	if r.read >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.read:])
	if r.read+n > r.limit {
		r.t.Errorf("read past byte %d (to %d)", r.limit, r.read+n)
	}
	r.read += n
	return n, nil
}

func TestTheCredentialLineIsFoundAfterNoise(t *testing.T) {
	line := MarshalCredentialLine(sampleCredentialLine())
	for name, before := range map[string]string{
		"nothing":       "",
		"motd":          "Welcome to the far host\nLast login: yesterday\n",
		"lookalike":     "MOSEY CONNECT 1 nope\nMOSEY\n MOSEY-CONNECT 1\nMOS\n",
		"escape codes":  "\x1b]0;pwned\x07\x1b[2J\r\n",
		"almost prefix": "MOSEY_CONNECT\nMOSEYS-\n",
	} {
		data := append([]byte(before), line...)
		data = append(data, "and after\n"...)
		r := &strictReader{t: t, data: data, limit: len(before) + len(line)}
		got, err := ReadCredential(r)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !bytes.Equal(MarshalCredentialLine(got), line) {
			t.Errorf("%s: got another line", name)
		}
	}
}

func TestAByteAtATimeReaderGivesTheSameLine(t *testing.T) {
	line := MarshalCredentialLine(sampleCredentialLine())
	got, err := ReadCredential(iotest.OneByteReader(bytes.NewReader(append([]byte("hi\n"), line...))))
	if err != nil || !bytes.Equal(MarshalCredentialLine(got), line) {
		t.Errorf("%v", err)
	}
}

func TestALineOfOursThatDoesNotParseIsNeverSkipped(t *testing.T) {
	good := MarshalCredentialLine(sampleCredentialLine())
	for _, bad := range []string{
		"MOSEY-CONNECT 1 nope\n",
		"MOSEY-\n",
		"MOSEY-SOMETHING else\n",
		"MOSEY-ERROR 1 !code=Bad\n",
		"MOSEY-ERROR 1 !code=line !later=x\n",
		"MOSEY-CONNECT" + strings.Repeat(" x", 1100) + "\n",
		strings.TrimSuffix(string(good), "\n"), // EOF inside the line
	} {
		_, err := ReadCredential(strings.NewReader("noise\n" + bad + string(good)))
		if !errors.Is(err, ErrBadLine) {
			t.Errorf("%.30q: %v", bad, err)
		}
	}
}

func TestAnErrorLineIsReturnedAsTheServersRefusal(t *testing.T) {
	_, err := ReadCredential(strings.NewReader("rc noise\nMOSEY-ERROR 2 !code=version later=x\n"))
	var re *RemoteError
	if !errors.As(err, &re) || re.Code != CodeVersion || re.Proto != 2 || re.Detail != "" {
		t.Errorf("%v", err)
	}
}

func TestNoLineKeepsTheTailOfWhatWasSaid(t *testing.T) {
	out := strings.Repeat("x", 3000) + "\nbash: mosey: command not found\n"
	_, err := ReadCredential(strings.NewReader(out))
	var nl *NoLineError
	if !errors.As(err, &nl) || nl.Overflow || !errors.Is(err, ErrNoLine) {
		t.Fatalf("%v", err)
	}
	if len(nl.Tail) != TailSize || !bytes.HasSuffix(nl.Tail, []byte("command not found\n")) {
		t.Errorf("tail %d bytes: %q", len(nl.Tail), nl.Tail[len(nl.Tail)-40:])
	}
	_, err = ReadCredential(strings.NewReader("short"))
	if !errors.As(err, &nl) || string(nl.Tail) != "short" {
		t.Errorf("%v %q", err, nl.Tail)
	}
}

func TestNoiseOverThePreambleIsAnError(t *testing.T) {
	line := MarshalCredentialLine(sampleCredentialLine())
	for name, noise := range map[string]string{
		"many lines": strings.Repeat("0123456789abcde\n", MaxPreamble/16+1),
		"one line":   strings.Repeat("y", MaxPreamble+1) + "\n",
	} {
		data := append([]byte(noise), line...)
		r := &strictReader{t: t, data: data, limit: MaxPreamble + MaxCredentialLine}
		_, err := ReadCredential(r)
		var nl *NoLineError
		if !errors.As(err, &nl) || !nl.Overflow {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Right at the bound, the line is still read.
	noise := strings.Repeat("z", MaxPreamble-1) + "\n"
	if _, err := ReadCredential(strings.NewReader(noise + string(line))); err != nil {
		t.Errorf("a line right after %d bytes of noise: %v", MaxPreamble, err)
	}
}

func TestAReadErrorIsPassedOn(t *testing.T) {
	boom := errors.New("boom")
	_, err := ReadCredential(iotest.ErrReader(boom))
	if !errors.Is(err, boom) {
		t.Errorf("%v", err)
	}
}
