package client

import (
	"bytes"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/danielbodart/mosey/internal/bootstrap"
)

func env(vars map[string]string) func(string) string {
	return func(n string) string { return vars[n] }
}

func TestTheLogLivesInTheStateDirectory(t *testing.T) {
	for _, c := range []struct {
		vars map[string]string
		want string
	}{
		{map[string]string{"XDG_STATE_HOME": "/s", "HOME": "/h"}, "/s/mosey/client.log"},
		{map[string]string{"HOME": "/h"}, "/h/.local/state/mosey/client.log"},
		{map[string]string{"XDG_STATE_HOME": "relative", "HOME": "/h"}, "/h/.local/state/mosey/client.log"},
	} {
		got, err := LogPath(env(c.vars))
		if err != nil || got != c.want {
			t.Errorf("%v: %q %v", c.vars, got, err)
		}
	}
	if _, err := LogPath(env(nil)); err == nil {
		t.Error("a path with no HOME")
	}
}

func TestTheLogIsPrivateAndRotates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "mosey", "client.log")
	l, err := OpenLog(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	dir, _ := os.Stat(filepath.Dir(path))
	file, _ := os.Stat(path)
	if dir.Mode().Perm() != 0o700 || file.Mode().Perm() != 0o600 {
		t.Errorf("modes %v %v", dir.Mode(), file.Mode())
	}
	record := bytes.Repeat([]byte("x"), 1000)
	record[len(record)-1] = '\n'
	for range MaxLogFile/len(record) + 10 {
		if _, err := l.Write(record); err != nil {
			t.Fatal(err)
		}
	}
	old, err := os.Stat(path + ".1")
	if err != nil {
		t.Fatal(err)
	}
	cur, _ := os.Stat(path)
	if old.Size() > MaxLogFile || old.Size()%int64(len(record)) != 0 || cur.Size() == 0 || cur.Size() > MaxLogFile {
		t.Errorf("sizes %d and %d", old.Size(), cur.Size())
	}
}

func TestALogThatCannotRotateKeepsLogging(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.log")
	// A non-empty directory where the old log goes: the rename fails.
	if err := os.MkdirAll(filepath.Join(path+".1", "in-the-way"), 0o700); err != nil {
		t.Fatal(err)
	}
	l, err := OpenLog(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	record := bytes.Repeat([]byte("y"), 1000)
	for range MaxLogFile/len(record) + 10 {
		if n, _ := l.Write(record); n != len(record) {
			t.Fatalf("wrote %d of %d", n, len(record))
		}
	}
	if st, err := os.Stat(path); err != nil || st.Size() <= MaxLogFile {
		t.Errorf("the records were lost: %v %v", st, err)
	}
}

func TestExitStatusesFollowTheSpec(t *testing.T) {
	for err, want := range map[error]int{
		nil:                                 StatusOK,
		&bootstrap.UsageError{Msg: "x"}:     StatusUsage,
		&TakenOverError{}:                   StatusTakenOver,
		&Failure{Msg: "x"}:                  StatusFailed,
		errors.New("anything else"):         StatusFailed,
		fail(bootstrap.ErrNoServer, "none"): StatusFailed,
		errors.Join(&TakenOverError{}, nil): StatusTakenOver,
	} {
		if got := ExitStatus(err); got != want {
			t.Errorf("%v: %d", err, got)
		}
	}
}

// A CredentialLine round-tripped through Marshal and Parse gives the
// handshake the credential the server minted (bootstrap.md §12).
func TestTheLineCarriesTheCredentialExactly(t *testing.T) {
	line := bootstrap.CredentialLine{
		SoftwareVersion: "dev",
		Addr:            netip.MustParseAddr("192.0.2.1"),
		Port:            60123,
		CredentialID:    [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		SessionID:       [16]byte{0: 0xaa, 15: 0xbb},
		Name:            "work",
		PSK:             [32]byte{0: 1, 31: 2},
		Public:          bytes.Repeat([]byte{0x5a}, bootstrap.PublicKeySize),
	}
	parsed, err := bootstrap.ParseCredentialLine(bootstrap.MarshalCredentialLine(line))
	if err != nil {
		t.Fatal(err)
	}
	c := credentialFrom(parsed)
	if c.ID != line.CredentialID || c.SessionID != line.SessionID || c.PSK != line.PSK || !bytes.Equal(c.ServerPublic, line.Public) {
		t.Errorf("%+v", c)
	}
	parsed.Public[0] ^= 1
	if c.ServerPublic[0] != 0x5a {
		t.Error("the credential shares the line's key bytes")
	}
}

func TestTheLocalPrefixesAreTheMachinesOwn(t *testing.T) {
	for _, p := range localPrefixes(slog.New(slog.DiscardHandler)) {
		if !p.IsValid() || p.Addr().Is4In6() || p.Bits() < 0 {
			t.Errorf("%v", p)
		}
		if p.Addr().Is4() && p.Bits() > 32 {
			t.Errorf("%v", p)
		}
	}

}
