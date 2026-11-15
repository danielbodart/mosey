package client

import (
	"bytes"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/danielbodart/mosey/internal/bootstrap"
)

// R3's real try (bootstrap.md §9.2.2), against an ssh and a server that
// are stand-ins: it runs ssh in batch mode with the line resume:SID:CREDID
// for the transport's own credential, and turns the launcher's answer into
// what the session's loop acts on: `session` and `taken` end the client, a
// credential for another session is a failure to try again after, and the
// session's own credential is a new transport to it.
func TestTheReconnectTryResumesItsOwnSessionByIDAndHolder(t *testing.T) {
	sid := [16]byte{0x5e, 0x55}
	holder := [8]byte{7, 7}
	try := func(t *testing.T, stdout []byte) (*Reattach, error) {
		t.Helper()
		dir := t.TempDir()
		o := Options{
			SSH:      bootstrap.SSH{Program: fakeSSH(t, dir, "hostname 127.0.0.1\n", 0), Destination: "far", Server: fakeServer(t, dir, stdout, nil, "0")},
			Version:  "1.2.3",
			Terminal: newFakeTerm(100, 30),
			Log:      slog.New(slog.DiscardHandler),
			Getenv:   func(string) string { return "" },
		}
		r, err := reconnector(o, sid)(t.Context(), holder)
		if r != nil {
			t.Cleanup(func() { r.Conn.Close(); r.Key.Wipe() })
		}
		argv, _ := os.ReadFile(filepath.Join(dir, "argv"))
		if !slices.Contains(strings.Split(string(argv), "\n"), "BatchMode=yes") {
			t.Errorf("ssh ran as %q, not in batch mode", argv)
		}
		stdin, _ := os.ReadFile(filepath.Join(dir, "stdin"))
		cl, perr := bootstrap.ParseClientLine(stdin)
		if perr != nil || cl.Attach != bootstrap.AttachResume || cl.SessionID != sid || !cl.HasHolder || cl.Holder != holder ||
			cl.Cols != 100 || cl.Rows != 30 || cl.SoftwareVersion != "1.2.3" {
			t.Errorf("the server read %q: %v", stdin, perr)
		}
		return r, err
	}
	refusal := func(code, detail string) []byte {
		return bootstrap.MarshalErrorLine(bootstrap.ErrorLine{Proto: bootstrap.Version, Code: code, Detail: detail})
	}
	credential := func(of [16]byte) []byte {
		return bootstrap.MarshalCredentialLine(bootstrap.CredentialLine{
			SoftwareVersion: "1.2.3", Addr: netip.MustParseAddr("127.0.0.1"), Port: 60001,
			CredentialID: [8]byte{9}, SessionID: of, Name: "work", Public: bytes.Repeat([]byte{6}, bootstrap.PublicKeySize),
		})
	}

	t.Run("gone", func(t *testing.T) {
		r, err := try(t, refusal(bootstrap.CodeSession, "-"))
		if r != nil || !errors.Is(err, ErrSessionGone) || !isFinal(err) {
			t.Errorf("%v", err)
		}
	})
	t.Run("taken", func(t *testing.T) {
		r, err := try(t, refusal(bootstrap.CodeTaken, "1794650000"))
		var taken *TakenOverError
		if r != nil || !errors.As(err, &taken) || !taken.At.Equal(time.Unix(1794650000, 0)) || !isFinal(err) {
			t.Errorf("%v", err)
		}
	})
	t.Run("another session", func(t *testing.T) {
		r, err := try(t, credential([16]byte{0x0e}))
		if r != nil || err == nil || isFinal(err) {
			t.Errorf("a credential for another session: %v, %+v", err, r)
		}
	})
	t.Run("a passing failure", func(t *testing.T) {
		r, err := try(t, refusal(bootstrap.CodeInternal, "-"))
		if r != nil || err == nil || isFinal(err) {
			t.Errorf("internal: %v", err)
		}
	})
	t.Run("its own session", func(t *testing.T) {
		r, err := try(t, credential(sid))
		if err != nil {
			t.Fatal(err)
		}
		if r.Credential.SessionID != sid || r.Credential.ID != [8]byte{9} || r.Server != netip.MustParseAddrPort("127.0.0.1:60001") ||
			r.Conn == nil || r.Key == nil {
			t.Errorf("reattach %+v", r)
		}
	})
}
