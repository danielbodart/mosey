package provenance

import (
	"encoding/hex"
	"os"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/verify"
)

// testdata/gh_2.104.0_linux_amd64.tar.gz.sigstore.json is a real bundle
// that actions/attest-build-provenance made on GitHub Actions and the
// public-good Sigstore signed and logged: the GitHub CLI's release of
// gh_2.104.0_linux_amd64.tar.gz, fetched with `gh attestation download`
// on 2026-11-15. mosey's own releases are attested the same way, so this
// shows that the release policy (an SCT, a Rekor entry, an observed time)
// and the embedded trusted root accept what GitHub really produces, which
// the virtual Sigstore of provenancetest cannot show.
const (
	ghBundle   = "testdata/gh_2.104.0_linux_amd64.tar.gz.sigstore.json"
	ghIdentity = "https://github.com/cli/cli/.github/workflows/deployment.yml@refs/heads/trunk"
	ghDigest   = "98cb101ad87dbbd3f6b2f2bfcbd43197ccd07643140121d8a9cfaa91eadbc24e"
)

func ghVerifier(t *testing.T, identity string) *Verifier {
	t.Helper()
	v, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	if v.id, err = verify.NewShortCertificateIdentity(Issuer, "", identity, ""); err != nil {
		t.Fatal(err)
	}
	return v
}

func readGH(t *testing.T) ([]byte, [32]byte) {
	t.Helper()
	b, err := os.ReadFile(ghBundle)
	if err != nil {
		t.Fatal(err)
	}
	var d [32]byte
	if _, err := hex.Decode(d[:], []byte(ghDigest)); err != nil {
		t.Fatal(err)
	}
	return b, d
}

func TestARealGitHubAttestationVerifiesUnderTheReleasePolicy(t *testing.T) {
	b, d := readGH(t)
	if err := ghVerifier(t, ghIdentity).Verify(b, d); err != nil {
		t.Fatal(err)
	}
}

func TestARealGitHubAttestationIsNotMoseys(t *testing.T) {
	// The same genuine bundle, under the pins mosey's client really uses:
	// it was signed by another repository's workflow, so it is refused.
	b, d := readGH(t)
	v, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(b, d); err == nil {
		t.Error("the GitHub CLI's attestation passed as mosey's")
	}
	d[0] ^= 1
	if err := ghVerifier(t, ghIdentity).Verify(b, d); err == nil {
		t.Error("a genuine attestation passed for another digest")
	}
}
