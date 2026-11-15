package provenance_test

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/danielbodart/mosey/internal/provenance"
	"github.com/danielbodart/mosey/internal/provenance/provenancetest"
)

var (
	asset     = []byte("mosey for linux/amd64, as a release carries it")
	assetName = "mosey-0.138.7-linux-amd64"
)

func TestTheEmbeddedTrustedRootParses(t *testing.T) {
	tr, err := provenance.TrustedRoot()
	if err != nil {
		t.Fatal(err)
	}
	// The public-good instance's: a Fulcio, a Rekor and a CT log, without
	// which no GitHub attestation of a public repository could verify.
	if len(tr.FulcioCertificateAuthorities()) == 0 || len(tr.RekorLogs()) == 0 || len(tr.CTLogs()) == 0 {
		t.Errorf("the embedded root has %d certificate authorities, %d Rekor logs and %d CT logs",
			len(tr.FulcioCertificateAuthorities()), len(tr.RekorLogs()), len(tr.CTLogs()))
	}
	if _, err := provenance.Default(); err != nil {
		t.Fatal(err)
	}
}

func TestABundleFromTheReleaseWorkflowVerifies(t *testing.T) {
	s := provenancetest.New(t)
	b := s.Bundle(t, assetName, provenancetest.Digest(asset), provenancetest.Attestation{})
	if err := s.Verifier.Verify(b, assetName, provenancetest.Digest(asset)); err != nil {
		t.Fatal(err)
	}
	// As actions/attest writes it: one line, ending in a newline.
	if err := s.Verifier.Verify(append(b, '\n'), assetName, provenancetest.Digest(asset)); err != nil {
		t.Fatal(err)
	}
}

func TestAWrongIdentityIsRefused(t *testing.T) {
	s := provenancetest.New(t)
	for _, id := range []string{
		"https://github.com/danielbodart/mosey/.github/workflows/ci.yml@refs/heads/feature",
		"https://github.com/danielbodart/mosey/.github/workflows/update.yml@refs/heads/trunk",
		"https://github.com/someone/mosey/.github/workflows/ci.yml@refs/heads/trunk",
		"https://github.com/danielbodart/mosey/.github/workflows/ci.yml@refs/pull/1/merge",
	} {
		b := s.Bundle(t, assetName, provenancetest.Digest(asset), provenancetest.Attestation{Identity: id})
		if err := s.Verifier.Verify(b, assetName, provenancetest.Digest(asset)); err == nil {
			t.Errorf("a bundle signed as %s was accepted", id)
		}
	}
}

func TestAWrongIssuerIsRefused(t *testing.T) {
	s := provenancetest.New(t)
	b := s.Bundle(t, assetName, provenancetest.Digest(asset), provenancetest.Attestation{Issuer: "https://accounts.google.com"})
	if err := s.Verifier.Verify(b, assetName, provenancetest.Digest(asset)); err == nil {
		t.Error("a bundle from another OIDC issuer was accepted")
	}
}

func TestAWrongDigestIsRefused(t *testing.T) {
	s := provenancetest.New(t)
	b := s.Bundle(t, assetName, provenancetest.Digest(asset), provenancetest.Attestation{})
	other := provenancetest.Digest([]byte("another binary"))
	if err := s.Verifier.Verify(b, assetName, other); err == nil {
		t.Error("a bundle for another file was accepted")
	}
}

// A genuine bundle for another release's asset, put in this release
// under this asset's name with a SHA256SUMS line to match, is refused:
// otherwise whoever can upload release assets could serve an old,
// vulnerable mosey as the current one, or one platform's as another's.
func TestAGenuineBundleForAnotherAssetIsRefused(t *testing.T) {
	s := provenancetest.New(t)
	for _, other := range []string{
		"mosey-0.100.3-linux-amd64",  // an older release
		"mosey-0.138.7-linux-arm64",  // another platform
		"mosey-0.138.7-darwin-amd64", // another OS
		"mosey",                      // no version at all
		"",
	} {
		b := s.Bundle(t, other, provenancetest.Digest(asset), provenancetest.Attestation{})
		err := s.Verifier.Verify(b, assetName, provenancetest.Digest(asset))
		if err == nil || !strings.Contains(err.Error(), "does not attest "+assetName) {
			t.Errorf("a bundle for %q passed as %s: %v", other, assetName, err)
		}
	}
}

func TestAnotherKindOfStatementIsRefused(t *testing.T) {
	s := provenancetest.New(t)
	b := s.Bundle(t, assetName, provenancetest.Digest(asset), provenancetest.Attestation{PredicateType: "https://spdx.dev/Document/v2.3"})
	err := s.Verifier.Verify(b, assetName, provenancetest.Digest(asset))
	if err == nil || !strings.Contains(err.Error(), "not "+provenance.PredicateType) {
		t.Errorf("got %v", err)
	}
}

func TestAMissingBundleIsRefused(t *testing.T) {
	s := provenancetest.New(t)
	if err := s.Verifier.Verify(nil, assetName, provenancetest.Digest(asset)); !errors.Is(err, provenance.ErrMissing) {
		t.Errorf("got %v", err)
	}
}

func TestABundleFromAnotherSigstoreIsRefused(t *testing.T) {
	// Signed by a Sigstore the verifier does not trust, with every pin
	// right: the trusted root is what makes the identity mean anything.
	b := provenancetest.New(t).Bundle(t, assetName, provenancetest.Digest(asset), provenancetest.Attestation{})
	if err := provenancetest.New(t).Verifier.Verify(b, assetName, provenancetest.Digest(asset)); err == nil {
		t.Error("a bundle from an untrusted Sigstore was accepted")
	}
	v, err := provenance.Default()
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(b, assetName, provenancetest.Digest(asset)); err == nil {
		t.Error("the embedded root accepted a virtual Sigstore's bundle")
	}
}

func TestTheReleasePolicyRequiresACertificateTimestamp(t *testing.T) {
	// The virtual CA's certificates carry no SCT, so the production
	// policy, which demands one, refuses what NewWithoutSCT accepts.
	s := provenancetest.New(t)
	b := s.Bundle(t, assetName, provenancetest.Digest(asset), provenancetest.Attestation{})
	v, err := provenance.New(s.VS)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(b, assetName, provenancetest.Digest(asset)); err == nil {
		t.Error("a certificate with no SCT was accepted")
	}
}

func TestATamperedOrOversizedBundleIsRefused(t *testing.T) {
	s := provenancetest.New(t)
	b := s.Bundle(t, assetName, provenancetest.Digest(asset), provenancetest.Attestation{})
	for name, in := range map[string][]byte{
		"not JSON":  []byte("not a bundle"),
		"cut short": b[:len(b)/2],
		"oversized": append(append([]byte{}, b...), make([]byte, provenance.MaxBundle)...),
		"no tlog":   without(t, b, "tlogEntries"),
	} {
		if err := s.Verifier.Verify(in, assetName, provenancetest.Digest(asset)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// without is bundle b with one field of its verification material left
// out: still a well-formed bundle, but missing what the policy requires.
func without(t *testing.T, b []byte, field string) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	delete(m["verificationMaterial"].(map[string]any), field)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The release job checks each bundle with scripts/release-bundles.sh
// before publishing it; that is only the client's check if it pins the
// same things.
func TestTheReleaseJobChecksWhatTheClientChecks(t *testing.T) {
	script, err := os.ReadFile("../../scripts/release-bundles.sh")
	if errors.Is(err, fs.ErrNotExist) {
		// The Nix build's source holds only cmd/, internal/ and go.mod
		// (flake.nix); `mise run check` runs this from the repository.
		t.Skip("scripts/ is not in this source tree")
	}
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"identity":  provenance.Identity,
		"issuer":    provenance.Issuer,
		"predicate": provenance.PredicateType,
	} {
		if line := name + `="` + want + `"`; !strings.Contains(string(script), "\n"+line+"\n") {
			t.Errorf("scripts/release-bundles.sh does not say %s", line)
		}
	}
	// gh attestation verify does not check the subject's name, which the
	// client pins, so the script checks it with jq.
	if !strings.Contains(string(script), `[.subject[] | select(.name == $name)]`) || !strings.Contains(string(script), `--arg name "mosey-$version-$platform"`) {
		t.Error("scripts/release-bundles.sh does not check that each bundle names its asset")
	}
}
