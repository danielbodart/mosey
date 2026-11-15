package provenance

import (
	_ "embed"
	"errors"
	"fmt"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// The pins (docs/spec/bootstrap.md §4.7.4, D7). A bundle is accepted only
// if its certificate says all of them.
const (
	// Identity is the certificate's subject alternative name: the
	// workflow that ran, at the ref it ran on. Only trunk releases (D10:
	// ci.yml's release job runs on trunk only), so a workflow run on any
	// other branch, a pull request or a fork cannot sign a release.
	Identity = "https://github.com/danielbodart/mosey/.github/workflows/ci.yml@refs/heads/trunk"
	// Issuer is GitHub Actions' OIDC issuer, whose token Fulcio checked
	// before it put Identity in the certificate.
	Issuer = "https://token.actions.githubusercontent.com"
	// PredicateType is what actions/attest-build-provenance attests:
	// SLSA provenance v1. Pinned so a bundle of another kind of statement
	// that happens to name the same digest is not taken for provenance.
	PredicateType = "https://slsa.dev/provenance/v1"
)

// MaxBundle bounds a bundle wherever one is read whole [choice]: a
// bundle is a certificate, a signature, a log entry with its inclusion
// proof and a small statement, about 10 KB.
const MaxBundle = 256 << 10

// trustedRoot is the public-good Sigstore instance's trusted root, as
// scripts/trusted-root.sh fetched it through TUF.
//
//go:embed trusted_root.json
var trustedRoot []byte

// TrustedRoot is the embedded trusted root, parsed.
func TrustedRoot() (*root.TrustedRoot, error) {
	tr, err := root.NewTrustedRootFromJSON(trustedRoot)
	if err != nil {
		return nil, fmt.Errorf("parsing the embedded Sigstore trusted root: %w", err)
	}
	return tr, nil
}

// ErrMissing is a release asset with no bundle.
var ErrMissing = errors.New("no Sigstore bundle")

// Verifier checks bundles against one trusted root and the pins above.
type Verifier struct {
	v  *verify.Verifier
	id verify.CertificateIdentity
}

// Default is a Verifier that trusts the embedded root.
func Default() (*Verifier, error) {
	tr, err := TrustedRoot()
	if err != nil {
		return nil, err
	}
	return New(tr)
}

// New is a Verifier that trusts material: the embedded root in
// production, a virtual Sigstore in tests.
//
// It requires what a public-good attestation from GitHub Actions has: a
// Rekor entry, at least one time the signature was observed (the entry's
// integrated time, or an RFC 3161 timestamp), and the certificate's
// signed certificate timestamp from the CT log. The certificate is
// checked at the observed time, never at the client's clock.
func New(material root.TrustedMaterial) (*Verifier, error) {
	return newVerifier(material, verify.WithSignedCertificateTimestamps(1))
}

// NewWithoutSCT is New without the signed certificate timestamp, for a
// virtual Sigstore (provenancetest), whose test CA puts none in its
// certificates. Nothing but tests calls it: the client uses Default.
func NewWithoutSCT(material root.TrustedMaterial) (*Verifier, error) {
	return newVerifier(material)
}

func newVerifier(material root.TrustedMaterial, extra ...verify.VerifierOption) (*Verifier, error) {
	opts := append([]verify.VerifierOption{
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	}, extra...)
	v, err := verify.NewVerifier(material, opts...)
	if err != nil {
		return nil, fmt.Errorf("setting up the Sigstore verifier: %w", err)
	}
	id, err := verify.NewShortCertificateIdentity(Issuer, "", Identity, "")
	if err != nil {
		return nil, fmt.Errorf("setting up the release identity: %w", err)
	}
	return &Verifier{v: v, id: id}, nil
}

// Verify says whether bundleJSON shows that the release workflow built
// the file whose SHA-256 is digest. Any error means no.
func (v *Verifier) Verify(bundleJSON []byte, digest [32]byte) error {
	if len(bundleJSON) == 0 {
		return ErrMissing
	}
	if len(bundleJSON) > MaxBundle {
		return fmt.Errorf("the Sigstore bundle is %d bytes, over %d", len(bundleJSON), MaxBundle)
	}
	var b bundle.Bundle
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return fmt.Errorf("parsing the Sigstore bundle: %w", err)
	}
	return v.verify(&b, digest)
}

func (v *Verifier) verify(e verify.SignedEntity, digest [32]byte) error {
	res, err := v.v.Verify(e, verify.NewPolicy(
		verify.WithArtifactDigest("sha256", digest[:]),
		verify.WithCertificateIdentity(v.id),
	))
	if err != nil {
		return fmt.Errorf("verifying the Sigstore bundle: %w", err)
	}
	if res.Statement == nil || res.Statement.GetPredicateType() != PredicateType {
		got := "none"
		if res.Statement != nil {
			got = fmt.Sprintf("%q", res.Statement.GetPredicateType())
		}
		return fmt.Errorf("the Sigstore bundle attests %s, not %s", got, PredicateType)
	}
	return nil
}
