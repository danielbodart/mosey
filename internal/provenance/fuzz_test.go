package provenance_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"

	"github.com/danielbodart/mosey/internal/provenance"
	"github.com/danielbodart/mosey/internal/provenance/provenancetest"
)

// FuzzVerify feeds Verify what a hostile release could serve as a bundle
// (it comes from the network, CLAUDE.md). Verify must never panic, and
// whatever it accepts must, read independently of it, be a bundle whose
// certificate names the release workflow and whose statement names the
// asset and digest asked about, in one subject: so no mutation turns a
// refusal into a wrong yes.
func FuzzVerify(f *testing.F) {
	s := provenancetest.New(f)
	digest := provenancetest.Digest(asset)
	f.Add(s.Bundle(f, assetName, digest, provenancetest.Attestation{}))
	f.Add(s.Bundle(f, assetName, digest, provenancetest.Attestation{Identity: "https://example.com/x"}))
	if real, err := os.ReadFile("testdata/gh_2.104.0_linux_amd64.tar.gz.sigstore.json"); err == nil {
		f.Add(real)
	}
	f.Add([]byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`))
	f.Add([]byte("{}"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if err := s.Verifier.Verify(b, assetName, digest); err != nil {
			return
		}
		var bb bundle.Bundle
		if err := bb.UnmarshalJSON(b); err != nil {
			t.Fatalf("accepted, but does not parse: %v", err)
		}
		vc, err := bb.VerificationContent()
		if err != nil {
			t.Fatal(err)
		}
		cert, ok := vc.(*bundle.Certificate)
		if !ok {
			t.Fatalf("accepted with %T, not a certificate", vc)
		}
		sum, err := certificate.SummarizeCertificate(cert.Certificate())
		if err != nil {
			t.Fatalf("accepted a certificate that does not summarize: %v", err)
		}
		if sum.SubjectAlternativeName != provenance.Identity || sum.Issuer != provenance.Issuer {
			t.Fatalf("accepted a certificate for %q from %q", sum.SubjectAlternativeName, sum.Issuer)
		}
		env := bb.GetDsseEnvelope()
		if env == nil {
			t.Fatal("accepted with no DSSE envelope")
		}
		var st struct {
			PredicateType string `json:"predicateType"`
			Subject       []struct {
				Name   string            `json:"name"`
				Digest map[string]string `json:"digest"`
			} `json:"subject"`
		}
		if err := json.Unmarshal(env.Payload, &st); err != nil {
			t.Fatalf("accepted a statement that does not parse: %v", err)
		}
		if st.PredicateType != provenance.PredicateType {
			t.Fatalf("accepted predicate %q", st.PredicateType)
		}
		for _, sub := range st.Subject {
			if sub.Name == assetName && sub.Digest["sha256"] == hex.EncodeToString(digest[:]) {
				return
			}
		}
		t.Fatalf("accepted a statement about %v", st.Subject)
	})
}
