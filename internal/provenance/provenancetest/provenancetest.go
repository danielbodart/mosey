// Package provenancetest is a virtual Sigstore for tests: it signs
// release bundles as the real release workflow's would be signed, in the
// same JSON a release publishes, and gives the Verifier that trusts it.
// No network is used (CLAUDE.md: nothing in CI depends on a live
// service).
//
// The certificates, log entries and timestamps are made by sigstore-go's
// own test CA (pkg/testing/ca), so the bundles go through every check the
// real ones do except one: that CA embeds no signed certificate timestamp
// in its leaf certificates, so the Verifier here is
// provenance.NewWithoutSCT. provenance's own tests show that the
// production policy does require one.
package provenancetest

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/danielbodart/mosey/internal/provenance"
)

// Sigstore is one virtual Sigstore instance: its own Fulcio, Rekor, CT
// log and timestamp authority.
type Sigstore struct {
	VS *ca.VirtualSigstore
	// Verifier trusts VS and pins what provenance pins.
	Verifier *provenance.Verifier
}

// New starts a virtual Sigstore.
func New(t testing.TB) *Sigstore {
	t.Helper()
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("starting a virtual Sigstore: %v", err)
	}
	v, err := provenance.NewWithoutSCT(vs)
	if err != nil {
		t.Fatal(err)
	}
	return &Sigstore{VS: vs, Verifier: v}
}

// Attestation says what to sign. The zero value of each field is what
// the release workflow signs.
type Attestation struct {
	Identity      string // provenance.Identity
	Issuer        string // provenance.Issuer
	PredicateType string // provenance.PredicateType
}

// Bundle is the bundle a release would publish for the asset called name
// (bootstrap.AssetName) whose SHA-256 is digest, as JSON (Sigstore bundle
// v0.3, as actions/attest writes it): one subject, named after the file.
func (s *Sigstore) Bundle(t testing.TB, name string, digest [32]byte, a Attestation) []byte {
	t.Helper()
	if a.Identity == "" {
		a.Identity = provenance.Identity
	}
	if a.Issuer == "" {
		a.Issuer = provenance.Issuer
	}
	if a.PredicateType == "" {
		a.PredicateType = provenance.PredicateType
	}
	statement, err := json.Marshal(map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"name": name, "digest": map[string]string{"sha256": hex.EncodeToString(digest[:])}}},
		"predicateType": a.PredicateType,
		"predicate":     map[string]any{"buildDefinition": map[string]any{"buildType": "https://actions.github.io/buildtypes/workflow/v1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// The integrated time must fall inside the leaf certificate's
	// validity, which the test CA starts at now; sigstore-go's own Attest
	// signs at now + 5 minutes for the same reason.
	e, err := s.VS.AttestAtTime(a.Identity, a.Issuer, statement, time.Now().Add(5*time.Minute), true)
	if err != nil {
		t.Fatalf("attesting: %v", err)
	}
	return s.marshal(t, e)
}

// marshal writes e as the protobuf bundle JSON a release carries.
func (s *Sigstore) marshal(t testing.TB, e *ca.TestEntity) []byte {
	t.Helper()
	vc, err := e.VerificationContent()
	if err != nil {
		t.Fatal(err)
	}
	cert := vc.(*bundle.Certificate).Certificate()
	sc, err := e.SignatureContent()
	if err != nil {
		t.Fatal(err)
	}
	env := sc.(*bundle.Envelope).RawEnvelope()
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var sigs []*protodsse.Signature
	for _, sig := range env.Signatures {
		raw, err := base64.StdEncoding.DecodeString(sig.Sig)
		if err != nil {
			t.Fatal(err)
		}
		sigs = append(sigs, &protodsse.Signature{Sig: raw, Keyid: sig.KeyID})
	}
	entries, err := e.TlogEntries()
	if err != nil {
		t.Fatal(err)
	}
	var tles []*protorekor.TransparencyLogEntry
	for _, entry := range entries {
		tles = append(tles, s.logEntry(t, entry))
	}
	stamps, err := e.Timestamps()
	if err != nil {
		t.Fatal(err)
	}
	var rfc3161 []*protocommon.RFC3161SignedTimestamp
	for _, ts := range stamps {
		rfc3161 = append(rfc3161, &protocommon.RFC3161SignedTimestamp{SignedTimestamp: ts})
	}
	pb := &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content:                   &protobundle.VerificationMaterial_Certificate{Certificate: &protocommon.X509Certificate{RawBytes: cert.Raw}},
			TlogEntries:               tles,
			TimestampVerificationData: &protobundle.TimestampVerificationData{Rfc3161Timestamps: rfc3161},
		},
		Content: &protobundle.Bundle_DsseEnvelope{DsseEnvelope: &protodsse.Envelope{
			Payload: payload, PayloadType: env.PayloadType, Signatures: sigs,
		}},
	}
	out, err := protojson.Marshal(pb)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// logEntry is entry as a bundle carries it. The test CA keeps the
// entry's signed entry timestamp to itself, so it is signed again here
// over the same payload, by the same log key, as Rekor's would be.
func (s *Sigstore) logEntry(t testing.TB, entry *tlog.Entry) *protorekor.TransparencyLogEntry {
	t.Helper()
	tle := entry.TransparencyLogEntry()
	set, err := s.VS.RekorSignPayload(tlog.RekorPayload{
		Body:           base64.StdEncoding.EncodeToString(tle.CanonicalizedBody),
		IntegratedTime: tle.IntegratedTime,
		LogIndex:       tle.LogIndex,
		LogID:          hex.EncodeToString(tle.LogId.KeyId),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &protorekor.TransparencyLogEntry{
		LogIndex:          tle.LogIndex,
		LogId:             tle.LogId,
		KindVersion:       &protorekor.KindVersion{Kind: "dsse", Version: "0.0.1"},
		IntegratedTime:    tle.IntegratedTime,
		InclusionPromise:  &protorekor.InclusionPromise{SignedEntryTimestamp: set},
		InclusionProof:    tle.InclusionProof,
		CanonicalizedBody: tle.CanonicalizedBody,
	}
}

// Digest is a file's SHA-256, as provenance.Verifier.Verify takes it.
func Digest(b []byte) [32]byte { return sha256.Sum256(b) }
