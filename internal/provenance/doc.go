// Package provenance checks that a release asset mosey downloaded was
// built by mosey's own release workflow, before the client copies it to a
// host of another platform (D7, docs/spec/bootstrap.md §4.6, §4.7.4).
//
// SHA256SUMS, which the client also checks, comes from the same GitHub
// release as the binary, so it catches a corrupt or wrong file but not a
// release someone else published. Every release asset therefore carries a
// Sigstore bundle, made by CI's actions/attest-build-provenance: a SLSA
// provenance statement naming the asset's SHA-256, signed with a
// short-lived Fulcio certificate that names the workflow GitHub's OIDC
// token vouched for, and logged in Rekor. Verify accepts a bundle only if
// all of that holds against the trusted root embedded here, and only for
// the identity, issuer and digest it pins. There is no long-lived signing
// key to guard or rotate (D7, Dan, 2026-11-15).
//
// The trusted root is embedded, so verification needs no network beyond
// the asset and its bundle: scripts/trusted-root.sh refreshes it through
// Sigstore's TUF repository, weekly (update.yml). Signing times come from
// the bundle's own log entry and timestamps, never from the clock, so a
// client keeps verifying its own release's assets after the certificate
// that signed them expired, as Sigstore intends.
//
// The verification itself is sigstore-go's (D19: never our own crypto);
// this package only fixes the policy. It lives apart from internal/client
// so the policy is one small file to read, and so the client's tests can
// trust a virtual Sigstore (provenancetest) instead of the real one.
package provenance
