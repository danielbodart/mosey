#!/usr/bin/env bash
# Put each release binary's Sigstore bundle next to it, under the name
# docs/spec/bootstrap.md §4.6 fixes (mosey-<V>-<os>-<arch>.sigstore.json),
# and check every one as the client will before the release is published
# (D7, S1): so a release whose own clients would refuse its assets is
# never made.
#
# usage: scripts/release-bundles.sh VERSION DIR PLATFORM=BUNDLE ...
#
# DIR holds the binaries scripts/release-assets.sh laid out. Each
# PLATFORM=BUNDLE pairs a platform (linux-amd64, ...) with the file
# actions/attest-build-provenance wrote for that binary (its bundle-path
# output: one bundle, as one line of JSON). Every platform a release
# ships for must be given exactly once.
#
# The check is `gh attestation verify`, an implementation other than the
# client's, against the trusted root the client embeds
# (internal/provenance/trusted_root.json, offline), with the pins the
# client uses (internal/provenance: the workflow identity on trunk,
# GitHub's OIDC issuer, SLSA provenance, the binary's digest).
# internal/provenance's tests check that the pins below are the client's.
set -euo pipefail

identity="https://github.com/danielbodart/mosey/.github/workflows/ci.yml@refs/heads/trunk"
issuer="https://token.actions.githubusercontent.com"
predicate="https://slsa.dev/provenance/v1"

if [ $# -lt 3 ]; then
    echo "usage: scripts/release-bundles.sh VERSION DIR PLATFORM=BUNDLE ..." >&2
    exit 2
fi
version=$1
dir=$2
shift 2

root="$(git rev-parse --show-toplevel)/internal/provenance/trusted_root.json"
platforms=(darwin-amd64 darwin-arm64 linux-amd64 linux-arm64)

# gh reads a custom trusted root as JSON lines: one root, one line.
jsonl=$(mktemp)
trap 'rm -f "$jsonl"' EXIT
jq -c . "$root" >"$jsonl"

declare -A given
for pair in "$@"; do
    platform=${pair%%=*}
    bundle=${pair#*=}
    if [ -n "${given[$platform]:-}" ]; then
        echo "release-bundles: $platform given twice" >&2
        exit 2
    fi
    given[$platform]=$bundle
done

for platform in "${platforms[@]}"; do
    bundle=${given[$platform]:-}
    if [ -z "$bundle" ]; then
        echo "release-bundles: no bundle for $platform" >&2
        exit 1
    fi
    unset "given[$platform]"
    asset="$dir/mosey-$version-$platform"
    if [ "$(jq -s length "$bundle")" != 1 ]; then
        echo "release-bundles: $bundle is not exactly one bundle" >&2
        exit 1
    fi
    jq -c . "$bundle" >"$asset.sigstore.json"
    gh attestation verify "$asset" \
        --bundle "$asset.sigstore.json" \
        --custom-trusted-root "$jsonl" \
        --repo danielbodart/mosey \
        --cert-identity "$identity" \
        --cert-oidc-issuer "$issuer" \
        --predicate-type "$predicate"
done
if [ ${#given[@]} -ne 0 ]; then
    echo "release-bundles: not a platform a release ships for: ${!given[*]}" >&2
    exit 2
fi
ls -l "$dir"
