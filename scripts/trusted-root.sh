#!/usr/bin/env bash
# Refresh the Sigstore trusted root that mosey embeds
# (internal/provenance/trusted_root.json), which the client checks a
# downloaded release's provenance bundle against before copying it to a
# host of another platform (D7, docs/spec/bootstrap.md §4.6, §4.7.4).
#
# usage: scripts/trusted-root.sh [OUT]   (default: internal/provenance/trusted_root.json)
#
# `gh attestation trusted-root` fetches it through Sigstore's TUF
# repository, verifying the chain from the TUF root that gh itself ships,
# so what lands here is what Sigstore signed, not merely what a server
# said. It prints one trusted root per line: the public-good instance's
# and GitHub's own. mosey's repository is public, so its attestations are
# signed by the public-good instance (Fulcio certificates, Rekor log
# entries), and only that root is kept: a root that is not needed is trust
# that is not needed. It is the one whose certificate authority is
# https://fulcio.sigstore.dev.
#
# The weekly update (.github/workflows/update.yml) runs this, so a key
# Sigstore rotates in reaches the next release; the release job checks
# every bundle it publishes against the file it is built with, so a
# release whose own clients could not verify its assets is never made.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

out=${1:-internal/provenance/trusted_root.json}

roots=$(gh attestation trusted-root)
public=$(jq -c 'select(any(.certificateAuthorities[]?; .uri == "https://fulcio.sigstore.dev"))' <<<"$roots")
if [ "$(grep -c . <<<"$public")" -ne 1 ]; then
    echo "trusted-root: want exactly one public-good trusted root from gh attestation trusted-root, found $(grep -c . <<<"$public")" >&2
    exit 1
fi
# Indented, so the weekly commit's diff shows which key moved.
jq . <<<"$public" >"$out.tmp"
mv "$out.tmp" "$out"
echo "trusted-root: wrote $out"
