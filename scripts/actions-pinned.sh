#!/usr/bin/env bash
# Every `uses:` in the workflows names a full commit SHA, with the release it
# is as a comment (`@<40 hex> # vX.Y.Z`), never a tag or a branch.
#
# Why every job and not only the release job: the release job attests, with
# the identity the client trusts (internal/provenance), whatever the build
# job uploaded, and the weekly update rewrites the trusted root the client
# embeds. A moved tag anywhere upstream of those (the toolchain mise-action
# installs, the bytes upload-artifact carries) could get a binary of its
# choosing attested, so the pin has to hold everywhere (S1). Bumping an
# action is a reviewed change of its SHA.
set -euo pipefail

cd "$(dirname "$0")/.." >/dev/null
status=0
while IFS= read -r line; do
    echo "not pinned by commit: $line" >&2
    status=1
done < <(grep -nE '^[[:space:]]*(-[[:space:]]+)?uses:' .github/workflows/*.yml |
    grep -vE 'uses:[[:space:]]+[^[:space:]@]+@[0-9a-f]{40}[[:space:]]+#[[:space:]]+v[0-9]' || true)
exit "$status"
