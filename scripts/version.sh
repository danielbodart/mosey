#!/usr/bin/env bash
# The version, derived from the repository rather than stored in it, as in
# quoin and gokit.
#
# Only the major is committed (in ./VERSION): it is the one part that is a
# decision, and 0 says the wire protocol and the command line still move.
# The minor is the commit count, so it only ever rises and names exactly
# one commit. The patch is the CI run number, or locally a timestamp, so two
# builds of one commit differ and a developer's build sorts after CI's and
# is obviously not one of them.
set -euo pipefail

major=$(tr -d '[:space:]' < "$(git rev-parse --show-toplevel)/VERSION")

# Counted from HEAD, not a branch name: on Actions the checkout is detached.
if [ "$(git rev-parse --is-shallow-repository)" = true ]; then
    echo "version: shallow clone, so the commit count and the version are wrong." >&2
    echo "         In Actions, check out with \`fetch-depth: 0\`." >&2
    exit 1
fi

minor=$(git rev-list --count HEAD)
patch=${GITHUB_RUN_NUMBER:-$(date -u +%Y%m%d%H%M%S)}

printf '%s.%s.%s\n' "$major" "$minor" "$patch"
