#!/usr/bin/env bash
# Whether the commit checked out is due a release: prints true and exits 0
# if anything a release is built from changed since the last release tag,
# else prints false and exits 1. With no release tag yet, it is due. CI's
# release job and the weekly update ask it (mise run release-due).
#
# A release is built from more than the Go source. Its binaries are
# compiled by scripts/build.sh with the Go mise.toml pins, not by the
# flake's (unlike quoin's, frisket's and chase's, which ship through Nix and
# so are built by the host's nixpkgs Go), so a Go patch, which is often a
# security fix to crypto/* or net, is a new release, as is a change to how
# the binary is built or stamped. Every path below is released:
#
#   cmd internal go.mod go.sum   the source and its requirements
#   VERSION scripts/version.sh   what the binary says it is
#   scripts/build.sh             how it is built (ldflags, -trimpath, D20's
#                                GOEXPERIMENT)
#   flake.nix                    how a Nix consumer pinning the tag
#                                installs the release's binary
#
# and, from mise.toml, only the Go pin: a bump of shellcheck or actionlint
# changes no binary. flake.lock (a consumer follows its own nixpkgs), the
# docs, the spikes, the VM tests and the workflows are not released, nor is
# nix/release.json, which a release adds on its tag's own commit.
set -euo pipefail
unset CDPATH
shopt -s inherit_errexit

cd "$(git rev-parse --show-toplevel)"

paths=(cmd internal go.mod go.sum VERSION scripts/version.sh scripts/build.sh flake.nix)

due() { echo true; exit 0; }

# The trunk commit the last release was made from, which is the parent of
# its tag's commit, not the tag's own commit (scripts/last-release.sh):
# that adds nix/release.json, which is the release's output, not its input.
read -r _ last < <(scripts/last-release.sh) || due

[ -z "$(git diff --name-only "$last" HEAD -- "${paths[@]}")" ] || due

# The `go = "..."` line of mise.toml's [tools] at a revision, empty if
# there is none.
gopin() {
    git show "$1:mise.toml" 2>/dev/null |
        sed -n -E '/^\[tools\]/,/^\[/s/^"?go"? *= *"([^"]*)".*$/\1/p'
}
[ "$(gopin "$last")" = "$(gopin HEAD)" ] || due

echo false
exit 1
