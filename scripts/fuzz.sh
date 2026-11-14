#!/usr/bin/env bash
# Run every fuzz target in the module for FUZZTIME each (default 10s).
#
# This is a smoke test, for CI and for a quick look after a change. A
# campaign, which every parser of attacker-reachable input gets before it
# lands, is the same command with a longer FUZZTIME, and its duration and
# exec count go in the commit message.
#
# usage: FUZZTIME=5m scripts/fuzz.sh [package ...]    (default: ./...)
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

fuzztime=${FUZZTIME:-10s}
packages=("$@")
[ ${#packages[@]} -gt 0 ] || packages=(./...)

found=0
while read -r pkg; do
    # go test -fuzz takes one target at a time, so list them first.
    while read -r target; do
        [ -n "$target" ] || continue
        found=$((found + 1))
        echo "== $pkg $target ($fuzztime)"
        go test -run '^$' -fuzz "^${target}\$" -fuzztime "$fuzztime" "$pkg"
    done < <(go test -list '^Fuzz' "$pkg" | grep '^Fuzz' || true)
done < <(go list "${packages[@]}")

echo "$found fuzz targets"
