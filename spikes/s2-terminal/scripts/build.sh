#!/usr/bin/env bash
# Build every spike command (with the ghostty backend compiled in) into $1.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${1:?usage: build.sh <bin-dir>}"
cd "$HERE"
for c in cmd/*/; do
  n=$(basename "$c")
  ./scripts/ghostty-env.sh go build -tags ghostty -o "$BIN/$n" "./$c"
done
ls "$BIN"
