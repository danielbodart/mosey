#!/usr/bin/env bash
# Build quoin-chain against a quoin checkout's sudo/chain.zig and fd.zig.
# usage: build.sh QUOIN_DIR OUT
set -euo pipefail
Q=${1:?quoin dir}; OUT=${2:?out}
H=$(cd "$(dirname "$0")" >/dev/null && pwd)
mise exec zig@0.15.2 -- zig build-exe -O ReleaseSafe --name "$(basename "$OUT")" -femit-bin="$OUT" \
  --dep chain -Mroot="$H/main.zig" \
  --dep fd -Mchain="$Q/sudo/chain.zig" \
  -Mfd="$Q/sudo/fd.zig"
