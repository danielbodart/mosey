#!/usr/bin/env bash
# Build the spike's binaries into DIR/bin. The server stand-in is installed
# as "mosey-server", the comm quoin 0331bf1's chain.zig rule matches; the
# quoin-chain tool is quoin's own chain.zig from QUOIN (default: the spike's
# quoin worktree).
# usage: build.sh DIR [QUOIN_DIR]
set -euo pipefail
S=${1:?dir}; Q=${2:-/home/dan/Projects/quoin-mosey-s3}
H=$(cd "$(dirname "$0")/.." >/dev/null && pwd)
mkdir -p "$S/bin"
(cd "$H" && mise exec go@1.27.3 -- go build -o "$S/bin/moseyc" ./cmd/moseyc &&
            mise exec go@1.27.3 -- go build -o "$S/bin/mosey-server" ./cmd/moseys)
"$H/quoinchain/build.sh" "$Q" "$S/bin/quoin-chain"
git -C "$Q" rev-parse --short HEAD > "$S/bin/quoin-rev"
