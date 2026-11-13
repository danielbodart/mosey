#!/usr/bin/env bash
# Regenerate the O8 capture sessions (vim and htop come from nixpkgs).
# Usage: run-captures.sh OUTDIR   (run from spikes/s5-netsim-ssp)
# Timing-dependent output means the bytes will differ from the committed
# files; the SHA-256 sums in README.md identify the ones the results used.
set -euo pipefail
OUT=${1:?outdir}
mkdir -p "$OUT"
F=$PWD/ssp/transport.go   # the file shown by vim, less and grep in the sessions
go build -o "$OUT/capture" ./cmd/capture
cd "$OUT"
for s in shell less top flood; do
  ./capture -session $s -file "$F" -out $s.bin
done
nix shell nixpkgs#vim nixpkgs#htop -c ./capture -session vim -file "$F" -out vim.bin
nix shell nixpkgs#vim nixpkgs#htop -c ./capture -session htop -file "$F" -out htop.bin
