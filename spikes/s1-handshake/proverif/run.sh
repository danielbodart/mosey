#!/usr/bin/env bash
# Runs every model and prints the RESULT lines with wall time.
# Usage: ./run.sh > results.txt
set -u
cd "$(dirname "$0")"
# ProVerif 2.05, pinned to the nixpkgs revision used for results.txt.
# Override with PROVERIF_PKG=nixpkgs#proverif to use the registry's nixpkgs.
PKG=${PROVERIF_PKG:-github:NixOS/nixpkgs/c56a87d8e41ce69bd2af57eb35dcc117a9dfca33#proverif}
for f in b1 b1_psk_leak b1_skS_leak b2 b2_psk_leak b3 b3_stdout_leak b3_noss2_sanity a a_kci a_nomac; do
  [ -f "$f.pv" ] || continue
  s=$(date +%s.%N)
  out=$(timeout 1800 nix shell "$PKG" -c proverif -lib common "$f.pv" 2>&1)
  e=$(date +%s.%N)
  printf '### %s (%.1fs)\n' "$f" "$(echo "$e - $s" | bc)"
  echo "$out" | grep -E '^RESULT|Error' | sed -E 's/_[0-9]+//g'
done
