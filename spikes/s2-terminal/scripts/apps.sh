#!/usr/bin/env bash
# Record real programs once (libghostty answering their queries), then replay
# the identical bytes into every candidate and score against libghostty.
# usage: apps.sh <bin-dir> <out-dir> [only]
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$1"; OUT="$2"; ONLY="${3:-}"
P=""
for p in vim htop fish zsh less; do
  P="$P:$(nix build --no-link --print-out-paths "nixpkgs#$p" 2>/dev/null | grep -v -- '-man$\|-doc$\|-xxd$' | head -1)/bin"
done
[ -n "${NO_RECORD:-}" ] || "$BIN/apprec" -out "$OUT/rec" -fixtures "$HERE/fixtures" -bin "${P#:}" -only "$ONLY"
"$BIN/appreplay" -rec "$OUT/rec" -out "$OUT/replay" -emus ghostty,tuios,charm,xtermgo,cy
"$BIN/vtcompare" -dir "$OUT/replay" -refs ghostty -emus ghostty,tuios,charm,xtermgo,cy -v
"$BIN/vtcompare" -dir "$OUT/replay" -refs ghostty -emus ghostty,tuios,charm,xtermgo,cy -ext .attr
