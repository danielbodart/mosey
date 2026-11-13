#!/usr/bin/env bash
# Run vttest against tmux (oracle) and every candidate with the same script.
# usage: vttest-all.sh <bin-dir> <out-dir> [menus] [emulators...]
set -uo pipefail
BIN="$1"; OUT="$2"; MENUS="${3:-1,2,3,4,7,8}"; shift 3 || true
EMUS=("$@"); [ ${#EMUS[@]} -eq 0 ] && EMUS=(tmux ghostty tuios charm xtermgo cy)
VT="$(nix build --no-link --print-out-paths nixpkgs#vttest)/bin/vttest"
"$VT" -V
mkdir -p "$OUT"
for e in "${EMUS[@]}"; do
  ( "$BIN/vttest-drive" -emu "$e" -out "$OUT" -vttest "$VT" -menus "$MENUS" > "$OUT/$e.log" 2>&1; echo "$e exit=$?" ) &
done
wait
