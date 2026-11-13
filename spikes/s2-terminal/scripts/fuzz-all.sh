#!/usr/bin/env bash
# Fuzz every candidate concurrently, each in its own throwaway systemd user
# scope (mosey-spike-fuzz-<name>) with a memory cap, for FUZZTIME each.
# Logs and the time each run really took go to $OUT.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${OUT:?set OUT to a scratch directory}"
FUZZTIME="${FUZZTIME:-20m}"
PAR="${PAR:-3}"
MEM="${MEM:-6G}"
mkdir -p "$OUT"
cd "$HERE"
for t in Tuios Charm Xtermgo Cy Ghostty; do
  (
    start=$(date +%s)
    systemd-run --user --scope --quiet --unit "mosey-spike-fuzz-${t,,}" \
      -p MemoryMax="$MEM" -p MemorySwapMax=0 \
      env LIBGHOSTTY_PREFIX="$LIBGHOSTTY_PREFIX" \
      ./scripts/ghostty-env.sh go test -tags ghostty ./fuzz -run '^$' \
        -fuzz "^Fuzz${t}\$" -fuzztime "$FUZZTIME" -parallel "$PAR" \
      > "$OUT/fuzz-${t,,}.log" 2>&1
    rc=$?
    echo "target=$t exit=$rc wall_seconds=$(( $(date +%s) - start ))" >> "$OUT/fuzz-${t,,}.log"
  ) &
done
wait
grep -h "^target=" "$OUT"/fuzz-*.log
