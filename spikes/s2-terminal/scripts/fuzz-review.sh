#!/usr/bin/env bash
# Fuzz runs added for the S2 review: the cell-diff client decoder, the
# server->client round trip at sizes up to the clamp, and tuios with resizes
# up to the clamp and a heap invariant. Each in its own systemd scope.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${OUT:?set OUT}"; mkdir -p "$OUT"; cd "$HERE"
go() { mise exec go@1.27.3 -- go "$@"; }
run() { # name pkg target time
  (
    start=$(date +%s)
    systemd-run --user --scope --quiet --unit "mosey-spike-fuzz-$1" -p MemoryMax=4G -p MemorySwapMax=0 \
      mise exec go@1.27.3 -- go test "./$2" -run '^$' -fuzz "^$3\$" -fuzztime "$4" -parallel 3 > "$OUT/$1.log" 2>&1
    echo "target=$3 exit=$? wall_seconds=$(( $(date +%s) - start ))" >> "$OUT/$1.log"
  ) &
}
run apply celldiff FuzzApply "${T1:-15m}"
run roundtrip celldiff FuzzRoundTrip "${T1:-15m}"
run tuiosclamp fuzz FuzzTuiosClamp "${T2:-20m}"
wait
grep -h "^target=" "$OUT"/*.log
