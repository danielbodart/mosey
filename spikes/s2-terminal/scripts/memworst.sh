#!/usr/bin/env bash
# Worst-case memory per tuios session (S2 review). Each case runs in its own
# transient systemd scope with a hard memory cap, so a runaway case is killed
# rather than swapping the machine. usage: memworst.sh <bin-dir> [lines]
set -uo pipefail
BIN="$1"; LINES="${2:-2000}"
for cols in 80 200 500 1000; do
  for m in "plain" "color" "cluster" "link -linklen 256" "link -linklen 2048"; do
    timeout 600 systemd-run --user --scope --quiet --unit "mosey-spike-s2-mem-$RANDOM" \
      -p MemoryMax=12G -p MemorySwapMax=0 \
      "$BIN/memworst" -cols "$cols" -rows 60 -mode $m -lines "$LINES" | grep -v backend= | tail -1 \
      | sed "s/^/$(echo $m | tr ' ' '_') /"
    echo "  exit=$?"
  done
done
