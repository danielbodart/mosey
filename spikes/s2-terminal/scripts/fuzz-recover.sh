#!/usr/bin/env bash
# Phase-2 fuzzing: one target, panics and invariant failures recorded (not
# fatal) via MOSEY_FUZZ_RECOVER, and the run restarted after a hang (which go's
# fuzzer cannot recover from) until TOTAL seconds of fuzzing have been spent.
# Hang reproducers are moved to fuzz/crashers/<Target>/ so they don't become
# seeds of the restarted run.
# usage: OUT=... LIBGHOSTTY_PREFIX=... fuzz-recover.sh <Target> <total-seconds> [parallel]
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
T="$1"; TOTAL="$2"; PAR="${3:-3}"
OUT="${OUT:?}"; mkdir -p "$OUT" "$HERE/fuzz/crashers/Fuzz$T"
LOG="$OUT/recover-${T,,}.log"; FAILS="$OUT/failures-${T,,}.tsv"
cd "$HERE"
spent=0; round=0
while [ "$spent" -lt "$TOTAL" ]; do
  round=$((round+1)); left=$((TOTAL-spent)); start=$(date +%s)
  systemd-run --user --scope --quiet --unit "mosey-spike-fuzz2-${T,,}-$round" \
    -p MemoryMax="${MEM:-6G}" -p MemorySwapMax=0 \
    env MOSEY_FUZZ_RECOVER="$FAILS" LIBGHOSTTY_PREFIX="$LIBGHOSTTY_PREFIX" \
    ./scripts/ghostty-env.sh go test -tags ghostty ./fuzz -run '^$' \
      -fuzz "^Fuzz${T}\$" -fuzztime "${left}s" -parallel "$PAR" >> "$LOG" 2>&1
  rc=$?
  el=$(( $(date +%s) - start )); spent=$((spent+el))
  echo "round=$round exit=$rc seconds=$el spent=$spent" | tee -a "$LOG"
  if [ "$rc" -ne 0 ]; then
    for f in fuzz/testdata/fuzz/Fuzz$T/*; do
      [ -e "$f" ] || continue
      printf 'hang\tround%d\t-\t%s\n' "$round" "$(tail -1 "$f")" >> "$FAILS"
      mv "$f" "fuzz/crashers/Fuzz$T/"
    done
  fi
  [ "$rc" -eq 0 ] && break
  [ "$round" -ge 15 ] && { echo "giving up after 15 rounds" | tee -a "$LOG"; break; }
done
echo "target=$T rounds=$round fuzz_seconds=$spent" | tee -a "$LOG"
