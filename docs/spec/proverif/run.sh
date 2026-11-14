#!/usr/bin/env bash
# Run every B3 model and print its RESULT lines with the wall time taken,
# in the form results.txt records.
#
# usage: docs/spec/proverif/run.sh > docs/spec/proverif/results.txt
#
# PROVERIF names the binary; without it, ProVerif 2.05 comes from nixpkgs.
set -euo pipefail

cd "$(dirname "$0")" >/dev/null

if [ -n "${PROVERIF:-}" ]; then
    run() { "$PROVERIF" "$@"; }
else
    run() { nix shell nixpkgs#proverif -c proverif "$@"; }
fi

for model in b3 b3_stdout_leak b3_noss2_sanity; do
    start=$(date +%s.%N)
    out=$(timeout 1800 nice -n 19 bash -c "$(declare -f run); run -lib common $model.pv" 2>&1) || true
    end=$(date +%s.%N)
    printf '### %s (%.1fs)\n' "$model" "$(echo "$end - $start" | bc)"
    # ProVerif numbers its variables (sid_12); the numbers change with any
    # edit, so they are dropped to keep the diff of results.txt readable.
    echo "$out" | grep -E '^RESULT|Error' | sed -E 's/_[0-9]+//g'
done
