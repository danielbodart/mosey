#!/usr/bin/env bash
# Rerun of the timing benchmarks for the S2 review: several repetitions,
# interleaved, with the load average recorded before each.
# usage: bench-review.sh <bin-dir> <apps-rec-dir> [reps]
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$1"; REC="$2"; REPS="${3:-3}"
R="$HERE/../../docs/spikes/s2-terminal/results"
host() { echo "Machine: $(uname -n), $(nproc) CPUs, $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ //'), $(date -u +%FT%TZ), load average: $(cut -d" " -f1-3 /proc/loadavg) (other spikes share this machine)"; }
{ echo "# Per-session memory and throughput"; echo; host; echo
  "$BIN/perf" -emus ghostty,tuios,charm,xtermgo,cy -rec "$REC" -reps "$REPS"
  echo; echo "Finished: $(date -u +%FT%TZ), load average: $(cut -d" " -f1-3 /proc/loadavg)"; } > "$R/perf.md"
{ echo "# Helper-process boundary cost"; echo; echo "$REPS repetitions, one table each, tuios then libghostty alternating."; echo
  for r in $(seq "$REPS"); do for e in tuios ghostty; do echo "Run $r: $(host)"; echo; "$BIN/boundary" -emu $e -n 20000; echo; done; done; } > "$R/boundary.md"
{ echo "# Structured cell diffs (celldiff prototype, hardened after the review)"; echo
  echo "Diff bytes are deterministic; timings are from $REPS runs (each table is one run)."; echo
  for r in $(seq "$REPS"); do for e in tuios ghostty; do echo "Run $r: $(host)"; echo; "$BIN/diffbench" -rec "$REC" -emu $e; echo; done; done; } > "$R/celldiff.md"
echo done
