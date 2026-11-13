#!/usr/bin/env bash
# Benchmarks, run on an otherwise idle machine. Writes markdown tables to
# docs/spikes/s2-terminal/results/.
# usage: bench-all.sh <bin-dir> <apps-out>
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$1"; APPS="$2"
R="$HERE/../../docs/spikes/s2-terminal/results"
mkdir -p "$R"
host() { echo "Machine: $(uname -n), $(nproc) CPUs, $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ //'), $(date -u +%FT%TZ), load average at start: $(cut -d" " -f1-3 /proc/loadavg) (other spikes share this machine)"; }
{ echo "# Per-session memory and throughput"; echo; host; echo; "$BIN/perf" -emus ghostty,tuios,charm,xtermgo,cy -rec "$APPS/rec"; } > "$R/perf.md"
{ echo "# Structured cell diffs (celldiff prototype)"; echo; host; echo
  for e in tuios ghostty; do "$BIN/diffbench" -rec "$APPS/rec" -emu $e; echo; done; } > "$R/celldiff.md"
{ echo "# Helper-process boundary cost"; echo; host; echo
  for e in tuios ghostty; do "$BIN/boundary" -emu $e -n 20000; echo; done; } > "$R/boundary.md"
{ echo "# Hostile input"; echo; host; echo
  echo "Each cell: outcome, wall time, peak RSS; for runs killed at the limit, the throughput reached. Children run with GOMAXPROCS=2, 5 emulators in parallel per case, 30 s / 4 GiB limits."; echo
  "$BIN/hostile" -emus ghostty,tuios,charm,xtermgo,cy -timeout 30s; } > "$R/hostile.md"
echo done
