#!/usr/bin/env bash
# Black-box sweep of the installed mosh-client's adaptive prediction display.
# For each one-way netem delay D (RTT = 2D) on loopback inside a throwaway
# user+network namespace, run cmd/moshprobe and summarise: median key latency
# and fraction of keys drawn underlined. Touches no host networking.
# Usage: moshprobe.sh <bin-dir> <out-dir> [delays...]
set -euo pipefail
BIN=$1; OUT=$2; shift 2
DELAYS=${*:-"5 10 12 14 15 16 18 20 25 30 35 38 40 42 45 50 60 75"}
mkdir -p "$OUT"
for d in $DELAYS; do
  unshare -rn bash -c "ip link set lo up; tc qdisc add dev lo root netem delay ${d}ms; exec timeout 60 $BIN/moshprobe -keys 25" > "$OUT/d$d.txt" 2>&1 || true
  awk -v d="$d" '!/^#/ && $2!="-" {n++; l[n]=$2; if ($3=="true") u++} END {asort(l); printf "oneway=%sms rtt=%sms keys=%d median_ms=%s instant(<%sms)=%d underlined=%d\n", d, 2*d, n, l[int((n+1)/2)], d, 0, u}' "$OUT/d$d.txt"
  awk -v d="$d" '!/^#/ && $2!="-" && $2 < d {i++} END {print "  keys faster than one-way delay (=predicted):", i+0}' "$OUT/d$d.txt"
done
