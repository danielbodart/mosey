#!/usr/bin/env bash
# Bootstrap wall time per option, interleaved (capture, none, xcrypto in
# turn each round) so machine load drifts across all three alike. Loopback
# only: it measures local cost, not a WAN round trip.
#
# usage: timing.sh DIR ROUNDS
set -uo pipefail
S=${1:?dir}; N=${2:-30}
H=$(cd "$(dirname "$0")" >/dev/null && pwd)
R="$S/results"
export SSH_AUTH_SOCK="$S/local-agent.sock"
: > "$R/timing.tsv"
for i in $(seq "$N"); do
  for m in capture none xcrypto; do
    EXECS_OVERRIDE='[]' "$H/one.sh" "$S" spikeA "$m" "$R/t.json" >/dev/null 2>&1
    python3 -c "import json,sys;r=json.load(open('$R/t.json'));print(sys.argv[1], r['bootstrap_ms'], r['agent_state'])" "$m" >> "$R/timing.tsv"
  done
done
rm -f "$R/t.json"
python3 - "$R/timing.tsv" <<'EOF'
import sys, statistics as st, collections
d = collections.defaultdict(list); trig = []
for l in open(sys.argv[1]):
    m, ms, state = l.split()
    d[m].append(float(ms))
    if state.startswith("triggered-"):
        trig.append(int(state[len("triggered-"):-2]) / 1000)
for m, xs in d.items():
    xs.sort()
    print(f"{m:8s} n={len(xs)} median={st.median(xs):.1f}ms p10={xs[len(xs)//10]:.1f} p90={xs[9*len(xs)//10]:.1f}")
trig.sort()
print(f"trigger (server-side agent round trip, inside capture): n={len(trig)} median={st.median(trig):.2f}ms max={trig[-1]:.2f}ms")
EOF
