#!/usr/bin/env bash
# Counterfactuals behind claims in FINDINGS (review response: commit the
# raw evidence). All runs are systemd --user transient units named
# mosey-spike-cf-*, with CPUQuota so cgroup cpu.max exists.
#  1. pread64 dropped from the policy (KILL): how long the network process
#     lives, and what the supervisor does about a crash loop.
#  2. the same with PR_SET_DUMPABLE left at 1 vs set to 0: does the SIGSYS
#     produce a core dump (of a process that may hold keys)?
# usage: counterfactuals.sh BIN OUTDIR
set -uo pipefail
BIN=$(realpath "$1"); W=$2; rm -rf "$W"; mkdir -p "$W"; W=$(realpath "$W")
run() { # name secs env...
  local n=$1 s=$2; shift 2
  local U=mosey-spike-cf-$n-$$
  local sets=(); for e in "$@"; do sets+=(--setenv="$e"); done
  echo "== $n: systemd-run --user -p CPUQuota=200% ${sets[*]} $BIN server   (for ${s}s)"
  systemd-run --user --quiet --unit="$U" --collect -p CPUQuota=200% \
    -p StandardOutput=file:"$W/$n.out" -p StandardError=file:"$W/$n.err" \
    --setenv=MOSEY_SPIKE_LAYOUT=B2 --setenv=MOSEY_SPIKE_SANDBOX=both --setenv=MOSEY_SPIKE_SECCOMP_ACTION=kill \
    "${sets[@]}" "$BIN" server
  sleep "$s"
  systemctl --user stop "$U.service" 2>/dev/null; systemctl --user reset-failed "$U.service" 2>/dev/null
  grep -E "policy: dropped|seccomp:|CHILD-EXIT|SUPERVISOR" "$W/$n.err" | head -30
}
SINCE=$(date '+%Y-%m-%d %H:%M:%S')
run pread64-dumpable0 75 MOSEY_SPIKE_DROP=pread64 MOSEY_SPIKE_DUMPABLE=0
sleep 2
echo "== coredumps of $BIN since $SINCE (DUMPABLE=0 run):"
coredumpctl list --no-pager --since="$SINCE" "$BIN" 2>&1 | tail -n +1
SINCE2=$(date '+%Y-%m-%d %H:%M:%S')
run pread64-dumpable1 75 MOSEY_SPIKE_DROP=pread64 MOSEY_SPIKE_DUMPABLE=1
sleep 3
echo "== coredumps of $BIN since $SINCE2 (DUMPABLE=1 run):"
coredumpctl list --no-pager --since="$SINCE2" "$BIN" 2>&1 | tail -n +1
echo "== 3. busy runtime: pread64 dropped, net churning the runtime (MOSEY_SPIKE_STRESS=60)"
run pread64-busy 20 MOSEY_SPIKE_DROP=pread64 MOSEY_SPIKE_STRESS=60
echo "== control: full policy, 20s"
run control 20
