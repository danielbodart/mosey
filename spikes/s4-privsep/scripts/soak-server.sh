#!/usr/bin/env bash
# Soak the REAL multi-process server (review response; the first soaks used
# a single-process stand-in with NetPolicy). Sandboxed roles run the
# production policies under SECCOMP_RET_KILL_PROCESS and churn the Go
# runtime for SECS while client-load drives traffic through every hop.
#   MODE=shell    plain child of this shell, with GOMAXPROCS churn
#   MODE=systemd  systemd --user transient unit with CPUQuota=$QUOTA and NO
#                 GOMAXPROCS calls, so Go's updatemaxprocs keeps re-reading
#                 cgroup cpu.max (pread64) for the whole run
# Pass: client-load saw output in every 10 s window, and no sandboxed
# process died (no CHILD-EXIT / SUPERVISOR line before the end).
# usage: soak-server.sh MODE LAYOUT SECS BIN OUTDIR
set -uo pipefail
MODE=$1 L=$2 SECS=$3; BIN=$(realpath "$4"); W=$5; mkdir -p "$W"; W=$(realpath "$W")
QUOTA=${QUOTA:-200%}
P="$W/$MODE-$L"
U=mosey-spike-soak-$MODE-$L-$$
echo "cmd: $0 $*  QUOTA=$QUOTA  start=$(date -Is)  kernel=$(uname -r)" >"$P.log"
if [ "$MODE" = systemd ]; then
  trap 'systemctl --user stop "$U.service" 2>/dev/null; systemctl --user reset-failed "$U.service" 2>/dev/null' EXIT
  systemd-run --user --quiet --unit="$U" --collect -p CPUQuota="$QUOTA" \
    -p StandardOutput=file:"$P.out" -p StandardError=file:"$P.err" \
    --setenv=MOSEY_SPIKE_LAYOUT="$L" --setenv=MOSEY_SPIKE_SANDBOX=both \
    --setenv=MOSEY_SPIKE_SECCOMP_ACTION=kill --setenv=MOSEY_SPIKE_STRESS="$SECS" "$BIN" server
  sleep 1
  CG=$(systemctl --user show -p ControlGroup --value "$U.service")
  echo "unit=$U cgroup=$CG cpu.max=$(cat /sys/fs/cgroup$CG/cpu.max)" >>"$P.log"
else
  MOSEY_SPIKE_LAYOUT=$L MOSEY_SPIKE_SANDBOX=both MOSEY_SPIKE_SECCOMP_ACTION=kill \
    MOSEY_SPIKE_STRESS=$SECS MOSEY_SPIKE_STRESS_GOMAXPROCS=1 "$BIN" server >"$P.out" 2>"$P.err" &
  SPID=$!
fi
for _ in $(seq 50); do grep -q CONNECT "$P.out" 2>/dev/null && break; sleep 0.1; done
read -r _ _ PORT KEY <"$P.out"
"$BIN" client-load "$PORT" "$KEY" "$SECS" >>"$P.log" 2>&1; echo "client-load exit=$?" >>"$P.log"
sleep 2
[ "$MODE" = shell ] && { kill "$SPID" 2>/dev/null; wait "$SPID" 2>/dev/null; }
grep -vE '^\[.*pre-sandbox' "$P.err" >>"$P.log"
DIED=$(grep -cE 'bad system call|SUPERVISOR' "$P.err")
echo "end=$(date -Is) sandboxed-process deaths/respawns: $DIED" >>"$P.log"
