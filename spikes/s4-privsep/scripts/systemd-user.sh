#!/usr/bin/env bash
# Run the spike as unprivileged systemd --user transient units (prefix
# mosey-spike-), check the sandbox comes up, the session works end to end,
# and the cgroup cpu.max re-read path (Go updatemaxprocs) survives the KILL
# filter. Cleans up its units.
# usage: systemd-user.sh BIN WORKDIR
set -uo pipefail
BIN=$(realpath "$1"); W=$2; mkdir -p "$W"; W=$(realpath "$W")
U=mosey-spike-$$
cleanup() {
  systemctl --user stop "$U-srv.service" "$U-soak.service" 2>/dev/null
  systemctl --user reset-failed "$U-srv.service" "$U-soak.service" 2>/dev/null
}
trap cleanup EXIT

echo "== 1. server as a transient user service"
systemd-run --user --quiet --unit="$U-srv" --collect \
  -p StandardOutput=file:"$W/srv.out" -p StandardError=file:"$W/srv.err" \
  --setenv=MOSEY_SPIKE_SANDBOX=both "$BIN" server
for _ in $(seq 50); do grep -q CONNECT "$W/srv.out" 2>/dev/null && break; sleep 0.1; done
read -r _ _ PORT KEY <"$W/srv.out"
printf 'echo hello-from-$((6*7))\necho cgroup=$(cat /proc/self/cgroup)\nexit\n' | "$BIN" client "$PORT" "$KEY" 1500 >"$W/client.out"
sleep 0.5
cat "$W/srv.err"
grep -q hello-from-42 "$W/client.out" && echo "SYSTEMD SERVER OK" || { echo "SYSTEMD SERVER FAIL"; cat "$W/client.out"; }
grep -o 'cgroup=.*' "$W/client.out" | head -1
systemctl --user show "$U-srv.service" -p ActiveState -p Result 2>/dev/null

echo "== 2. soak with CPUQuota (cpu.max exists -> runtime keeps an fd and pread64s it)"
systemd-run --user --quiet --unit="$U-soak" --collect --wait \
  -p CPUQuota="${QUOTA:-200%}" -p StandardOutput=file:"$W/soak.out" -p StandardError=file:"$W/soak.err" \
  --setenv=MOSEY_SPIKE_SANDBOX=both --setenv=MOSEY_SPIKE_STRESS=${SOAK_SECS:-30} "$BIN" soak
echo "unit exit: $? (CPUQuota=${QUOTA:-200%})"
cat "$W/soak.err" "$W/soak.out"
