#!/usr/bin/env bash
# Every S3 experiment against the throwaway harness (two unprivileged sshds,
# a throwaway stock ssh-agent). Results land in DIR/results/*.json.
# Nothing here reads ~/.ssh or talks to the live quoin-signer: SSH_AUTH_SOCK
# and IdentityAgent both point at DIR/local-agent.sock.
#
# usage: run-all.sh DIR   (DIR must be short: unix socket paths <= 108 bytes)
set -uo pipefail
S=${1:?dir}
H=$(cd "$(dirname "$0")" && pwd)
R="$S/results"
mkdir -p "$R"
export SSH_AUTH_SOCK="$S/local-agent.sock"
one() { "$H/one.sh" "$S" "$@" 2>&1 | grep -E "moseyc:|SUDO|refused|chain.remote|EXIT|Permission|denied|error" ; }

"$H/stop-sshd.sh" "$S"; "$H/start-sshd.sh" "$S" >/dev/null
"$H/local-agent.sh" "$S" start >/dev/null

echo "### E1-E6: bind source per option, unconstrained stock agent"
one spikeA capture "$R/capture-A.json"
one spikeB-via-A capture "$R/capture-BviaA.json"
one spikeA xcrypto "$R/xcrypto-A.json"
one spikeB-via-A xcrypto "$R/xcrypto-BviaA.json"
one spikeA identity "$R/identity-A.json"
one spikeA none "$R/none-A.json"
echo "### E10: option (c) hop record after the bind, stock agent"
one spikeA capture "$R/capture-hop-A.json" -hop

echo "### E7: server forbids agent forwarding (AllowAgentForwarding no on B)"
"$H/stop-sshd.sh" "$S"; B_AGENT_FWD=no "$H/start-sshd.sh" "$S" >/dev/null
one spikeB capture "$R/capture-B-nofwd.json"
"$H/stop-sshd.sh" "$S"; "$H/start-sshd.sh" "$S" >/dev/null

echo "### E8: stock ssh-agent destination constraints (ssh-add -h spikeA -h 'spikeA>spikeB')"
"$H/local-agent.sh" "$S" start -H "$S/client/known_hosts" -h spikeA -h "spikeA>spikeB" >/dev/null
ONWARD=$(printf '[["ssh","-F","%s","spikeB","echo onward-login-ok"],["%s","sudo-sign","-hostkeys","%s","-listed","%s"]]' \
  "$S/client/onward_config" "$S/bin/moseys" "$S/A/host_ed25519.pub" "$S/client/id_user.pub")
for m in capture xcrypto identity none; do
  echo "-- $m"
  EXECS_OVERRIDE="$ONWARD" "$H/one.sh" "$S" spikeA "$m" "$R/constrained-$m-A.json" 2>&1 |
    grep -E "moseyc:|onward-login-ok|SUDO|refused|Permission denied|EXIT"
done
echo "-- control: the constrained agent used directly (origin), not through a session"
SSH_AUTH_SOCK="$S/local-agent.sock" ssh -F "$S/client/onward_config" spikeB echo direct-origin-to-B-ok 2>&1 | grep -E "ok|denied"
"$H/local-agent.sh" "$S" start >/dev/null

echo "### E9: bootstrap time, 20 runs each (ms), spikeA"
for m in capture none xcrypto; do
  ts=()
  for i in $(seq 20); do
    EXECS_OVERRIDE='[]' "$H/one.sh" "$S" spikeA "$m" "$R/t.json" >/dev/null 2>&1
    ts+=("$(python3 -c "import json;print(json.load(open('$R/t.json'))['bootstrap_ms'])")")
  done
  python3 - "$m" "${ts[@]}" <<'EOF'
import sys, statistics as st
m, xs = sys.argv[1], sorted(map(float, sys.argv[2:]))
print(f"{m:9s} n={len(xs)} median={st.median(xs):.1f} p10={xs[len(xs)//10]:.1f} p90={xs[9*len(xs)//10]:.1f} min={xs[0]:.1f} max={xs[-1]:.1f}")
EOF
done
rm -f "$R/t.json"
