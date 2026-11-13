#!/usr/bin/env bash
# Every S3 experiment against the throwaway harness (two unprivileged sshds,
# a throwaway stock ssh-agent). Results land in DIR/results/*.json.
# Nothing here reads ~/.ssh or talks to the live quoin-signer: SSH_AUTH_SOCK
# and IdentityAgent both point at DIR/local-agent.sock.
#
# usage: run-all.sh DIR   (DIR must be short: unix socket paths <= 108 bytes)
# Build first: build.sh DIR
set -uo pipefail
S=${1:?dir}
H=$(cd "$(dirname "$0")" >/dev/null && pwd)
R="$S/results"
mkdir -p "$R"
export SSH_AUTH_SOCK="$S/local-agent.sock"
PAT="^  [0-9]+ |moseyc:|SUDO|refused|chain.remote|chain.zig|EXIT|Permission|denied|error|onward-login-ok|ok$"
one() { "$H/one.sh" "$S" "$@" 2>&1 | grep -E "$PAT" ; }
ONWARD=$(printf '[["ssh","-F","%s","spikeB","echo onward-login-ok"],["%s","sudo-sign","-hostkeys","%s","-listed","%s"]]' \
  "$S/client/onward_config" "$S/bin/mosey-server" "$S/A/host_ed25519.pub" "$S/client/id_user.pub")

echo "quoin worktree rev for quoin-chain: $(cat "$S/bin/quoin-rev")"
"$H/stop-sshd.sh" "$S"; "$H/start-sshd.sh" "$S" >/dev/null
"$H/local-agent.sh" "$S" start >/dev/null

echo "### E1-E6: bind source per option, unconstrained stock agent; server comm mosey-server"
one spikeA capture "$R/capture-A.json"
one spikeB-via-A capture "$R/capture-BviaA.json"
one spikeA xcrypto "$R/xcrypto-A.json"
one spikeB-via-A xcrypto "$R/xcrypto-BviaA.json"
one spikeA identity "$R/identity-A.json"
one spikeA none "$R/none-A.json"
echo "### E10: option (c) hop record after the bind, stock agent"
one spikeA capture "$R/capture-hop-A.json" -hop

echo "### E7: server forbids agent forwarding (AllowAgentForwarding no on B): session goes on, agent off"
"$H/stop-sshd.sh" "$S"; B_AGENT_FWD=no "$H/start-sshd.sh" "$S" >/dev/null
one spikeB capture "$R/capture-B-nofwd.json"
"$H/stop-sshd.sh" "$S"; "$H/start-sshd.sh" "$S" >/dev/null
echo "-- E7b: no bind, and a hostile server that opens agent channels anyway"
REMOTE_ARGS="-trigger=false -hostile-ignore-noagent" one spikeA capture "$R/capture-A-hostile-noagent.json"

echo "### E8: stock ssh-agent destination constraints (ssh-add -h spikeA -h 'spikeA>spikeB')"
"$H/local-agent.sh" "$S" start -H "$S/client/known_hosts" -h spikeA -h "spikeA>spikeB" >/dev/null
for m in capture xcrypto identity none; do
  echo "-- $m"
  EXECS_OVERRIDE="$ONWARD" one spikeA "$m" "$R/constrained-$m-A.json"
done
echo "-- control: the constrained agent used directly (origin), not through a session"
ssh -F "$S/client/onward_config" spikeB echo direct-origin-to-B-ok 2>&1 | grep -E "ok|denied"

echo "### E11: hostile server injects a session-bind for host X after ssh's own (ssh-add -h spikeA -h spikeX -h 'spikeX>spikeB': X may forward to B, A may not)"
"$H/local-agent.sh" "$S" start -H "$S/client/known_hosts" -h spikeA -h spikeX -h "spikeX>spikeB" >/dev/null
echo "-- control: plain ssh -A spikeA, then ssh spikeB from A (OpenSSH: chain spikeA>spikeB, not allowed)"
ssh -F "$S/client/ssh_config" -o ForwardAgent=yes -o ControlPath=none spikeA \
  "ssh -F $S/client/onward_config spikeB echo onward-login-ok" 2>&1 | grep -E "onward-login-ok|denied"
echo "-- legacy capture (first prototype: last bind wins)"
EXECS_OVERRIDE="$ONWARD" REMOTE_ARGS="-hostile-bind-key $S/X/host_ed25519" \
  one spikeA capture "$R/hostile-legacy-A.json" -legacy-capture
echo "-- strict capture (this revision)"
EXECS_OVERRIDE="$ONWARD" REMOTE_ARGS="-hostile-bind-key $S/X/host_ed25519" \
  one spikeA capture "$R/hostile-strict-A.json"
"$H/local-agent.sh" "$S" start >/dev/null

echo "### E12: ControlMaster auto + ControlPersist, with a live master"
ssh -F "$S/client/ssh_config" -o ForwardAgent=no -fN spikeA-cm
ssh -F "$S/client/ssh_config" -O check spikeA-cm 2>&1
echo "-- -allow-mux (the first prototype's behaviour: bootstrap rides the master)"
one spikeA-cm capture "$R/cm-allowmux-A.json" -allow-mux
echo "-- default (ControlMaster=no, ControlPath=none for the bootstrap)"
one spikeA-cm capture "$R/cm-A.json"
echo "-- what the forced fresh connection costs: 'ssh spikeA-cm true', 10 runs each, ms"
for how in mux fresh; do
  ts=()
  for i in $(seq 10); do
    o=(); [ $how = fresh ] && o=(-o ControlMaster=no -o ControlPath=none)
    t0=$(date +%s%N); ssh -F "$S/client/ssh_config" "${o[@]}" spikeA-cm true; t1=$(date +%s%N)
    ts+=("$(( (t1 - t0) / 1000 ))")
  done
  python3 -c "import sys,statistics as s;x=sorted(int(v)/1000 for v in sys.argv[2:]);print(f'{sys.argv[1]:6s} n={len(x)} median={s.median(x):.1f} min={x[0]:.1f} max={x[-1]:.1f}')" $how "${ts[@]}"
done
ssh -F "$S/client/ssh_config" -O exit spikeA-cm 2>&1
echo "-- E12b: a master that itself forwards the user's agent (ForwardAgent=yes): with -allow-mux the"
echo "   bootstrap's trigger reaches the user's real agent (agent=triggered-*), never the capture socket"
ssh -F "$S/client/ssh_config" -o ForwardAgent=yes -fN spikeA-cm
one spikeA-cm capture "$R/cm-allowmux-fwdmaster-A.json" -allow-mux
one spikeA-cm capture "$R/cm-fwdmaster-A.json"
ssh -F "$S/client/ssh_config" -O exit spikeA-cm 2>&1

echo "### E13: ProxyCommand ssh -W (B via A)"
one spikeB-pc capture "$R/capture-BviaPC.json"
