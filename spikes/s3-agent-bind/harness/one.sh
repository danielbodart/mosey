#!/usr/bin/env bash
# One moseyc run against the harness. SSH_AUTH_SOCK is the throwaway agent,
# so nothing reaches the live signer.
#
# usage: one.sh DIR HOST MODE OUT [moseyc flags...]
set -euo pipefail
S=${1:?dir}; HOST=${2:?host}; MODE=${3:?mode}; OUT=${4:?out}; shift 4
export SSH_AUTH_SOCK="$S/local-agent.sock"
B="$S/bin"
REMOTE_DIR="$S/r-$HOST-$MODE"
rm -rf "$REMOTE_DIR"
case $HOST in spikeA) HK="$S/A/host_ed25519.pub" ;; *) HK="$S/B/host_ed25519.pub" ;; esac
EXECS=$(printf '[["%s","sudo-sign","-hostkeys","%s","-listed","%s"],["%s","chain"]]' \
  "$B/moseys" "$HK" "$S/client/id_user.pub" "$B/moseys")
"$B/moseyc" -F "$S/client/ssh_config" -host "$HOST" -mode "$MODE" \
  -agent "${AGENT:-$SSH_AUTH_SOCK}" -remote "$B/moseys" -dir "$REMOTE_DIR" -capdir "$S/cap" \
  -exec "${EXECS_OVERRIDE:-$EXECS}" -out "$OUT" "$@"
for f in "$REMOTE_DIR"/exec-*.log; do echo "== $f"; cat "$f"; done
