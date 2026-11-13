#!/usr/bin/env bash
# A throwaway stock OpenSSH ssh-agent standing in for the client's local
# agent, holding only the spike's software user key. Never the live signer.
#
# usage: local-agent.sh DIR start [ssh-add constraint args...] | stop
set -euo pipefail
S=${1:?scratch dir}
case ${2:?start|stop} in
start)
  shift 2
  sock="$S/local-agent.sock"
  [ -f "$S/local-agent.pid" ] && kill "$(cat "$S/local-agent.pid")" 2>/dev/null || true
  rm -f "$sock"
  eval "$(ssh-agent -a "$sock" -s)" >/dev/null
  echo "$SSH_AGENT_PID" > "$S/local-agent.pid"
  SSH_AUTH_SOCK="$sock" ssh-add -q "$@" "$S/client/id_user"
  SSH_AUTH_SOCK="$sock" ssh-add -l
  ;;
stop)
  [ -f "$S/local-agent.pid" ] && kill "$(cat "$S/local-agent.pid")" 2>/dev/null || true
  rm -f "$S/local-agent.pid" "$S/local-agent.sock"
  ;;
esac
