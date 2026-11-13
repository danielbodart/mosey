#!/usr/bin/env bash
# Two unprivileged OpenSSH sshd instances on 127.0.0.1 (hosts "A" and "B"),
# each with a throwaway ed25519 host key, plus a client ssh_config with a
# ProxyJump entry (B via A). Nothing here touches ~/.ssh or the system sshd.
#
# usage: start-sshd.sh DIR        (DIR is created; stop with stop-sshd.sh DIR)
set -euo pipefail
S=${1:?scratch dir}
mkdir -p "$S/A" "$S/B" "$S/client"
SSHD=$(readlink -f "$(command -v sshd)")

[ -f "$S/A/host_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -f "$S/A/host_ed25519" -C hostA
[ -f "$S/B/host_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -f "$S/B/host_ed25519" -C hostB
# X is a host the hostile server can mint a session-bind for (it stands for
# any sshd the server can reach: the host key signs the session id before
# authentication). Only its key is used; no sshd runs for it.
[ -f "$S/X/host_ed25519" ] || { mkdir -p "$S/X"; ssh-keygen -q -t ed25519 -N '' -f "$S/X/host_ed25519" -C hostX; }
[ -f "$S/client/id_user" ] || ssh-keygen -q -t ed25519 -N '' -f "$S/client/id_user" -C user@spike

write_sshd_config() {
  local h=$1 port=$2 fwd=$3
  cat > "$S/$h/sshd_config" <<EOF
Port $port
ListenAddress 127.0.0.1
HostKey $S/$h/host_ed25519
PidFile $S/$h/sshd.pid
AuthorizedKeysFile $S/client/id_user.pub
PasswordAuthentication no
KbdInteractiveAuthentication no
StrictModes no
AllowAgentForwarding $fwd
AllowTcpForwarding yes
UsePAM no
LogLevel VERBOSE
PerSourcePenalties no
SetEnv MOSEY_SPIKE_HOST=$h
EOF
}
write_sshd_config A 22221 "${A_AGENT_FWD:-yes}"
write_sshd_config B 22222 "${B_AGENT_FWD:-yes}"

cat > "$S/client/ssh_config" <<EOF
Host spikeA
  HostName 127.0.0.1
  Port 22221
  HostKeyAlias spikeA
Host spikeB
  HostName 127.0.0.1
  Port 22222
  HostKeyAlias spikeB
Host spikeB-via-A
  HostName 127.0.0.1
  Port 22222
  HostKeyAlias spikeB
  ProxyJump spikeA
Host spikeB-pc
  HostName 127.0.0.1
  Port 22222
  HostKeyAlias spikeB
  ProxyCommand ssh -F $S/client/ssh_config -W %h:%p spikeA
Host spikeA-cm
  HostName 127.0.0.1
  Port 22221
  HostKeyAlias spikeA
  ControlMaster auto
  ControlPath $S/cm-%C
  ControlPersist 60
Host *
  User $(id -un)
  IdentityFile $S/client/id_user
  IdentitiesOnly yes
  IdentityAgent $S/local-agent.sock
  UserKnownHostsFile $S/client/known_hosts
  StrictHostKeyChecking yes
  BatchMode yes
EOF
# The onward login made from inside a session: agent only (the IdentityFile
# is the public half, so ssh can only sign through SSH_AUTH_SOCK).
mkdir -p "$S/pubonly"
cp "$S/client/id_user.pub" "$S/pubonly/id_user.pub"
chmod 600 "$S/pubonly/id_user.pub"
cat > "$S/client/onward_config" <<EOF
Host spikeB
  HostName 127.0.0.1
  Port 22222
  HostKeyAlias spikeB
  User $(id -un)
  IdentityFile $S/pubonly/id_user.pub
  IdentitiesOnly yes
  IdentityAgent SSH_AUTH_SOCK
  UserKnownHostsFile $S/client/known_hosts
  StrictHostKeyChecking yes
  BatchMode yes
EOF
{
  echo "spikeA $(cat "$S/A/host_ed25519.pub")"
  echo "spikeB $(cat "$S/B/host_ed25519.pub")"
  echo "spikeX $(cat "$S/X/host_ed25519.pub")"
} > "$S/client/known_hosts"

"$SSHD" -f "$S/A/sshd_config" -E "$S/A/sshd.log"
"$SSHD" -f "$S/B/sshd_config" -E "$S/B/sshd.log"
echo "sshd A on 22221, B on 22222; client config $S/client/ssh_config"
