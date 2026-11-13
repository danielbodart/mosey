#!/usr/bin/env bash
# Start the server from an sshd login, as D6 does (`ssh host mosey server`),
# using a THROWAWAY unprivileged sshd on 127.0.0.1 with its own host key and
# a throwaway user key. Never touches ~/.ssh, the agent, or the system sshd.
# usage: sshd-login.sh BIN WORKDIR
set -uo pipefail
BIN=$(realpath "$1"); W=$2; rm -rf "$W"; mkdir -p "$W"; W=$(realpath "$W")
PORT=$((20000 + RANDOM % 20000))
ssh-keygen -q -t ed25519 -N '' -f "$W/hostkey"
ssh-keygen -q -t ed25519 -N '' -f "$W/userkey"
cp "$W/userkey.pub" "$W/authorized_keys"
cat >"$W/sshd_config" <<EOF
Port $PORT
ListenAddress 127.0.0.1
HostKey $W/hostkey
AuthorizedKeysFile $W/authorized_keys
PidFile $W/sshd.pid
UsePAM no
StrictModes no
PasswordAuthentication no
KbdInteractiveAuthentication no
EOF
SSHD=$(readlink -f "$(command -v sshd)")
"$SSHD" -D -e -f "$W/sshd_config" 2>"$W/sshd.log" &
SSHDPID=$!
trap 'kill $SSHDPID 2>/dev/null; [ -f "$W/srv.pid" ] && kill "$(cat "$W/srv.pid")" 2>/dev/null' EXIT
sleep 0.5
SSH=(ssh -F /dev/null -i "$W/userkey" -o IdentitiesOnly=yes -o IdentityAgent=none
     -o UserKnownHostsFile="$W/known_hosts" -o StrictHostKeyChecking=accept-new
     -o BatchMode=yes -p "$PORT" 127.0.0.1)

echo "== remote environment as the server will see it"
"${SSH[@]}" 'echo "cgroup: $(cat /proc/self/cgroup)"; grep -E "Seccomp|NoNewPrivs" /proc/self/status | tr "\n" " "; echo; echo "XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-<unset>} SSH_CONNECTION=${SSH_CONNECTION:+set}"'

echo "== start the server detached from the ssh channel (as mosh-server does), read CONNECT"
"${SSH[@]}" "setsid -f env MOSEY_SPIKE_SANDBOX=both $BIN server >$W/srv.out 2>$W/srv.err </dev/null; sleep 0.5; cat $W/srv.out"
SPID=$(sed -n 's/.*session=\([0-9]*\).*/\1/p' "$W/srv.err"); echo "$SPID" >"$W/srv.pid"
read -r _ _ CPORT KEY <"$W/srv.out"
echo "ssh exited; server pid $SPID still alive: $(kill -0 "$SPID" 2>/dev/null && echo yes || echo no)"
printf 'echo hello-from-$((6*7))\nexit\n' | "$BIN" client "$CPORT" "$KEY" 1500 >"$W/client.out"
sleep 0.5
cat "$W/srv.err"
grep -q hello-from-42 "$W/client.out" && echo "SSHD LOGIN OK" || { echo "SSHD LOGIN FAIL"; cat "$W/client.out"; }

echo "== can the ssh login hand the server to the user manager? (systemd-run --user)"
"${SSH[@]}" "systemd-run --user --quiet --collect --unit=mosey-spike-from-ssh true 2>&1 && echo 'systemd-run --user: ok' || echo 'systemd-run --user: FAILED (exit '\$?')'"
"${SSH[@]}" "XDG_RUNTIME_DIR=/run/user/\$(id -u) systemd-run --user --quiet --collect --unit=mosey-spike-from-ssh2 true 2>&1 && echo 'with XDG_RUNTIME_DIR set: ok' || echo 'with XDG_RUNTIME_DIR set: FAILED'"
