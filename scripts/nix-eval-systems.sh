#!/usr/bin/env bash
# Evaluates the flake's outputs for every system CI does not build on: the
# package and dev shell for each, and the checks for each Linux one, down
# to their derivations, without building anything. CI builds x86_64-linux
# only, so this is what keeps an evaluation error on a Mac or on arm64 (the
# linux-only GOEXPERIMENT branch, say) from landing unseen: nothing may
# rule macOS out (D22). A vendoring or compile failure there would still
# need a build on that system.
#
# usage: scripts/nix-eval-systems.sh     (from anywhere in the repository)
set -euo pipefail
unset CDPATH

cd "$(git rev-parse --show-toplevel)"

built=x86_64-linux
mapfile -t systems < <(nix eval --json .#packages --apply builtins.attrNames | jq -r '.[]')
mapfile -t checked < <(nix eval --json .#checks --apply builtins.attrNames | jq -r '.[]')

for sys in "${systems[@]}"; do
    [ "$sys" != "$built" ] || continue
    nix eval --raw ".#packages.$sys.mosey.drvPath" >/dev/null
    nix eval --raw ".#devShells.$sys.default.drvPath" >/dev/null
    echo "$sys: package and dev shell evaluate"
done
for sys in "${checked[@]}"; do
    [ "$sys" != "$built" ] || continue
    # Not the VM test: it reads its throwaway keys at evaluation time from a
    # derivation built for $sys (tests/install.nix), so it can only be
    # evaluated on that system.
    nix eval --json ".#checks.$sys" \
        --apply 'cs: builtins.mapAttrs (_: c: c.drvPath) (removeAttrs cs [ "vm-install" ])' >/dev/null
    echo "$sys: checks but vm-install evaluate"
done
