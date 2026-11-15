#!/usr/bin/env bash
# Evaluates the flake's outputs for every system CI does not build on: the
# package and dev shell for each system that has one, and the checks for
# each Linux one, down to their derivations, without building anything. CI
# builds x86_64-linux only, so this is what keeps an evaluation error on a
# Mac or on arm64 from landing unseen: nothing may rule macOS out (D22).
# The package exists only where nix/release.json does (flake.nix), so CI
# runs this after scripts/nix-local-release.sh has written one.
#
# usage: scripts/nix-eval-systems.sh     (from anywhere in the repository)
set -euo pipefail
unset CDPATH

cd "$(git rev-parse --show-toplevel)"

built=x86_64-linux
names() { nix eval --json ".#$1" --apply builtins.attrNames | jq -r '.[]'; }
mapfile -t packaged < <(names packages)
mapfile -t shells < <(names devShells)
mapfile -t checked < <(names checks)

for sys in "${packaged[@]}"; do
    [ "$sys" != "$built" ] || continue
    nix eval --raw ".#packages.$sys.mosey.drvPath" >/dev/null
    echo "$sys: package evaluates"
done
for sys in "${shells[@]}"; do
    [ "$sys" != "$built" ] || continue
    nix eval --raw ".#devShells.$sys.default.drvPath" >/dev/null
    echo "$sys: dev shell evaluates"
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
