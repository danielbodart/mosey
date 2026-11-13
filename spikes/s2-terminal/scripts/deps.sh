#!/usr/bin/env bash
# Non-stdlib packages each candidate pulls into a build, and the licence of
# every module they come from.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"
G="mise exec go@1.27.3 -- go"
for p in tuios.dev/vt github.com/charmbracelet/x/vt github.com/gitpod-io/xterm-go github.com/cfoust/cy/pkg/emu; do
  mods=$($G list -deps -f '{{if not .Standard}}{{with .Module}}{{.Path}}@{{.Version}}{{end}}{{end}}' "$p" 2>/dev/null | sort -u | grep -v '^$')
  pk=$($G list -deps -f '{{if not .Standard}}{{.ImportPath}}{{end}}' "$p" 2>/dev/null | grep -v '^$' | wc -l)
  echo "### $p  (non-std packages: $pk, modules: $(echo "$mods" | wc -l))"
  for m in $mods; do
    dir=$($G list -m -f '{{.Dir}}' "${m%@*}" 2>/dev/null)
    lic=$(ls "$dir" 2>/dev/null | grep -i -m1 '^licen[cs]e\|^copying')
    kind="?"
    if [ -n "$lic" ]; then
      head -c 2000 "$dir/$lic" | tr '\n' ' ' > /tmp/claude-1000/-home-dan-Projects-mosey/c1583940-2f8d-4ca9-afd0-7e8448d730af/scratchpad/s2-terminal/lic.txt
      case "$(cat /tmp/claude-1000/-home-dan-Projects-mosey/c1583940-2f8d-4ca9-afd0-7e8448d730af/scratchpad/s2-terminal/lic.txt)" in
        *"MIT License"*|*"Permission is hereby granted, free of charge"*) kind=MIT;;
        *"Apache License"*) kind=Apache-2.0;;
        *"Redistribution and use in source and binary forms"*) kind=BSD;;
        *"Mozilla Public License"*) kind=MPL-2.0;;
        *"GNU GENERAL PUBLIC"*) kind=GPL;;
        *"ISC License"*|*"Permission to use, copy, modify, and/or distribute"*) kind=ISC;;
        *) kind="other($lic)";;
      esac
    fi
    echo "  $m  $kind"
  done
done
echo "### libghostty-vt (C library via cgo): MIT (ghostty-org/ghostty), links libc only"
