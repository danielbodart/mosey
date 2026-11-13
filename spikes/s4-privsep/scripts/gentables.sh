#!/usr/bin/env bash
set -euo pipefail
X=/home/dan/go/pkg/mod/golang.org/x/sys@v0.50.0/unix
OUT=/home/dan/Projects/mosey/.claude/worktrees/wf_81ba60d9-5e8-4/spikes/s4-privsep/sandbox/sysnum_tables.go
{
echo '// Code generated from golang.org/x/sys@v0.50.0/unix/zsysnum_linux_{amd64,arm64}.go by the S4 spike; DO NOT EDIT.'
echo
echo 'package sandbox'
echo
for a in amd64 arm64; do
 echo "var sysnums_$a = map[string]uint32{"
 grep -E '^\s+SYS_[A-Z0-9_]+\s+= [0-9]+' "$X/zsysnum_linux_$a.go" | awk '{n=tolower(substr($1,5)); printf "\t\"%s\": %s,\n", n, $3}'
 echo "}"
 echo
done
} > "$OUT"
wc -l "$OUT"
