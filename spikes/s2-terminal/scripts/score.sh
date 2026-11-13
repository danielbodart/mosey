#!/usr/bin/env bash
# Regenerate the score tables in docs/spikes/s2-terminal/results from a
# vttest-all.sh run and an apps.sh run.
# usage: score.sh <bin-dir> <vttest-out> <apps-out>
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$1"; VT="$2"; APPS="$3"
R="$HERE/../../docs/spikes/s2-terminal/results"
mkdir -p "$R"
E=ghostty,tuios,charm,xtermgo,cy,tmux
{
  echo "# vttest screen agreement"
  echo
  echo "## All captured screens"
  "$BIN/vtcompare" -dir "$VT" -emus $E -consensus ghostty,tmux,xtermgo,cy
  echo
  echo "## Core screens (menus 1, 2, 4, 8, 11.5-11.7; DECCOLM screens, reports (6), VT52 (7) and charsets (3) left out)"
  "$BIN/vtcompare" -dir "$VT" -emus $E -consensus ghostty,tmux,xtermgo,cy -skip-deccolm ghostty -exclude m6,m7,m3 -v
  echo
  echo "## Attributes (SGR) on core screens, against libghostty"
  "$BIN/vtcompare" -dir "$VT" -emus ghostty,tuios,charm,xtermgo,cy -refs ghostty -ext .attr -skip-deccolm ghostty -exclude m6,m7,m3
} > "$R/vttest.md"
{
  echo "# Real programs: replay of recorded output, against libghostty"
  echo
  echo "## Text"
  "$BIN/vtcompare" -dir "$APPS/replay" -refs ghostty -emus ghostty,tuios,charm,xtermgo,cy -v
  echo
  echo "## Attributes and colours"
  "$BIN/vtcompare" -dir "$APPS/replay" -refs ghostty -emus ghostty,tuios,charm,xtermgo,cy -ext .attr -v
} > "$R/apps.md"
echo "wrote $R/vttest.md $R/apps.md"
