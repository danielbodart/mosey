#!/usr/bin/env bash
# Regenerate the score tables in docs/spikes/s2-terminal/results from a
# vttest-all.sh run and an apps.sh run.
#
# References (after the S2 review): "ghosttyd" is libghostty-vt read directly
# through go.mitchellh.com/libghostty, with no tuios.dev/vt code in the path;
# "ghostty" is tuios' own libghostty binding (kept for comparison; it has the
# background-colour-erase bug); tmux is a third, independent implementation.
# DECCOLM screens are chosen from what vttest sent (scripts/deccolm-screens.py),
# not from any emulator's state.
# usage: score.sh <bin-dir> <vttest-out> <apps-out>
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$1"; VT="$2"; APPS="$3"
R="$HERE/../../docs/spikes/s2-terminal/results"
mkdir -p "$R"
E=ghosttyd,ghostty,tuios,charm,xtermgo,cy,tmux
X=$(python3 -I "$HERE/scripts/deccolm-screens.py" "$VT" ghosttyd)
ALL=$(ls "$VT/ghosttyd" | grep '\.txt$' | sed 's/\.txt$//' | grep -v -x -F -f <(echo "$X" | tr , '\n') | tr '\n' , | sed 's/,$//')
{
  echo "# vttest screen agreement"
  echo
  echo "vttest 2.7 (20251205), one run of scripts/vttest-all.sh for every emulator. References: ghosttyd (libghostty direct), ghostty (libghostty via tuios' binding), tmux."
  echo
  echo "## All captured screens"
  "$BIN/vtcompare" -dir "$VT" -refs ghosttyd,tmux -emus $E -consensus ghosttyd,tmux,xtermgo,cy
  echo
  echo "## Core screens: menus 1, 2, 4, 8, 11.5-11.7, without DECCOLM screens"
  echo
  echo "DECCOLM screens, by what vttest sent: $X. Also left out: reports (6), VT52 (7), charsets (3)."
  echo
  "$BIN/vtcompare" -dir "$VT" -refs ghosttyd,ghostty,tmux -emus $E -exclude "m6,m7,m3,$X" -v
  echo
  echo "## DECCOLM screens only"
  "$BIN/vtcompare" -dir "$VT" -refs ghosttyd,tmux -emus $E -exclude "m6,m7,m3,$ALL" -v
  echo
  echo "## Attributes (SGR) on core screens"
  "$BIN/vtcompare" -dir "$VT" -emus ghosttyd,ghostty,tuios,charm,xtermgo,cy -refs ghosttyd -ext .attr -exclude "m6,m7,m3,$X"
  echo
  echo "## Previous rule, for comparison: screens where tuios' libghostty binding had DECCOLM set at capture"
  "$BIN/vtcompare" -dir "$VT" -refs ghosttyd -emus $E -exclude m6,m7,m3 -skip-deccolm ghostty
} > "$R/vttest.md"
{
  echo "# Real programs: replay of recorded output"
  echo
  echo "References: ghosttyd (libghostty read directly, no tuios code) and ghostty (tuios' libghostty binding). The recordings were made with tuios' libghostty binding answering the programs' queries; every emulator replays the same bytes."
  echo
  echo "## Text, against ghosttyd"
  "$BIN/vtcompare" -dir "$APPS/replay" -refs ghosttyd,ghostty -emus ghosttyd,ghostty,tuios,charm,xtermgo,cy -v
  echo
  echo "## Attributes and colours, against ghosttyd"
  "$BIN/vtcompare" -dir "$APPS/replay" -refs ghosttyd,ghostty -emus ghosttyd,ghostty,tuios,charm,xtermgo,cy -ext .attr -v
  echo
  echo "## Pairwise: tuios against xtermgo (two independent pure-Go implementations, no libghostty)"
  "$BIN/vtcompare" -dir "$APPS/replay" -refs xtermgo -emus tuios,xtermgo
  "$BIN/vtcompare" -dir "$APPS/replay" -refs xtermgo -emus tuios,xtermgo -ext .attr
} > "$R/apps.md"
echo "wrote $R/vttest.md $R/apps.md"
