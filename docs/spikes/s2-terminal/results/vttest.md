# vttest screen agreement

vttest 2.7 (20251205), one run of scripts/vttest-all.sh for every emulator. References: ghosttyd (libghostty direct), ghostty (libghostty via tuios' binding), tmux.

## All captured screens
| emulator | screens = ghosttyd | rows = ghosttyd | screens = tmux | rows = tmux |
|---|---|---|---|---|
| ghosttyd | 70/70 | 100.0% | 49/70 | 86.2% |
| ghostty | 69/70 | 99.9% | 49/70 | 86.2% |
| tuios | 57/70 | 91.6% | 57/70 | 90.1% |
| charm | 46/70 | 87.4% | 49/70 | 86.8% |
| xtermgo | 54/70 | 88.3% | 59/70 | 93.4% |
| cy | 48/70 | 86.2% | 60/70 | 93.9% |
| tmux | 49/70 | 86.2% | 70/70 | 100.0% |

Leave-one-out consensus of ghosttyd,tmux,xtermgo,cy (row-level plurality, ties to the first listed):

| emulator | screens = consensus | rows = consensus |
|---|---|---|
| ghosttyd | 51/70 | 87.1% |
| ghostty | 56/70 | 89.5% |
| tuios | 63/70 | 95.4% |
| charm | 52/70 | 90.7% |
| xtermgo | 61/70 | 95.0% |
| cy | 58/70 | 94.1% |
| tmux | 59/70 | 93.5% |

## Core screens: menus 1, 2, 4, 8, 11.5-11.7, without DECCOLM screens

DECCOLM screens, by what vttest sent: m1-02,m1-03,m1-04,m1-05,m2-03,m2-04,m2-05,m2-06,m4-03,m4-04,m4-05,m8-08,m8-09,m8-10,m8-11,m8-12,m8-13,m8-14,m8-15. Also left out: reports (6), VT52 (7), charsets (3).

(34 screens excluded: DECCOLM set in "" or prefix in "m6,m7,m3,m1-02,m1-03,m1-04,m1-05,m2-03,m2-04,m2-05,m2-06,m4-03,m4-04,m4-05,m8-08,m8-09,m8-10,m8-11,m8-12,m8-13,m8-14,m8-15")

| emulator | screens = ghosttyd | rows = ghosttyd | screens = ghostty | rows = ghostty | screens = tmux | rows = tmux |
|---|---|---|---|---|---|---|
| ghosttyd | 36/36 | 100.0% | 36/36 | 100.0% | 32/36 | 98.5% |
| ghostty | 36/36 | 100.0% | 36/36 | 100.0% | 32/36 | 98.5% |
| tuios | 36/36 | 100.0% | 36/36 | 100.0% | 32/36 | 98.5% |
| charm | 29/36 | 95.7% | 29/36 | 95.7% | 26/36 | 94.6% |
| xtermgo | 36/36 | 100.0% | 36/36 | 100.0% | 32/36 | 98.5% |
| cy | 31/36 | 97.5% | 31/36 | 97.5% | 31/36 | 98.1% |
| tmux | 32/36 | 98.5% | 32/36 | 98.5% | 36/36 | 100.0% |
ghosttyd vs tmux: m2-02
ghosttyd vs tmux: m2-11
ghosttyd vs tmux: m2-15
ghosttyd vs tmux: m4-06
ghostty vs tmux: m2-02
ghostty vs tmux: m2-11
ghostty vs tmux: m2-15
ghostty vs tmux: m4-06
tuios vs tmux: m2-02
tuios vs tmux: m2-11
tuios vs tmux: m2-15
tuios vs tmux: m4-06
charm vs ghosttyd: m1-01
charm vs ghosttyd: m2-07
charm vs ghosttyd: m2-09
charm vs ghosttyd: m2-15
charm vs ghosttyd: m8-02
charm vs ghosttyd: m8-03
charm vs ghosttyd: m8-04
charm vs ghostty: m1-01
charm vs ghostty: m2-07
charm vs ghostty: m2-09
charm vs ghostty: m2-15
charm vs ghostty: m8-02
charm vs ghostty: m8-03
charm vs ghostty: m8-04
charm vs tmux: m1-01
charm vs tmux: m2-02
charm vs tmux: m2-07
charm vs tmux: m2-09
charm vs tmux: m2-11
charm vs tmux: m2-15
charm vs tmux: m4-06
charm vs tmux: m8-02
charm vs tmux: m8-03
charm vs tmux: m8-04
xtermgo vs tmux: m2-02
xtermgo vs tmux: m2-11
xtermgo vs tmux: m2-15
xtermgo vs tmux: m4-06
cy vs ghosttyd: m1-01
cy vs ghosttyd: m2-15
cy vs ghosttyd: m4-06
cy vs ghosttyd: m8-03
cy vs ghosttyd: m8-04
cy vs ghostty: m1-01
cy vs ghostty: m2-15
cy vs ghostty: m4-06
cy vs ghostty: m8-03
cy vs ghostty: m8-04
cy vs tmux: m1-01
cy vs tmux: m2-02
cy vs tmux: m2-11
cy vs tmux: m8-03
cy vs tmux: m8-04
tmux vs ghosttyd: m2-02
tmux vs ghosttyd: m2-11
tmux vs ghosttyd: m2-15
tmux vs ghosttyd: m4-06
tmux vs ghostty: m2-02
tmux vs ghostty: m2-11
tmux vs ghostty: m2-15
tmux vs ghostty: m4-06

## DECCOLM screens only
(51 screens excluded: DECCOLM set in "" or prefix in "m6,m7,m3,00-menu,m1-01,m1-06,m1-07,m11.5-01,m11.5-02,m11.5-03,m11.6-01,m11.6-02,m11.6-03,m11.7-01,m11.7-02,m11.7-03,m2-01,m2-02,m2-07,m2-08,m2-09,m2-10,m2-11,m2-12,m2-13,m2-14,m2-15,m2-16,m3-01,m3-02,m4-01,m4-02,m4-06,m4-07,m6.3-01,m6.3-02,m6.3-03,m6.4-01,m6.4-02,m6.4-03,m6.5-01,m6.5-02,m6.5-03,m7-01,m7-02,m7-03,m7-04,m8-01,m8-02,m8-03,m8-04,m8-05,m8-06,m8-07")

| emulator | screens = ghosttyd | rows = ghosttyd | screens = tmux | rows = tmux |
|---|---|---|---|---|
| ghosttyd | 19/19 | 100.0% | 8/19 | 65.9% |
| ghostty | 19/19 | 100.0% | 8/19 | 65.9% |
| tuios | 9/19 | 71.2% | 15/19 | 80.3% |
| charm | 7/19 | 65.5% | 13/19 | 75.9% |
| xtermgo | 9/19 | 71.2% | 15/19 | 80.3% |
| cy | 8/19 | 68.2% | 16/19 | 82.7% |
| tmux | 8/19 | 65.9% | 19/19 | 100.0% |
ghosttyd vs tmux: m1-02
ghosttyd vs tmux: m1-03
ghosttyd vs tmux: m1-04
ghosttyd vs tmux: m2-03
ghosttyd vs tmux: m2-05
ghosttyd vs tmux: m4-05
ghosttyd vs tmux: m8-08
ghosttyd vs tmux: m8-09
ghosttyd vs tmux: m8-10
ghosttyd vs tmux: m8-11
ghosttyd vs tmux: m8-12
ghostty vs tmux: m1-02
ghostty vs tmux: m1-03
ghostty vs tmux: m1-04
ghostty vs tmux: m2-03
ghostty vs tmux: m2-05
ghostty vs tmux: m4-05
ghostty vs tmux: m8-08
ghostty vs tmux: m8-09
ghostty vs tmux: m8-10
ghostty vs tmux: m8-11
ghostty vs tmux: m8-12
tuios vs ghosttyd: m1-02
tuios vs ghosttyd: m1-03
tuios vs ghosttyd: m1-04
tuios vs ghosttyd: m2-03
tuios vs ghosttyd: m2-05
tuios vs ghosttyd: m8-08
tuios vs ghosttyd: m8-09
tuios vs ghosttyd: m8-10
tuios vs ghosttyd: m8-11
tuios vs ghosttyd: m8-12
tuios vs tmux: m1-02
tuios vs tmux: m1-03
tuios vs tmux: m1-04
tuios vs tmux: m4-05
charm vs ghosttyd: m1-02
charm vs ghosttyd: m1-03
charm vs ghosttyd: m1-04
charm vs ghosttyd: m1-05
charm vs ghosttyd: m2-03
charm vs ghosttyd: m2-05
charm vs ghosttyd: m4-05
charm vs ghosttyd: m8-08
charm vs ghosttyd: m8-09
charm vs ghosttyd: m8-10
charm vs ghosttyd: m8-11
charm vs ghosttyd: m8-12
charm vs tmux: m1-02
charm vs tmux: m1-03
charm vs tmux: m1-04
charm vs tmux: m1-05
charm vs tmux: m4-05
charm vs tmux: m8-09
xtermgo vs ghosttyd: m1-02
xtermgo vs ghosttyd: m1-03
xtermgo vs ghosttyd: m1-04
xtermgo vs ghosttyd: m2-03
xtermgo vs ghosttyd: m2-05
xtermgo vs ghosttyd: m8-08
xtermgo vs ghosttyd: m8-09
xtermgo vs ghosttyd: m8-10
xtermgo vs ghosttyd: m8-11
xtermgo vs ghosttyd: m8-12
xtermgo vs tmux: m1-02
xtermgo vs tmux: m1-03
xtermgo vs tmux: m1-04
xtermgo vs tmux: m4-05
cy vs ghosttyd: m1-02
cy vs ghosttyd: m1-03
cy vs ghosttyd: m1-04
cy vs ghosttyd: m2-03
cy vs ghosttyd: m2-05
cy vs ghosttyd: m4-05
cy vs ghosttyd: m8-08
cy vs ghosttyd: m8-09
cy vs ghosttyd: m8-10
cy vs ghosttyd: m8-11
cy vs ghosttyd: m8-12
cy vs tmux: m1-02
cy vs tmux: m1-03
cy vs tmux: m1-04
tmux vs ghosttyd: m1-02
tmux vs ghosttyd: m1-03
tmux vs ghosttyd: m1-04
tmux vs ghosttyd: m2-03
tmux vs ghosttyd: m2-05
tmux vs ghosttyd: m4-05
tmux vs ghosttyd: m8-08
tmux vs ghosttyd: m8-09
tmux vs ghosttyd: m8-10
tmux vs ghosttyd: m8-11
tmux vs ghosttyd: m8-12

## Attributes (SGR) on core screens
(34 screens excluded: DECCOLM set in "" or prefix in "m6,m7,m3,m1-02,m1-03,m1-04,m1-05,m2-03,m2-04,m2-05,m2-06,m4-03,m4-04,m4-05,m8-08,m8-09,m8-10,m8-11,m8-12,m8-13,m8-14,m8-15")

| emulator | screens = ghosttyd | rows = ghosttyd |
|---|---|---|
| ghosttyd | 36/36 | 100.0% |
| ghostty | 36/36 | 100.0% |
| tuios | 36/36 | 100.0% |
| charm | 36/36 | 100.0% |
| xtermgo | 36/36 | 100.0% |
| cy | 36/36 | 100.0% |

## Previous rule, for comparison: screens where tuios' libghostty binding had DECCOLM set at capture
(28 screens excluded: DECCOLM set in "ghostty" or prefix in "m6,m7,m3")

| emulator | screens = ghosttyd | rows = ghosttyd |
|---|---|---|
| ghosttyd | 42/42 | 100.0% |
| ghostty | 42/42 | 100.0% |
| tuios | 41/42 | 99.4% |
| charm | 32/42 | 93.8% |
| xtermgo | 41/42 | 99.4% |
| cy | 35/42 | 96.0% |
| tmux | 36/42 | 95.2% |
