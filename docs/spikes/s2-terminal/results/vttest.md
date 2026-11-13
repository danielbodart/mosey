# vttest screen agreement

## All captured screens
| emulator | screens = ghostty | rows = ghostty | screens = tmux | rows = tmux |
|---|---|---|---|---|
| ghostty | 71/71 | 100.0% | 47/70 | 83.8% |
| tuios | 54/71 | 87.7% | 57/70 | 90.1% |
| charm | 44/71 | 83.7% | 49/70 | 86.8% |
| xtermgo | 52/71 | 84.6% | 59/70 | 93.4% |
| cy | 46/71 | 82.5% | 60/70 | 93.9% |
| tmux | 47/71 | 82.5% | 70/70 | 100.0% |

Leave-one-out consensus of ghostty,tmux,xtermgo,cy (row-level plurality, ties to the first listed):

| emulator | screens = consensus | rows = consensus |
|---|---|---|
| ghostty | 49/70 | 84.7% |
| tuios | 63/71 | 93.9% |
| charm | 52/71 | 89.3% |
| xtermgo | 61/71 | 93.7% |
| cy | 58/71 | 92.7% |
| tmux | 59/71 | 92.1% |

## Core screens (menus 1, 2, 4, 8, 11.5-11.7; DECCOLM screens, reports (6), VT52 (7) and charsets (3) left out)
(29 screens excluded: DECCOLM set in "ghostty" or prefix in "m6,m7,m3")

| emulator | screens = ghostty | rows = ghostty | screens = tmux | rows = tmux |
|---|---|---|---|---|
| ghostty | 42/42 | 100.0% | 36/42 | 95.2% |
| tuios | 41/42 | 99.4% | 36/42 | 94.6% |
| charm | 32/42 | 93.8% | 29/42 | 90.3% |
| xtermgo | 41/42 | 99.4% | 36/42 | 94.6% |
| cy | 35/42 | 96.0% | 36/42 | 95.5% |
| tmux | 36/42 | 95.2% | 42/42 | 100.0% |

Leave-one-out consensus of ghostty,tmux,xtermgo,cy (row-level plurality, ties to the first listed):

| emulator | screens = consensus | rows = consensus |
|---|---|---|
| ghostty | 38/42 | 97.2% |
| tuios | 41/42 | 99.4% |
| charm | 32/42 | 93.8% |
| xtermgo | 38/42 | 97.2% |
| cy | 35/42 | 96.0% |
| tmux | 36/42 | 94.6% |
ghostty vs tmux: m1-03
ghostty vs tmux: m2-02
ghostty vs tmux: m2-11
ghostty vs tmux: m2-15
ghostty vs tmux: m4-05
ghostty vs tmux: m4-06
tuios vs ghostty: m1-03
tuios vs tmux: m1-03
tuios vs tmux: m2-02
tuios vs tmux: m2-11
tuios vs tmux: m2-15
tuios vs tmux: m4-05
tuios vs tmux: m4-06
charm vs ghostty: m1-01
charm vs ghostty: m1-03
charm vs ghostty: m1-05
charm vs ghostty: m2-07
charm vs ghostty: m2-09
charm vs ghostty: m2-15
charm vs ghostty: m4-05
charm vs ghostty: m8-02
charm vs ghostty: m8-03
charm vs ghostty: m8-04
charm vs tmux: m1-01
charm vs tmux: m1-03
charm vs tmux: m1-05
charm vs tmux: m2-02
charm vs tmux: m2-07
charm vs tmux: m2-09
charm vs tmux: m2-11
charm vs tmux: m2-15
charm vs tmux: m4-05
charm vs tmux: m4-06
charm vs tmux: m8-02
charm vs tmux: m8-03
charm vs tmux: m8-04
xtermgo vs ghostty: m1-03
xtermgo vs tmux: m1-03
xtermgo vs tmux: m2-02
xtermgo vs tmux: m2-11
xtermgo vs tmux: m2-15
xtermgo vs tmux: m4-05
xtermgo vs tmux: m4-06
cy vs ghostty: m1-01
cy vs ghostty: m1-03
cy vs ghostty: m2-15
cy vs ghostty: m4-05
cy vs ghostty: m4-06
cy vs ghostty: m8-03
cy vs ghostty: m8-04
cy vs tmux: m1-01
cy vs tmux: m1-03
cy vs tmux: m2-02
cy vs tmux: m2-11
cy vs tmux: m8-03
cy vs tmux: m8-04
tmux vs ghostty: m1-03
tmux vs ghostty: m2-02
tmux vs ghostty: m2-11
tmux vs ghostty: m2-15
tmux vs ghostty: m4-05
tmux vs ghostty: m4-06
ghostty vs consensus: m1-03
ghostty vs consensus: m2-15
ghostty vs consensus: m4-05
ghostty vs consensus: m4-06
tuios vs consensus: m1-03
charm vs consensus: m1-01
charm vs consensus: m1-03
charm vs consensus: m1-05
charm vs consensus: m2-07
charm vs consensus: m2-09
charm vs consensus: m2-15
charm vs consensus: m4-05
charm vs consensus: m8-02
charm vs consensus: m8-03
charm vs consensus: m8-04
xtermgo vs consensus: m1-03
xtermgo vs consensus: m2-15
xtermgo vs consensus: m4-05
xtermgo vs consensus: m4-06
cy vs consensus: m1-01
cy vs consensus: m1-03
cy vs consensus: m2-15
cy vs consensus: m4-05
cy vs consensus: m4-06
cy vs consensus: m8-03
cy vs consensus: m8-04
tmux vs consensus: m1-03
tmux vs consensus: m2-02
tmux vs consensus: m2-11
tmux vs consensus: m2-15
tmux vs consensus: m4-05
tmux vs consensus: m4-06

## Attributes (SGR) on core screens, against libghostty
(29 screens excluded: DECCOLM set in "ghostty" or prefix in "m6,m7,m3")

| emulator | screens = ghostty | rows = ghostty |
|---|---|---|
| ghostty | 42/42 | 100.0% |
| tuios | 42/42 | 100.0% |
| charm | 42/42 | 100.0% |
| xtermgo | 42/42 | 100.0% |
| cy | 42/42 | 100.0% |
