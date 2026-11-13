# Real programs: replay of recorded output

References: ghosttyd (libghostty read directly, no tuios code) and ghostty (tuios' libghostty binding). The recordings were made with tuios' libghostty binding answering the programs' queries; every emulator replays the same bytes.

## Text, against ghosttyd
| emulator | screens = ghosttyd | rows = ghosttyd | screens = ghostty | rows = ghostty |
|---|---|---|---|---|
| ghosttyd | 42/42 | 100.0% | 42/42 | 100.0% |
| ghostty | 42/42 | 100.0% | 42/42 | 100.0% |
| tuios | 40/42 | 99.8% | 40/42 | 99.8% |
| charm | 29/42 | 84.8% | 29/42 | 84.8% |
| xtermgo | 33/42 | 96.0% | 33/42 | 96.0% |
| cy | 29/42 | 84.1% | 29/42 | 84.1% |
tuios vs ghosttyd: vim-insert
tuios vs ghosttyd: vim-resized
tuios vs ghostty: vim-insert
tuios vs ghostty: vim-resized
charm vs ghosttyd: claude-down
charm vs ghosttyd: claude-down2
charm vs ghosttyd: claude-start
charm vs ghosttyd: fish-color
charm vs ghosttyd: fish-echo
charm vs ghosttyd: fish-resized
charm vs ghosttyd: fish-typing
charm vs ghosttyd: unicode-back
charm vs ghosttyd: unicode-cat
charm vs ghosttyd: unicode-narrow
charm vs ghosttyd: vim-insert
charm vs ghosttyd: vim-resized
charm vs ghosttyd: zsh-narrow
charm vs ghostty: claude-down
charm vs ghostty: claude-down2
charm vs ghostty: claude-start
charm vs ghostty: fish-color
charm vs ghostty: fish-echo
charm vs ghostty: fish-resized
charm vs ghostty: fish-typing
charm vs ghostty: unicode-back
charm vs ghostty: unicode-cat
charm vs ghostty: unicode-narrow
charm vs ghostty: vim-insert
charm vs ghostty: vim-resized
charm vs ghostty: zsh-narrow
xtermgo vs ghosttyd: less-open
xtermgo vs ghosttyd: unicode-back
xtermgo vs ghosttyd: unicode-cat
xtermgo vs ghosttyd: unicode-narrow
xtermgo vs ghosttyd: vim-hscroll
xtermgo vs ghosttyd: vim-insert
xtermgo vs ghosttyd: vim-resized
xtermgo vs ghosttyd: vim-small
xtermgo vs ghosttyd: zsh-narrow
xtermgo vs ghostty: less-open
xtermgo vs ghostty: unicode-back
xtermgo vs ghostty: unicode-cat
xtermgo vs ghostty: unicode-narrow
xtermgo vs ghostty: vim-hscroll
xtermgo vs ghostty: vim-insert
xtermgo vs ghostty: vim-resized
xtermgo vs ghostty: vim-small
xtermgo vs ghostty: zsh-narrow
cy vs ghosttyd: fish-color
cy vs ghosttyd: fish-echo
cy vs ghosttyd: fish-resized
cy vs ghosttyd: fish-typing
cy vs ghosttyd: unicode-back
cy vs ghosttyd: unicode-cat
cy vs ghosttyd: unicode-narrow
cy vs ghosttyd: vim-hscroll
cy vs ghosttyd: vim-insert
cy vs ghosttyd: vim-resized
cy vs ghosttyd: vim-small
cy vs ghosttyd: zsh-echo
cy vs ghosttyd: zsh-osc
cy vs ghostty: fish-color
cy vs ghostty: fish-echo
cy vs ghostty: fish-resized
cy vs ghostty: fish-typing
cy vs ghostty: unicode-back
cy vs ghostty: unicode-cat
cy vs ghostty: unicode-narrow
cy vs ghostty: vim-hscroll
cy vs ghostty: vim-insert
cy vs ghostty: vim-resized
cy vs ghostty: vim-small
cy vs ghostty: zsh-echo
cy vs ghostty: zsh-osc

## Attributes and colours, against ghosttyd
| emulator | screens = ghosttyd | rows = ghosttyd | screens = ghostty | rows = ghostty |
|---|---|---|---|---|
| ghosttyd | 42/42 | 100.0% | 37/42 | 98.1% |
| ghostty | 37/42 | 98.1% | 42/42 | 100.0% |
| tuios | 40/42 | 99.7% | 35/42 | 97.8% |
| charm | 35/42 | 98.4% | 30/42 | 96.5% |
| xtermgo | 36/42 | 98.7% | 31/42 | 96.8% |
| cy | 25/42 | 94.7% | 25/42 | 94.7% |
ghosttyd vs ghostty: htop-open
ghosttyd vs ghostty: htop-resized
ghosttyd vs ghostty: htop-setup
ghosttyd vs ghostty: htop-tick
ghosttyd vs ghostty: htop-tree
ghostty vs ghosttyd: htop-open
ghostty vs ghosttyd: htop-resized
ghostty vs ghosttyd: htop-setup
ghostty vs ghosttyd: htop-tick
ghostty vs ghosttyd: htop-tree
tuios vs ghosttyd: vim-insert
tuios vs ghosttyd: vim-resized
tuios vs ghostty: htop-open
tuios vs ghostty: htop-resized
tuios vs ghostty: htop-setup
tuios vs ghostty: htop-tick
tuios vs ghostty: htop-tree
tuios vs ghostty: vim-insert
tuios vs ghostty: vim-resized
charm vs ghosttyd: claude-down
charm vs ghosttyd: claude-down2
charm vs ghosttyd: claude-start
charm vs ghosttyd: fish-color
charm vs ghosttyd: vim-insert
charm vs ghosttyd: vim-resized
charm vs ghosttyd: zsh-narrow
charm vs ghostty: claude-down
charm vs ghostty: claude-down2
charm vs ghostty: claude-start
charm vs ghostty: fish-color
charm vs ghostty: htop-open
charm vs ghostty: htop-resized
charm vs ghostty: htop-setup
charm vs ghostty: htop-tick
charm vs ghostty: htop-tree
charm vs ghostty: vim-insert
charm vs ghostty: vim-resized
charm vs ghostty: zsh-narrow
xtermgo vs ghosttyd: less-open
xtermgo vs ghosttyd: vim-hscroll
xtermgo vs ghosttyd: vim-insert
xtermgo vs ghosttyd: vim-resized
xtermgo vs ghosttyd: zsh-narrow
xtermgo vs ghosttyd: zsh-osc
xtermgo vs ghostty: htop-open
xtermgo vs ghostty: htop-resized
xtermgo vs ghostty: htop-setup
xtermgo vs ghostty: htop-tick
xtermgo vs ghostty: htop-tree
xtermgo vs ghostty: less-open
xtermgo vs ghostty: vim-hscroll
xtermgo vs ghostty: vim-insert
xtermgo vs ghostty: vim-resized
xtermgo vs ghostty: zsh-narrow
xtermgo vs ghostty: zsh-osc
cy vs ghosttyd: claude-down
cy vs ghosttyd: claude-down2
cy vs ghosttyd: claude-narrow
cy vs ghosttyd: claude-quit
cy vs ghosttyd: claude-resized
cy vs ghosttyd: claude-start
cy vs ghosttyd: fish-color
cy vs ghosttyd: htop-open
cy vs ghosttyd: htop-resized
cy vs ghosttyd: htop-setup
cy vs ghosttyd: htop-tick
cy vs ghosttyd: htop-tree
cy vs ghosttyd: vim-hscroll
cy vs ghosttyd: vim-insert
cy vs ghosttyd: vim-resized
cy vs ghosttyd: zsh-echo
cy vs ghosttyd: zsh-osc
cy vs ghostty: claude-down
cy vs ghostty: claude-down2
cy vs ghostty: claude-narrow
cy vs ghostty: claude-quit
cy vs ghostty: claude-resized
cy vs ghostty: claude-start
cy vs ghostty: fish-color
cy vs ghostty: htop-open
cy vs ghostty: htop-resized
cy vs ghostty: htop-setup
cy vs ghostty: htop-tick
cy vs ghostty: htop-tree
cy vs ghostty: vim-hscroll
cy vs ghostty: vim-insert
cy vs ghostty: vim-resized
cy vs ghostty: zsh-echo
cy vs ghostty: zsh-osc

## Pairwise: tuios against xtermgo (two independent pure-Go implementations, no libghostty)
| emulator | screens = xtermgo | rows = xtermgo |
|---|---|---|
| tuios | 33/42 | 96.0% |
| xtermgo | 42/42 | 100.0% |
| emulator | screens = xtermgo | rows = xtermgo |
|---|---|---|
| tuios | 36/42 | 98.7% |
| xtermgo | 42/42 | 100.0% |
