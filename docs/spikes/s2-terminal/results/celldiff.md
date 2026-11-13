# Structured cell diffs (celldiff prototype)

Machine: dan-desktop, 24 CPUs, 12th Gen Intel(R) Core(TM) i9-12900K, 2026-11-13T19:01:12Z, load average at start: 12.71 30.15 36.91 (other spikes share this machine)

emulator tuios, frame every 1024 bytes

| stream | raw bytes | frames | diff bytes | diff/raw | deflated diffs | mean diff | p99 snapshot+diff | mean snapshot+diff |
|---|---|---|---|---|---|---|---|---|
| claude | 6021 | 10 | 7896 | 1.31 | 2543 | 789 B | 256µs | 136µs |
| fish | 2646 | 8 | 1438 | 0.54 | 763 | 179 B | 179µs | 127µs |
| htop | 34849 | 39 | 48139 | 1.38 | 13383 | 1234 B | 329µs | 238µs |
| less | 8908 | 15 | 9945 | 1.12 | 4070 | 663 B | 322µs | 188µs |
| synth-seq100k | 688895 | 674 | 199877 | 0.29 | 69115 | 296 B | 143µs | 109µs |
| synth-top200x60 | 3252000 | 3177 | 1629772 | 0.50 | 446253 | 512 B | 890µs | 612µs |
| unicode | 1073 | 3 | 1684 | 1.57 | 1003 | 561 B | 95µs | 92µs |
| vim | 14865 | 19 | 19299 | 1.30 | 7580 | 1015 B | 164µs | 104µs |
| zsh | 23259 | 29 | 16652 | 0.72 | 6713 | 574 B | 152µs | 122µs |

emulator ghostty, frame every 1024 bytes

| stream | raw bytes | frames | diff bytes | diff/raw | deflated diffs | mean diff | p99 snapshot+diff | mean snapshot+diff |
|---|---|---|---|---|---|---|---|---|
| claude | 6021 | 10 | 7896 | 1.31 | 2543 | 789 B | 484µs | 227µs |
| fish | 2646 | 8 | 1438 | 0.54 | 763 | 179 B | 310µs | 177µs |
| htop | 34849 | 39 | 47830 | 1.37 | 13334 | 1226 B | 665µs | 374µs |
| less | 8908 | 15 | 9945 | 1.12 | 4070 | 663 B | 454µs | 247µs |
| synth-seq100k | 688895 | 674 | 199877 | 0.29 | 69115 | 296 B | 221µs | 172µs |
| synth-top200x60 | 3252000 | 3177 | 1629772 | 0.50 | 446253 | 512 B | 1.234ms | 850µs |
| unicode | 1073 | 3 | 1684 | 1.57 | 1004 | 561 B | 271µs | 229µs |
| vim | 14865 | 19 | 19357 | 1.30 | 7619 | 1018 B | 427µs | 260µs |
| zsh | 23259 | 29 | 16652 | 0.72 | 6713 | 574 B | 357µs | 194µs |

