# Structured cell diffs (celldiff prototype, hardened after the review)

Diff bytes are deterministic; timings are from 3 runs (each table is one run).

Run 1: Machine: dan-desktop, 24 CPUs, 12th Gen Intel(R) Core(TM) i9-12900K, 2026-11-13T19:52:31Z, load average: 1.53 4.78 12.22 (other spikes share this machine)

emulator tuios, frame every 1024 bytes

| stream | raw bytes | frames | diff bytes | diff/raw | deflated diffs | mean diff | p99 snapshot+diff | mean snapshot+diff |
|---|---|---|---|---|---|---|---|---|
| claude | 6021 | 10 | 7896 | 1.31 | 2543 | 789 B | 353µs | 160µs |
| fish | 2646 | 8 | 1438 | 0.54 | 763 | 179 B | 191µs | 138µs |
| htop | 34849 | 39 | 48139 | 1.38 | 13383 | 1234 B | 484µs | 229µs |
| less | 8908 | 15 | 9945 | 1.12 | 4070 | 663 B | 271µs | 142µs |
| synth-seq100k | 688895 | 674 | 199877 | 0.29 | 69115 | 296 B | 185µs | 113µs |
| synth-top200x60 | 3252000 | 3177 | 1629772 | 0.50 | 446253 | 512 B | 942µs | 579µs |
| unicode | 1073 | 3 | 1684 | 1.57 | 1003 | 561 B | 141µs | 122µs |
| vim | 14865 | 19 | 19299 | 1.30 | 7580 | 1015 B | 229µs | 148µs |
| zsh | 23259 | 29 | 16652 | 0.72 | 6713 | 574 B | 207µs | 98µs |

Run 1: Machine: dan-desktop, 24 CPUs, 12th Gen Intel(R) Core(TM) i9-12900K, 2026-11-13T19:52:33Z, load average: 1.65 4.75 12.17 (other spikes share this machine)

emulator ghostty, frame every 1024 bytes

| stream | raw bytes | frames | diff bytes | diff/raw | deflated diffs | mean diff | p99 snapshot+diff | mean snapshot+diff |
|---|---|---|---|---|---|---|---|---|
| claude | 6021 | 10 | 7896 | 1.31 | 2543 | 789 B | 664µs | 324µs |
| fish | 2646 | 8 | 1438 | 0.54 | 763 | 179 B | 541µs | 224µs |
| htop | 34849 | 39 | 47830 | 1.37 | 13334 | 1226 B | 670µs | 335µs |
| less | 8908 | 15 | 9945 | 1.12 | 4070 | 663 B | 420µs | 229µs |
| synth-seq100k | 688895 | 674 | 199877 | 0.29 | 69115 | 296 B | 337µs | 167µs |
| synth-top200x60 | 3252000 | 3177 | 1629772 | 0.50 | 446253 | 512 B | 1.335ms | 810µs |
| unicode | 1073 | 3 | 1684 | 1.57 | 1004 | 561 B | 214µs | 170µs |
| vim | 14865 | 19 | 19357 | 1.30 | 7619 | 1018 B | 330µs | 206µs |
| zsh | 23259 | 29 | 16652 | 0.72 | 6713 | 574 B | 304µs | 215µs |

Run 2: Machine: dan-desktop, 24 CPUs, 12th Gen Intel(R) Core(TM) i9-12900K, 2026-11-13T19:52:36Z, load average: 1.65 4.75 12.17 (other spikes share this machine)

emulator tuios, frame every 1024 bytes

| stream | raw bytes | frames | diff bytes | diff/raw | deflated diffs | mean diff | p99 snapshot+diff | mean snapshot+diff |
|---|---|---|---|---|---|---|---|---|
| claude | 6021 | 10 | 7896 | 1.31 | 2543 | 789 B | 411µs | 204µs |
| fish | 2646 | 8 | 1438 | 0.54 | 763 | 179 B | 275µs | 187µs |
| htop | 34849 | 39 | 48139 | 1.38 | 13383 | 1234 B | 433µs | 238µs |
| less | 8908 | 15 | 9945 | 1.12 | 4070 | 663 B | 498µs | 162µs |
| synth-seq100k | 688895 | 674 | 199877 | 0.29 | 69115 | 296 B | 168µs | 96µs |
| synth-top200x60 | 3252000 | 3177 | 1629772 | 0.50 | 446253 | 512 B | 967µs | 574µs |
| unicode | 1073 | 3 | 1684 | 1.57 | 1003 | 561 B | 257µs | 147µs |
| vim | 14865 | 19 | 19299 | 1.30 | 7580 | 1015 B | 164µs | 107µs |
| zsh | 23259 | 29 | 16652 | 0.72 | 6713 | 574 B | 104µs | 92µs |

Run 2: Machine: dan-desktop, 24 CPUs, 12th Gen Intel(R) Core(TM) i9-12900K, 2026-11-13T19:52:39Z, load average: 1.60 4.68 12.11 (other spikes share this machine)

emulator ghostty, frame every 1024 bytes

| stream | raw bytes | frames | diff bytes | diff/raw | deflated diffs | mean diff | p99 snapshot+diff | mean snapshot+diff |
|---|---|---|---|---|---|---|---|---|
| claude | 6021 | 10 | 7896 | 1.31 | 2543 | 789 B | 480µs | 239µs |
| fish | 2646 | 8 | 1438 | 0.54 | 763 | 179 B | 410µs | 208µs |
| htop | 34849 | 39 | 47830 | 1.37 | 13334 | 1226 B | 608µs | 330µs |
| less | 8908 | 15 | 9945 | 1.12 | 4070 | 663 B | 443µs | 236µs |
| synth-seq100k | 688895 | 674 | 199877 | 0.29 | 69115 | 296 B | 288µs | 163µs |
| synth-top200x60 | 3252000 | 3177 | 1629772 | 0.50 | 446253 | 512 B | 1.292ms | 799µs |
| unicode | 1073 | 3 | 1684 | 1.57 | 1004 | 561 B | 221µs | 173µs |
| vim | 14865 | 19 | 19357 | 1.30 | 7619 | 1018 B | 305µs | 186µs |
| zsh | 23259 | 29 | 16652 | 0.72 | 6713 | 574 B | 189µs | 161µs |

Run 3: Machine: dan-desktop, 24 CPUs, 12th Gen Intel(R) Core(TM) i9-12900K, 2026-11-13T19:52:42Z, load average: 1.60 4.68 12.11 (other spikes share this machine)

emulator tuios, frame every 1024 bytes

| stream | raw bytes | frames | diff bytes | diff/raw | deflated diffs | mean diff | p99 snapshot+diff | mean snapshot+diff |
|---|---|---|---|---|---|---|---|---|
| claude | 6021 | 10 | 7896 | 1.31 | 2543 | 789 B | 286µs | 148µs |
| fish | 2646 | 8 | 1438 | 0.54 | 763 | 179 B | 202µs | 138µs |
| htop | 34849 | 39 | 48139 | 1.38 | 13383 | 1234 B | 599µs | 272µs |
| less | 8908 | 15 | 9945 | 1.12 | 4070 | 663 B | 281µs | 171µs |
| synth-seq100k | 688895 | 674 | 199877 | 0.29 | 69115 | 296 B | 160µs | 96µs |
| synth-top200x60 | 3252000 | 3177 | 1629772 | 0.50 | 446253 | 512 B | 948µs | 573µs |
| unicode | 1073 | 3 | 1684 | 1.57 | 1003 | 561 B | 97µs | 95µs |
| vim | 14865 | 19 | 19299 | 1.30 | 7580 | 1015 B | 225µs | 115µs |
| zsh | 23259 | 29 | 16652 | 0.72 | 6713 | 574 B | 300µs | 122µs |

Run 3: Machine: dan-desktop, 24 CPUs, 12th Gen Intel(R) Core(TM) i9-12900K, 2026-11-13T19:52:44Z, load average: 1.55 4.62 12.05 (other spikes share this machine)

emulator ghostty, frame every 1024 bytes

| stream | raw bytes | frames | diff bytes | diff/raw | deflated diffs | mean diff | p99 snapshot+diff | mean snapshot+diff |
|---|---|---|---|---|---|---|---|---|
| claude | 6021 | 10 | 7896 | 1.31 | 2543 | 789 B | 493µs | 241µs |
| fish | 2646 | 8 | 1438 | 0.54 | 763 | 179 B | 447µs | 212µs |
| htop | 34849 | 39 | 47830 | 1.37 | 13334 | 1226 B | 718µs | 365µs |
| less | 8908 | 15 | 9945 | 1.12 | 4070 | 663 B | 444µs | 234µs |
| synth-seq100k | 688895 | 674 | 199877 | 0.29 | 69115 | 296 B | 320µs | 166µs |
| synth-top200x60 | 3252000 | 3177 | 1629772 | 0.50 | 446253 | 512 B | 1.303ms | 811µs |
| unicode | 1073 | 3 | 1684 | 1.57 | 1004 | 561 B | 226µs | 172µs |
| vim | 14865 | 19 | 19357 | 1.30 | 7619 | 1018 B | 302µs | 200µs |
| zsh | 23259 | 29 | 16652 | 0.72 | 6713 | 574 B | 224µs | 195µs |

