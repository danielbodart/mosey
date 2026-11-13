# Helper-process boundary cost

3 repetitions, one table each, tuios then libghostty alternating.

Run 1: Machine: dan-desktop, 24 CPUs, 12th Gen Intel(R) Core(TM) i9-12900K, 2026-11-13T19:51:13Z, load average: 2.68 5.89 13.22 (other spikes share this machine)

| emulator / workload / mode | iterations | p50 round | p99 | p99.9 | CPU per round (both processes) | diff bytes per round |
|---|---|---|---|---|---|---|
| tuios / echo / in-process | 20000 | 89µs | 223.2µs | 296.7µs | 112µs | 11 |
| tuios / echo / helper+socketpair | 20000 | 94.1µs | 219µs | 289.3µs | 118.6µs | 11 |
| tuios / line / in-process | 20000 | 94.4µs | 242.7µs | 304.3µs | 143.5µs | 75 |
| tuios / line / helper+socketpair | 20000 | 101.8µs | 263µs | 334.5µs | 160.4µs | 75 |
| tuios / top / in-process | 1000 | 667µs | 1.1569ms | 1.2659ms | 877.8µs | 3166 |
| tuios / top / helper+socketpair | 1000 | 694.6µs | 1.2321ms | 1.3452ms | 925.6µs | 3161 |

Run 1: Machine: dan-desktop, 24 CPUs, 12th Gen Intel(R) Core(TM) i9-12900K, 2026-11-13T19:51:23Z, load average: 2.42 5.72 13.09 (other spikes share this machine)

| emulator / workload / mode | iterations | p50 round | p99 | p99.9 | CPU per round (both processes) | diff bytes per round |
|---|---|---|---|---|---|---|
| ghostty / echo / in-process | 20000 | 118.5µs | 271.3µs | 351.1µs | 141.4µs | 11 |
| ghostty / echo / helper+socketpair | 20000 | 124.3µs | 279.3µs | 360.5µs | 152.8µs | 11 |
| ghostty / line / in-process | 20000 | 170.7µs | 385.2µs | 476.2µs | 227.8µs | 75 |
| ghostty / line / helper+socketpair | 20000 | 179.9µs | 396.2µs | 497.2µs | 235.8µs | 75 |
| ghostty / top / in-process | 1000 | 1.1673ms | 2.0834ms | 2.1604ms | 1.4158ms | 3166 |
| ghostty / top / helper+socketpair | 1000 | 1.1946ms | 2.1157ms | 2.2838ms | 1.5094ms | 3161 |

Run 2: Machine: dan-desktop, 24 CPUs, 12th Gen Intel(R) Core(TM) i9-12900K, 2026-11-13T19:51:39Z, load average: 2.09 5.43 12.83 (other spikes share this machine)

| emulator / workload / mode | iterations | p50 round | p99 | p99.9 | CPU per round (both processes) | diff bytes per round |
|---|---|---|---|---|---|---|
| tuios / echo / in-process | 20000 | 89.1µs | 223µs | 301.7µs | 113.2µs | 11 |
| tuios / echo / helper+socketpair | 20000 | 94.7µs | 226.9µs | 301.3µs | 121.6µs | 11 |
| tuios / line / in-process | 20000 | 95.2µs | 237.8µs | 304.3µs | 147.5µs | 75 |
| tuios / line / helper+socketpair | 20000 | 103µs | 267.6µs | 344.5µs | 162.2µs | 75 |
| tuios / top / in-process | 1000 | 670.3µs | 1.1837ms | 1.312ms | 876.8µs | 3166 |
| tuios / top / helper+socketpair | 1000 | 694.6µs | 1.2447ms | 1.3712ms | 922.1µs | 3161 |

Run 2: Machine: dan-desktop, 24 CPUs, 12th Gen Intel(R) Core(TM) i9-12900K, 2026-11-13T19:51:49Z, load average: 2.08 5.32 12.72 (other spikes share this machine)

| emulator / workload / mode | iterations | p50 round | p99 | p99.9 | CPU per round (both processes) | diff bytes per round |
|---|---|---|---|---|---|---|
| ghostty / echo / in-process | 20000 | 118.7µs | 281.2µs | 368.8µs | 142.8µs | 11 |
| ghostty / echo / helper+socketpair | 20000 | 124.4µs | 277.6µs | 374µs | 153.6µs | 11 |
| ghostty / line / in-process | 20000 | 170.7µs | 398.7µs | 507µs | 228.5µs | 75 |
| ghostty / line / helper+socketpair | 20000 | 178.1µs | 390.7µs | 470.1µs | 232.7µs | 75 |
| ghostty / top / in-process | 1000 | 1.1612ms | 2.0673ms | 2.2142ms | 1.3896ms | 3166 |
| ghostty / top / helper+socketpair | 1000 | 1.1919ms | 2.1083ms | 2.2598ms | 1.4924ms | 3161 |

Run 3: Machine: dan-desktop, 24 CPUs, 12th Gen Intel(R) Core(TM) i9-12900K, 2026-11-13T19:52:05Z, load average: 1.90 5.12 12.53 (other spikes share this machine)

| emulator / workload / mode | iterations | p50 round | p99 | p99.9 | CPU per round (both processes) | diff bytes per round |
|---|---|---|---|---|---|---|
| tuios / echo / in-process | 20000 | 88.6µs | 226.8µs | 316.6µs | 111.1µs | 11 |
| tuios / echo / helper+socketpair | 20000 | 95.1µs | 228.5µs | 309.6µs | 123.2µs | 11 |
| tuios / line / in-process | 20000 | 96.4µs | 265.6µs | 330.9µs | 153µs | 75 |
| tuios / line / helper+socketpair | 20000 | 101.9µs | 260.4µs | 333.7µs | 160.2µs | 75 |
| tuios / top / in-process | 1000 | 672.4µs | 1.1701ms | 1.2799ms | 889.2µs | 3166 |
| tuios / top / helper+socketpair | 1000 | 696.6µs | 1.2842ms | 1.3713ms | 949.1µs | 3161 |

Run 3: Machine: dan-desktop, 24 CPUs, 12th Gen Intel(R) Core(TM) i9-12900K, 2026-11-13T19:52:15Z, load average: 1.68 4.97 12.40 (other spikes share this machine)

| emulator / workload / mode | iterations | p50 round | p99 | p99.9 | CPU per round (both processes) | diff bytes per round |
|---|---|---|---|---|---|---|
| ghostty / echo / in-process | 20000 | 118.5µs | 280.9µs | 371.3µs | 143µs | 11 |
| ghostty / echo / helper+socketpair | 20000 | 125.1µs | 280.1µs | 355µs | 155.4µs | 11 |
| ghostty / line / in-process | 20000 | 171µs | 389.2µs | 474.1µs | 226µs | 75 |
| ghostty / line / helper+socketpair | 20000 | 178.6µs | 391.8µs | 485.1µs | 233.2µs | 75 |
| ghostty / top / in-process | 1000 | 1.1837ms | 2.0324ms | 2.1365ms | 1.4517ms | 3166 |
| ghostty / top / helper+socketpair | 1000 | 1.1984ms | 2.0459ms | 2.2398ms | 1.5013ms | 3161 |

