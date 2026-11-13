# Helper-process boundary cost

Machine: dan-desktop, 24 CPUs, 12th Gen Intel(R) Core(TM) i9-12900K, 2026-11-13T19:01:18Z, load average at start: 12.50 29.81 36.77 (other spikes share this machine)

| emulator / workload / mode | iterations | p50 round | p99 | p99.9 | CPU per round (both processes) | diff bytes per round |
|---|---|---|---|---|---|---|
| tuios / echo / in-process | 20000 | 94.5µs | 223.6µs | 271.5µs | 113.3µs | 11 |
| tuios / echo / helper+socketpair | 20000 | 121.7µs | 247µs | 679µs | 132.8µs | 11 |
| tuios / line / in-process | 20000 | 112.2µs | 247.5µs | 316.1µs | 150.2µs | 75 |
| tuios / line / helper+socketpair | 20000 | 118.2µs | 261.8µs | 586.6µs | 159.9µs | 75 |
| tuios / top / in-process | 1000 | 715µs | 1.0989ms | 1.2586ms | 890.4µs | 3166 |
| tuios / top / helper+socketpair | 1000 | 881.4µs | 1.188ms | 1.5773ms | 963µs | 3161 |

| emulator / workload / mode | iterations | p50 round | p99 | p99.9 | CPU per round (both processes) | diff bytes per round |
|---|---|---|---|---|---|---|
| ghostty / echo / in-process | 20000 | 131.6µs | 281µs | 316.5µs | 149.9µs | 11 |
| ghostty / echo / helper+socketpair | 20000 | 157.9µs | 315.2µs | 923.9µs | 172.2µs | 11 |
| ghostty / line / in-process | 20000 | 196.2µs | 409.1µs | 493µs | 238.6µs | 75 |
| ghostty / line / helper+socketpair | 20000 | 229.3µs | 417.7µs | 601.8µs | 253.1µs | 75 |
| ghostty / top / in-process | 1000 | 1.2588ms | 1.8543ms | 2.3169ms | 1.4662ms | 3166 |
| ghostty / top / helper+socketpair | 1000 | 1.4161ms | 1.9309ms | 2.3306ms | 1.5795ms | 3161 |

