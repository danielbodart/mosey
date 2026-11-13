# Hostile input at the client clamp (1000x500)

Rerun after the S2 review: every case with the session created at 1000x500 (`hostile -size 1000x500`), tuios and tuios' libghostty binding only, plus the four new cases (resize-to-clamp, resize-storm-clamp, cluster-color-scrollback, osc8-long-links). Machine: dan-desktop, 2026-11-13 ~19:32 UTC. Same watchdog: 30 s, 4 GiB, GOMAXPROCS=2. Each cell: outcome, wall time, peak RSS; for runs killed at the limit, the throughput reached.

load at start: 26.06 26.60 22.09
| case | ghostty | tuios |
|---|---|---|
| csi-huge-params | ok 7.1s 57MiB | ok 0.1s 11MiB |
| csi-many-params | ok 0.1s 24MiB | ok 0.0s 16MiB |
| rep-intmax | ok 0.0s 25MiB | ok 0.0s 9MiB |
| rep-overflow | ok 0.1s 25MiB | ok 0.1s 67MiB |
| rep-65535-x10k | ok 1.0s 114MiB | TIMEOUT>30s 30.0s 74MiB (0.0 MB/s, 9794 writes) |
| sixel-huge-raster | ok 0.2s 72MiB | ok 0.1s 55MiB |
| sixel-many-bands | ok 0.2s 73MiB | ok 0.1s 55MiB |
| kitty-huge-declared | ok 0.2s 19MiB | ok 0.1s 13MiB |
| kitty-many-images | ok 0.1s 19MiB | ok 0.0s 12MiB |
| osc-title-64MiB | ok 0.2s 33MiB | ok 0.6s 31MiB |
| osc-unterminated-256MiB | ok 0.5s 31MiB | ok 2.7s 31MiB |
| osc52-64MiB | ok 0.1s 41MiB | ok 0.6s 31MiB |
| dcs-unterminated-256MiB | ok 4.9s 21MiB | ok 0.2s 27MiB |
| osc8-1M-links | ok 1.9s 94MiB | ok 2.0s 182MiB |
| title-stack-1M | ok 2.2s 20MiB | ok 0.8s 13MiB |
| grapheme-1M-combining | ok 0.3s 17MiB | ok 0.5s 11MiB |
| zwj-chain-1M | ok 0.6s 97MiB | ok 0.8s 11MiB |
| truecolor-churn | ok 10.4s 166MiB | ok 9.0s 377MiB |
| scrollback-flood | ok 7.3s 112MiB | TIMEOUT>30s 30.0s 86MiB (13.0 MB/s, 5904 writes) |
| altscreen-toggle | TIMEOUT>30s 30.0s 24MiB (0.0 MB/s, 2 writes) | ok 3.5s 140MiB |
| dsr-flood | ok 1.0s 20MiB | ok 0.7s 13MiB |
| sync-never-ends | ok 1.0s 110MiB | ok 0.4s 66MiB |
| resize-storm | ok 13.9s 17MiB | ok 6.2s 51MiB |
| resize-to-clamp | ok 0.3s 20MiB | ok 0.4s 86MiB |
| resize-storm-clamp | ok 1.0s 16MiB | ok 0.4s 23MiB |
| cluster-color-scrollback | TIMEOUT>30s 30.0s 373MiB (4.0 MB/s, 1510 writes) | TIMEOUT>30s 30.0s 606MiB (7.9 MB/s, 2958 writes) |
| osc8-long-links | ok 3.1s 97MiB | ok 6.4s 790MiB |
| resize-huge | ok 0.9s 13MiB | ok 13.8s 2870MiB |

real	3m10.121s
user	4m6.459s
sys	0m14.667s

## The four new cases at 80x24, all candidates

load at start: 25.11 25.86 22.64
| case | ghostty | tuios | charm | xtermgo | cy |
|---|---|---|---|---|---|
| resize-to-clamp | ok 0.4s 20MiB | ok 0.4s 86MiB | ok 0.9s 274MiB | ok 0.2s 33MiB | ok 0.4s 98MiB |
| resize-storm-clamp | ok 1.1s 17MiB | ok 0.6s 25MiB | ok 12.7s 315MiB | CRASH 0.7s 323MiB (0.0 MB/s, 98 writes) | ok 6.5s 99MiB |
| cluster-color-scrollback | TIMEOUT>30s 30.0s 51MiB (2.5 MB/s, 1174 writes) | ok 10.0s 145MiB | ok 1.8s 182MiB | ok 2.8s 199MiB | ok 2.0s 107MiB |
| osc8-long-links | ok 3.2s 39MiB | ok 7.6s 896MiB | ok 4.6s 779MiB | ok 4.8s 1188MiB | ok 5.4s 40MiB |
