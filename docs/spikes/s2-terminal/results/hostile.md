# Hostile input

Machine: dan-desktop, 24 CPUs, 12th Gen Intel(R) Core(TM) i9-12900K, 2026-11-13T19:01:46Z, load average at start: 12.43 28.13 35.98 (other spikes share this machine)

Each cell: outcome, wall time, peak RSS; for runs killed at the limit, the throughput reached. Children run with GOMAXPROCS=2, 5 emulators in parallel per case, 30 s / 4 GiB limits.

Scoring rule (added after the S2 review; FINDINGS applies it): *ok* finishes in reasonable time and memory; *degraded* is a finite slowdown or a large but bounded allocation that stays inside the one session (the helper's limits contain it); *fail* is a crash, unbounded work, or memory growth the emulator never stops. TIMEOUT means killed by the 30 s watchdog, which can be either: libghostty's altscreen-toggle is degraded (each toggle finishes, ~14k/s), charm's rep-overflow is a fail (one REP never returns). The "resize-huge" row is client-controlled in mosey, not host-controlled; see hostile-clamp.md for the rerun at the 1000x500 clamp.

| case | ghostty | tuios | charm | xtermgo | cy |
|---|---|---|---|---|---|
| csi-huge-params | ok 0.1s 17MiB | ok 0.0s 10MiB | ok 0.3s 11MiB | TIMEOUT>30s 30.0s 29MiB (0.0 MB/s, 1 writes) | TIMEOUT>30s 30.0s 7MiB (0.0 MB/s, 5 writes) |
| csi-many-params | ok 0.0s 19MiB | ok 0.0s 15MiB | ok 0.0s 12MiB | ok 0.0s 12MiB | ok 0.0s 12MiB |
| rep-intmax | ok 0.0s 12MiB | ok 0.0s 12MiB | ok 0.0s 12MiB | OOM>4096MiB 3.6s 4134MiB (0.0 MB/s, 1 writes) | ok 0.0s 12MiB |
| rep-overflow | ok 0.0s 12MiB | ok 0.0s 12MiB | TIMEOUT>30s 30.0s 207MiB (0.0 MB/s, 1 writes) | ok 0.0s 12MiB | ok 0.0s 12MiB |
| rep-65535-x10k | ok 2.3s 16MiB | ok 0.9s 12MiB | TIMEOUT>30s 30.0s 208MiB (0.0 MB/s, 1998 writes) | ok 8.6s 34MiB | ok 0.0s 12MiB |
| sixel-huge-raster | ok 0.0s 14MiB | ok 0.0s 14MiB | ok 0.0s 14MiB | ok 0.0s 14MiB | ok 0.0s 14MiB |
| sixel-many-bands | ok 0.0s 14MiB | ok 0.0s 14MiB | ok 0.0s 14MiB | ok 0.0s 14MiB | ok 0.0s 14MiB |
| kitty-huge-declared | ok 0.2s 14MiB | ok 0.1s 14MiB | ok 0.3s 14MiB | ok 0.3s 14MiB | ok 0.3s 14MiB |
| kitty-many-images | ok 0.0s 14MiB | ok 0.0s 14MiB | ok 0.0s 14MiB | ok 0.0s 14MiB | ok 0.0s 14MiB |
| osc-title-64MiB | ok 0.1s 27MiB | ok 0.7s 30MiB | ok 0.3s 15MiB | ok 0.2s 55MiB | ok 0.4s 300MiB |
| osc-unterminated-256MiB | ok 0.3s 25MiB | ok 2.6s 30MiB | ok 1.3s 14MiB | ok 0.5s 63MiB | ok 1.5s 1118MiB |
| osc52-64MiB | ok 0.1s 37MiB | ok 0.5s 31MiB | ok 0.4s 14MiB | ok 0.3s 14MiB | ok 0.4s 300MiB |
| dcs-unterminated-256MiB | ok 4.8s 14MiB | ok 0.2s 28MiB | ok 1.0s 14MiB | ok 1.1s 14MiB | ok 1.3s 14MiB |
| osc8-1M-links | ok 1.5s 28MiB | ok 1.1s 89MiB | ok 0.9s 215MiB | TIMEOUT>30s 30.1s 1503MiB (1.2 MB/s, 818321 writes) | ok 2.2s 106MiB |
| title-stack-1M | ok 1.7s 14MiB | ok 0.7s 14MiB | ok 0.6s 18MiB | ok 0.4s 14MiB | ok 1.7s 14MiB |
| grapheme-1M-combining | ok 0.3s 14MiB | ok 0.3s 14MiB | ok 0.0s 14MiB | TIMEOUT>30s 30.0s 77MiB (0.0 MB/s, 18 writes) | ok 0.0s 14MiB |
| zwj-chain-1M | ok 0.8s 41MiB | ok 0.8s 14MiB | ok 0.1s 41MiB | ok 0.2s 83MiB | ok 0.1s 52MiB |
| truecolor-churn | ok 8.7s 45MiB | ok 8.2s 33MiB | ok 12.6s 215MiB | ok 6.5s 33MiB | ok 13.8s 1767MiB |
| scrollback-flood | ok 7.4s 16MiB | ok 21.2s 14MiB | TIMEOUT>30s 30.0s 182MiB (3.0 MB/s, 1369 writes) | ok 15.7s 33MiB | TIMEOUT>30s 30.0s 268MiB (20.2 MB/s, 9184 writes) |
| altscreen-toggle | TIMEOUT>30s 30.0s 20MiB (0.3 MB/s, 160 writes) | ok 0.9s 14MiB | ok 10.3s 15MiB | ok 10.9s 16MiB | ok 5.1s 101MiB |
| dsr-flood | ok 0.6s 14MiB | ok 0.5s 14MiB | ok 2.4s 15MiB | ok 0.2s 14MiB | ok 0.3s 14MiB |
| sync-never-ends | ok 0.3s 15MiB | ok 0.2s 14MiB | ok 13.2s 35MiB | ok 0.3s 33MiB | ok 1.0s 68MiB |
| resize-storm | ok 9.5s 16MiB | ok 4.8s 50MiB | ok 23.1s 58MiB | CRASH 0.0s 46MiB | ok 11.1s 105MiB |
| resize-huge | ok 0.6s 14MiB | ok 9.8s 2870MiB | OOM>4096MiB 2.0s 4161MiB (0.0 MB/s, 0 writes) | ok 2.2s 305MiB | ok 7.3s 2865MiB |
