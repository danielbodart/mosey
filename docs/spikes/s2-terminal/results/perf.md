# Per-session memory and throughput

Machine: dan-desktop, 24 CPUs, 12th Gen Intel(R) Core(TM) i9-12900K, 2026-11-13T18:59:52Z, load average at start: 13.16 35.36 39.04 (other spikes share this machine)

| emulator | RSS per fresh 80x24 session | RSS per session after 10k coloured lines | plain MB/s | SGR MB/s | recorded-apps MB/s |
|---|---|---|---|---|---|
| ghostty | 60 KiB | 7550 KiB | 112.6 | 105.0 | 25.5 |
| tuios | 44 KiB | 1177 KiB | 60.9 | 45.2 | 44.8 |
| charm | 498 KiB | 58688 KiB | 2.7 | 3.2 | 1.7 |
| xtermgo | 79 KiB | 12655 KiB | 48.4 | 65.6 | 31.9 |
| cy | 120 KiB | 48926 KiB | 15.5 | 19.0 | 18.5 |
