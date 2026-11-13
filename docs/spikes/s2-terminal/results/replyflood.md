# Reply path under a query flood (cmd/replyflood)

A child on a raw-mode pty writes 64 MiB of `CSI 6n, CSI c, CSI > c, OSC 11 ?` plus a line of text, repeated, and never reads stdin. The server feeds tuios and writes tuios' replies back to the pty master. naive = one goroutine reads, parses and writes replies; split = the reader never writes, replies go to a 64 KiB bounded queue drained by a separate writer goroutine, overflow dropped and counted. Deadlock = no output consumed for 5 s. 3 runs each, interleaved, 2026-11-13 ~19:28 UTC, machine loaded by other spikes (load ~25).

```
mode=naive result=DEADLOCK child_mib=64 fed_mib=0.0 elapsed_s=0.2 replies_written_kib=19 replies_dropped_kib=0 max_queued_kib=0 heap_mib=1.0
mode=split result=completed child_mib=64 fed_mib=65.1 elapsed_s=6.4 replies_written_kib=17 replies_dropped_kib=54529 max_queued_kib=64 heap_mib=3.1
mode=naive result=DEADLOCK child_mib=64 fed_mib=0.0 elapsed_s=0.1 replies_written_kib=17 replies_dropped_kib=0 max_queued_kib=0 heap_mib=1.1
mode=split result=completed child_mib=64 fed_mib=65.1 elapsed_s=6.8 replies_written_kib=19 replies_dropped_kib=54528 max_queued_kib=64 heap_mib=2.0
mode=naive result=DEADLOCK child_mib=64 fed_mib=0.0 elapsed_s=0.2 replies_written_kib=17 replies_dropped_kib=0 max_queued_kib=0 heap_mib=1.0
mode=split result=completed child_mib=64 fed_mib=65.1 elapsed_s=7.3 replies_written_kib=19 replies_dropped_kib=54528 max_queued_kib=64 heap_mib=2.4
```
