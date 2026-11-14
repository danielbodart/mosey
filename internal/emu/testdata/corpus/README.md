# The O11 gate's corpus

Copies, as data, of the spikes' committed recordings, so production code
and its tests never import `spikes/` (docs/spec/screen.md §5.12):

- `s5/*.bin`: S5's O8 captures (`spikes/s5-netsim-ssp/testdata/captures/`),
  recorded at 120 x 40: repeated big-endian u64 microseconds, u32 length,
  then that many pty bytes. Their SHA-256 sums are in that directory's
  README.
- `s2/<name>/raw.bin` and `events.json`: S2's app recordings
  (`spikes/s2-terminal/fixtures/rec/`), at 80 x 24, with checkpoints and
  resizes by byte offset but no timing.

They show only an OS release file, a spike's own source, a man page and
the S2 Unicode torture file.
