# O8 terminal captures

Byte streams written by real programs under a pty, recorded with
`cmd/capture` (format: repeated u64 microseconds, u32 length, bytes) on
2026-11-13 on the spike author's NixOS 26.05 machine at 120x40.
`run-captures.sh` regenerates them (the bytes will differ run to run).

Committed: `shell`, `less`, `vim`, `flood`. They show only the OS
release file, a listing of this spike's directory, a bash man page, and the
spike's own `ssp/transport.go` (an earlier revision) - checked for
anything private before committing.

**Not committed: `top`, `htop`.** They contain the machine's live
process list (command lines can carry secrets). Results in
`docs/spikes/s5-netsim-ssp/results/o8-compression-6sessions.md` include
them; `o8-compression.md` is reproducible from the committed four alone
(`go test ./o8 -run O8Report -v`).

SHA-256 of the six files the results used:

```
66f1b450db313a7908413c4cf07a2b880a743a72504486c20253e84058176b8a  flood.bin
bf3fe1e1c41213580aa553f5e3021db396308f2d7caf3e8ccf5bd249bbb3c730  htop.bin
6d9c74db7a5799df43cf482ec0d6ca261c34e642db29ded18cee2e8c9ce1bd3e  less.bin
3770f4c014fe741f74419a1b2e83c33e44a7c0bbe8e251fab927ebf397abc997  shell.bin
a882b65bdf2d6be4105c921fe35a855294f3063a8a7b93a29b7b66632a18ff24  top.bin
033f890062470e73b9934b3547c2b8fad5c3fb5a55405f9270307099b4af2f19  vim.bin
```
