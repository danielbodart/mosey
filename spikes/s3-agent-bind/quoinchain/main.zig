//! quoin-chain: quoin-sudo's own chain walk and remote-mode rule
//! (sudo/chain.zig, imported unchanged from the quoin worktree named at
//! build time), run on this process's real chain. The plugin walks from
//! sudo's parent (getppid); so does this, so `sh -c quoin-chain` inside a
//! mosey session sees what `sh -c 'sudo ...'` would.
const std = @import("std");
const chain = @import("chain");

pub fn main() !void {
    var links: [chain.max_links]chain.Link = undefined;
    const n = chain.walk(chain.parentPid(), &links);
    const uid = std.os.linux.getuid();
    var buf: [4096]u8 = undefined;
    var w = std.fs.File.stdout().writerStreaming(&buf);
    const out = &w.interface;
    for (links[0..n]) |*l| {
        try out.print("  {d} {s} uid={d}\n", .{ l.pid, l.comm(), l.uid });
    }
    try out.print("quoin chain.zig remote(): {}\n", .{chain.remote(links[0..n], uid)});
    try out.flush();
}
