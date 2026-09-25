const std = @import("std");
const watch_mod = @import("../watch.zig");

pub fn collectDirty(self: anytype) void {
    for (0..self.paths.items.len) |i| {
        if (changed(self, i)) self.markDirty(@intCast(i));
    }
}

/// True when the tracked file at `i` can have new bytes or a new identity.
/// A stat error counts as a change.
fn changed(self: anytype, i: usize) bool {
    const file = self.files.items[i] orelse return true;
    const active_st = watch_mod.fstatHandle(file.handle) catch return true;
    const active_size: u64 = active_st.size;
    if (active_size != self.offsets.items[i]) return true;

    const path_st = std.Io.Dir.cwd().statFile(self.io, self.paths.items[i], .{}) catch return true;
    if (path_st.kind != .file) return true;

    const active_inode: u64 = active_st.ino;
    const path_inode: u64 = @intCast(path_st.inode);
    return path_inode != active_inode or path_st.size != active_size;
}
