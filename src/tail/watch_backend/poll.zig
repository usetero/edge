const std = @import("std");
const watch_mod = @import("../watch.zig");

pub fn collectDirty(self: anytype) void {
    const io = self.io;
    var i: usize = 0;
    while (i < self.paths.items.len) : (i += 1) {
        const idx: u32 = @intCast(i);
        if (self.files.items[i] == null) {
            self.markDirty(idx);
            continue;
        }

        const file = self.files.items[i].?;
        const active_st = watch_mod.fstatHandle(file.handle) catch {
            self.markDirty(idx);
            continue;
        };
        const active_size: u64 = active_st.size;
        if (active_size != self.offsets.items[i]) {
            self.markDirty(idx);
            continue;
        }

        const path_st = std.Io.Dir.cwd().statFile(io, self.paths.items[i], .{}) catch {
            self.markDirty(idx);
            continue;
        };
        if (path_st.kind != .file) {
            self.markDirty(idx);
            continue;
        }

        const active_inode: u64 = active_st.ino;
        const path_inode: u64 = @intCast(path_st.inode);
        if (path_inode != active_inode or path_st.size != active_size) {
            self.markDirty(idx);
        }
    }
}
