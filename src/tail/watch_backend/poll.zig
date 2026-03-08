const std = @import("std");

pub fn collectDirty(self: anytype) void {
    var i: usize = 0;
    while (i < self.paths.items.len) : (i += 1) {
        const idx: u32 = @intCast(i);
        if (self.files.items[i] == null) {
            self.markDirty(idx);
            continue;
        }

        const file = self.files.items[i].?;
        const active_st = std.posix.fstat(file.handle) catch {
            self.markDirty(idx);
            continue;
        };
        const active_size: u64 = @bitCast(active_st.size);
        if (active_size != self.offsets.items[i]) {
            self.markDirty(idx);
            continue;
        }

        const path_st = std.fs.cwd().statFile(self.paths.items[i]) catch {
            self.markDirty(idx);
            continue;
        };
        if (path_st.kind != .file) {
            self.markDirty(idx);
            continue;
        }

        const active_inode: u64 = @intCast(active_st.ino);
        const path_inode: u64 = @intCast(path_st.inode);
        if (path_inode != active_inode or path_st.size != active_size) {
            self.markDirty(idx);
        }
    }
}
