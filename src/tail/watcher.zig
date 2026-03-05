const std = @import("std");

pub const ReadFrom = enum {
    head,
    tail,
};

pub const FileEvent = struct {
    index: usize,
    start_offset: u64,
    end_offset: u64,
};

const TrackedFile = struct {
    path: []u8,
    file: ?std.fs.File,
    offset: u64,
};

pub const Watcher = struct {
    allocator: std.mem.Allocator,
    files: std.ArrayList(TrackedFile),
    events: std.ArrayList(FileEvent),

    pub fn init(allocator: std.mem.Allocator, paths: []const []const u8, read_from: ReadFrom) !Watcher {
        var watcher = Watcher{
            .allocator = allocator,
            .files = .{},
            .events = .{},
        };
        try watcher.files.ensureTotalCapacity(allocator, paths.len);

        for (paths) |path| {
            const path_copy = try allocator.dupe(u8, path);
            var tracked = TrackedFile{
                .path = path_copy,
                .file = null,
                .offset = 0,
            };
            try watcher.openTrackedFile(&tracked, read_from);
            watcher.files.appendAssumeCapacity(tracked);
        }

        return watcher;
    }

    pub fn deinit(self: *Watcher) void {
        for (self.files.items) |*tracked| {
            if (tracked.file) |file| {
                file.close();
            }
            self.allocator.free(tracked.path);
        }
        self.files.deinit(self.allocator);
        self.events.deinit(self.allocator);
    }

    pub fn poll(self: *Watcher, read_from: ReadFrom) ![]const FileEvent {
        self.events.clearRetainingCapacity();

        for (self.files.items, 0..) |*tracked, idx| {
            if (tracked.file == null) {
                try self.openTrackedFile(tracked, read_from);
                if (tracked.file == null) continue;
            }

            const file = tracked.file.?;
            const stat = file.stat() catch {
                file.close();
                tracked.file = null;
                tracked.offset = 0;
                continue;
            };

            if (stat.size < tracked.offset) {
                tracked.offset = 0;
            }

            if (stat.size > tracked.offset) {
                try self.events.append(self.allocator, .{
                    .index = idx,
                    .start_offset = tracked.offset,
                    .end_offset = stat.size,
                });
                tracked.offset = stat.size;
            }
        }

        return self.events.items;
    }

    pub fn fileForEvent(self: *Watcher, event: FileEvent) *const std.fs.File {
        return &self.files.items[event.index].file.?;
    }

    fn openTrackedFile(self: *Watcher, tracked: *TrackedFile, read_from: ReadFrom) !void {
        if (tracked.file != null) return;

        const file = std.fs.cwd().openFile(tracked.path, .{}) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };

        const stat = try file.stat();
        tracked.offset = switch (read_from) {
            .head => 0,
            .tail => stat.size,
        };
        tracked.file = file;

        _ = self;
    }
};
