const std = @import("std");

const log = std.log.scoped(.tail_io);

pub const OutputTarget = union(enum) {
    stdout,
    file_append: []const u8,
};

/// Writer endpoint wrapper for edge-tail.
///
/// This enforces append-safe file behavior while still exposing
/// `*std.Io.Writer` so callers can stay interface-driven.
pub const Output = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    file: std.Io.File,
    close_on_deinit: bool,
    write_buf: []u8,
    file_writer: std.Io.File.Writer,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, target: OutputTarget, write_buf_size: usize) !Output {
        return switch (target) {
            .stdout => initStdout(allocator, io, write_buf_size),
            .file_append => |path| initFileAppend(allocator, io, path, write_buf_size),
        };
    }

    pub fn initStdout(allocator: std.mem.Allocator, io: std.Io, write_buf_size: usize) !Output {
        const buf = try allocator.alloc(u8, write_buf_size);
        const file = std.Io.File.stdout();
        const fw = file.writerStreaming(io, buf);
        return .{
            .allocator = allocator,
            .io = io,
            .file = file,
            .close_on_deinit = false,
            .write_buf = buf,
            .file_writer = fw,
        };
    }

    pub fn initFileAppend(allocator: std.mem.Allocator, io: std.Io, path: []const u8, write_buf_size: usize) !Output {
        const buf = try allocator.alloc(u8, write_buf_size);
        errdefer allocator.free(buf);

        // Open the output file with `O_APPEND` and write through a streaming
        // writer so each `writev` is positioned at the live end-of-file by
        // the kernel. This is the only way to remain correct when anything
        // else mutates the output file while edge-tail is running (an operator
        // truncating it, a sibling process appending to it): a positional
        // writer seeded once from `stat().size` goes stale, leaving flushes to
        // land at that stale offset via `pwritev`, which either prepends a NUL
        // hole (after an external truncation) or overwrites externally
        // appended bytes (after a sibling append).
        //
        // `std.Io.Dir`'s `createFile`/`openFile` expose no `O_APPEND` option,
        // so the descriptor is opened directly via `std.posix.openat` against
        // the current working directory.
        const fd = try std.posix.openat(std.posix.AT.FDCWD, path, .{
            .ACCMODE = .RDWR,
            .APPEND = true,
            .CREAT = true,
            .CLOEXEC = true,
        }, 0o644);
        const file: std.Io.File = .{
            .handle = fd,
            .flags = .{ .nonblocking = false },
        };
        errdefer file.close(io);

        const fw = file.writerStreaming(io, buf);
        return .{
            .allocator = allocator,
            .io = io,
            .file = file,
            .close_on_deinit = true,
            .write_buf = buf,
            .file_writer = fw,
        };
    }

    pub fn writer(self: *Output) *std.Io.Writer {
        return &self.file_writer.interface;
    }

    pub fn flush(self: *Output) !void {
        try self.file_writer.interface.flush();
    }

    pub fn deinit(self: *Output) void {
        self.file_writer.interface.flush() catch |err| log.warn("Output.deinit: flush failed: {}", .{err});
        if (self.close_on_deinit) self.file.close(self.io);
        self.allocator.free(self.write_buf);
        self.* = undefined;
    }
};

const testing = std.testing;

test "io public API: file output writes bytes through std.Io.Writer" {
    const io = std.Options.debug_io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const path = "out.log";
    {
        const seed = try tmp.dir.createFile(io, path, .{ .truncate = true });
        defer seed.close(io);
        try seed.writeStreamingAll(io, "old\n");
    }

    const abs = try tmp.dir.realPathFileAlloc(io, path, testing.allocator);
    defer testing.allocator.free(abs);

    var out = try Output.initFileAppend(testing.allocator, io, abs, 1024);
    defer out.deinit();
    try out.writer().writeAll("new\n");
    try out.flush();

    const read_back = try tmp.dir.readFileAlloc(io, path, testing.allocator, .limited(4096));
    defer testing.allocator.free(read_back);
    try testing.expectEqualStrings("old\nnew\n", read_back);
}

test "Output.initFileAppend: external truncation between writes does not prepend a NUL hole" {
    const io = std.Options.debug_io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const path = "out.log";
    {
        const seed = try tmp.dir.createFile(io, path, .{ .truncate = true });
        defer seed.close(io);
        try seed.writeStreamingAll(io, "old\n");
    }

    const abs = try tmp.dir.realPathFileAlloc(io, path, testing.allocator);
    defer testing.allocator.free(abs);

    var out = try Output.initFileAppend(testing.allocator, io, abs, 1024);
    defer out.deinit();

    // First append lands at the initial EOF (4), yielding "old\nnew\n".
    try out.writer().writeAll("new\n");
    try out.flush();

    // Externally truncate the output file to zero in place (same inode),
    // simulating logrotate copytruncate / `: > out`.
    {
        const trunc = try tmp.dir.createFile(io, path, .{ .truncate = true });
        trunc.close(io);
    }

    // The live EOF is now 0. A true `O_APPEND` write must land the next payload
    // at 0; a stale-offset `pwritev` (seeded once from `stat().size` at startup)
    // would land "more\n" at the stale offset (8), producing an 8-byte NUL hole
    // on read-back instead of preserving the truncation.
    try out.writer().writeAll("more\n");
    try out.flush();

    const read_back = try tmp.dir.readFileAlloc(io, path, testing.allocator, .limited(4096));
    defer testing.allocator.free(read_back);

    // No NUL bytes should ever appear in the output under true append mode.
    for (read_back) |b| try testing.expect(b != 0);
    try testing.expectEqualStrings("more\n", read_back);
}

test "Output.initFileAppend: externally-appended bytes are not overwritten by this process" {
    const io = std.Options.debug_io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const path = "out.log";
    {
        const seed = try tmp.dir.createFile(io, path, .{ .truncate = true });
        seed.close(io);
    }

    const abs = try tmp.dir.realPathFileAlloc(io, path, testing.allocator);
    defer testing.allocator.free(abs);

    // Open this process's output handle against the empty file first.
    var out = try Output.initFileAppend(testing.allocator, io, abs, 1024);
    defer out.deinit();

    // Before this process flushes anything, a sibling descriptor appends "X\n"
    // to the same file. Under true `O_APPEND` this process's subsequent write
    // must land after "X\n" (yielding "X\nY\n"); a stale-offset `pwritev` would
    // land "Y\n" at the offset captured at startup (0), overwriting "X\n" and
    // yielding "Y\n".
    {
        var sibling = try Output.initFileAppend(testing.allocator, io, abs, 1024);
        defer sibling.deinit();
        try sibling.writer().writeAll("X\n");
        try sibling.flush();
    }

    try out.writer().writeAll("Y\n");
    try out.flush();

    const read_back = try tmp.dir.readFileAlloc(io, path, testing.allocator, .limited(4096));
    defer testing.allocator.free(read_back);
    try testing.expectEqualStrings("X\nY\n", read_back);
}
