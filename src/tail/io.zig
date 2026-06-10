const std = @import("std");

const log = std.log.scoped(.tail_io);

pub const InputSource = union(enum) {
    stdin,
    file: []const u8,
};

pub const OutputTarget = union(enum) {
    stdout,
    file_append: []const u8,
};

/// Reader endpoint wrapper for edge-tail.
///
/// It exposes a stable `*std.Io.Reader` interface regardless of whether the
/// source is stdin or a file on disk.
pub const Input = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    file: std.Io.File,
    close_on_deinit: bool,
    read_buf: []u8,
    file_reader: std.Io.File.Reader,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, source: InputSource, read_buf_size: usize) !Input {
        return switch (source) {
            .stdin => initStdin(allocator, io, read_buf_size),
            .file => |path| initFile(allocator, io, path, read_buf_size),
        };
    }

    pub fn initStdin(allocator: std.mem.Allocator, io: std.Io, read_buf_size: usize) !Input {
        const buf = try allocator.alloc(u8, read_buf_size);
        const file = std.Io.File.stdin();
        const fr = file.reader(io, buf);
        return .{
            .allocator = allocator,
            .io = io,
            .file = file,
            .close_on_deinit = false,
            .read_buf = buf,
            .file_reader = fr,
        };
    }

    pub fn initFile(allocator: std.mem.Allocator, io: std.Io, path: []const u8, read_buf_size: usize) !Input {
        const buf = try allocator.alloc(u8, read_buf_size);
        errdefer allocator.free(buf);

        const file = try std.Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
        errdefer file.close(io);

        const fr = file.reader(io, buf);
        return .{
            .allocator = allocator,
            .io = io,
            .file = file,
            .close_on_deinit = true,
            .read_buf = buf,
            .file_reader = fr,
        };
    }

    pub fn reader(self: *Input) *std.Io.Reader {
        return &self.file_reader.interface;
    }

    pub fn deinit(self: *Input) void {
        if (self.close_on_deinit) self.file.close(self.io);
        self.allocator.free(self.read_buf);
        self.* = undefined;
    }
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

        // Open (creating if necessary) without truncating, then position the
        // positional writer at end-of-file so writes append.
        const file = try std.Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = false });
        errdefer file.close(io);

        const end_pos: u64 = (try file.stat(io)).size;
        var fw = file.writer(io, buf);
        fw.pos = end_pos;
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
        const seed = try tmp.dir.createFile(path, .{ .truncate = true });
        defer seed.close();
        try seed.writeAll("old\n");
    }

    const abs = try tmp.dir.realpathAlloc(testing.allocator, path);
    defer testing.allocator.free(abs);

    var out = try Output.initFileAppend(testing.allocator, io, abs, 1024);
    defer out.deinit();
    try out.writer().writeAll("new\n");
    try out.flush();

    const read_back = try tmp.dir.readFileAlloc(testing.allocator, path, 4096);
    defer testing.allocator.free(read_back);
    try testing.expectEqualStrings("old\nnew\n", read_back);
}
