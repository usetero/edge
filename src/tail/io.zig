const std = @import("std");

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
    file: std.fs.File,
    close_on_deinit: bool,
    read_buf: []u8,
    file_reader: std.fs.File.Reader,

    pub fn init(allocator: std.mem.Allocator, source: InputSource, read_buf_size: usize) !Input {
        return switch (source) {
            .stdin => initStdin(allocator, read_buf_size),
            .file => |path| initFile(allocator, path, read_buf_size),
        };
    }

    pub fn initStdin(allocator: std.mem.Allocator, read_buf_size: usize) !Input {
        const buf = try allocator.alloc(u8, read_buf_size);
        const file = std.fs.File.stdin();
        const fr = file.reader(buf);
        return .{
            .allocator = allocator,
            .file = file,
            .close_on_deinit = false,
            .read_buf = buf,
            .file_reader = fr,
        };
    }

    pub fn initFile(allocator: std.mem.Allocator, path: []const u8, read_buf_size: usize) !Input {
        const buf = try allocator.alloc(u8, read_buf_size);
        errdefer allocator.free(buf);

        const file = try std.fs.cwd().openFile(path, .{ .mode = .read_only });
        errdefer file.close();

        const fr = file.reader(buf);
        return .{
            .allocator = allocator,
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
        if (self.close_on_deinit) self.file.close();
        self.allocator.free(self.read_buf);
    }
};

/// Writer endpoint wrapper for edge-tail.
///
/// This enforces append-safe file behavior while still exposing
/// `*std.Io.Writer` so callers can stay interface-driven.
pub const Output = struct {
    allocator: std.mem.Allocator,
    file: std.fs.File,
    close_on_deinit: bool,
    write_buf: []u8,
    file_writer: std.fs.File.Writer,

    pub fn init(allocator: std.mem.Allocator, target: OutputTarget, write_buf_size: usize) !Output {
        return switch (target) {
            .stdout => initStdout(allocator, write_buf_size),
            .file_append => |path| initFileAppend(allocator, path, write_buf_size),
        };
    }

    pub fn initStdout(allocator: std.mem.Allocator, write_buf_size: usize) !Output {
        const buf = try allocator.alloc(u8, write_buf_size);
        const file = std.fs.File.stdout();
        const fw = file.writerStreaming(buf);
        return .{
            .allocator = allocator,
            .file = file,
            .close_on_deinit = false,
            .write_buf = buf,
            .file_writer = fw,
        };
    }

    pub fn initFileAppend(allocator: std.mem.Allocator, path: []const u8, write_buf_size: usize) !Output {
        const buf = try allocator.alloc(u8, write_buf_size);
        errdefer allocator.free(buf);

        // Use O_APPEND so each write is appended atomically from the kernel's
        // perspective without relying on mutable seek position.
        const fd = try std.posix.open(path, .{
            .ACCMODE = .WRONLY,
            .APPEND = true,
            .CREAT = true,
            .CLOEXEC = true,
        }, 0o644);
        errdefer std.posix.close(fd);
        const file = std.fs.File{ .handle = fd };

        const fw = file.writerStreaming(buf);
        return .{
            .allocator = allocator,
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
        self.file_writer.interface.flush() catch {};
        if (self.close_on_deinit) self.file.close();
        self.allocator.free(self.write_buf);
    }
};

const testing = std.testing;

test "io public API: file output writes bytes through std.Io.Writer" {
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

    var out = try Output.initFileAppend(testing.allocator, abs, 1024);
    defer out.deinit();
    try out.writer().writeAll("new\n");
    try out.flush();

    const read_back = try tmp.dir.readFileAlloc(testing.allocator, path, 4096);
    defer testing.allocator.free(read_back);
    try testing.expectEqualStrings("old\nnew\n", read_back);
}
