const std = @import("std");
const framer_mod = @import("../framer.zig");
const watch_mod = @import("../watch.zig");

pub fn processBatchScalar(
    io: std.Io,
    framer: *framer_mod.LineFramer,
    writer: *std.Io.Writer,
    events: []const watch_mod.Event,
    filter_ctx: *anyopaque,
    filter_fn: *const framer_mod.LineFramer.LineFilterFn,
) !usize {
    var processed: usize = 0;
    for (events) |evt| {
        // Isolate per-file partial-line state before reading: a batch packs
        // events for multiple different files through this one framer, so
        // without switching a partial line left in scratch by one file is
        // completed with the next file's bytes.
        const key = eventKey(evt);
        // A start_offset of 0 means the watcher reset the read position —
        // truncation-and-rewrite or rotation to a new file at the same path.
        // Discard any saved partial for this key so stale pre-rewrite bytes
        // are not concatenated onto the new file contents.
        if (evt.start_offset == 0) framer.resetStream(key);
        try framer.selectStream(key);
        try framer.readRange(io, evt.file, evt.start_offset, evt.end_offset, writer, filter_ctx, filter_fn);
        processed += 1;
    }
    return processed;
}

/// Stable per-file key for isolating framer state across a multi-file batch.
/// Uses the OS file descriptor number, which is unique per open file within
/// the process and does not change when the watcher's `files` ArrayList moves
/// entries during a `swapRemove`. Using a pointer into the ArrayList instead
/// would produce a stale key for the moved entry on every subsequent batch
/// after a file removal. Using the physical file identity (dev+ino hash)
/// instead would assign the same key to two hard-linked paths tracked as
/// separate watcher entries, causing their framer states to collide.
pub fn eventKey(evt: watch_mod.Event) u64 {
    return @bitCast(@as(i64, evt.file.handle));
}

// ============================== Tests ==============================

const testing = std.testing;

fn keepAll(_: *anyopaque, _: []const u8) !bool {
    return true;
}

/// Filter that records every record it is asked to evaluate, so a test can
/// distinguish "the filter saw this record" (the line was independently
/// framed and evaluated) from "the bytes were copied through fail-open
/// without evaluation".
const SeenList = struct {
    list: std.ArrayList([]u8) = .empty,
    allocator: std.mem.Allocator,

    fn deinit(self: *SeenList) void {
        for (self.list.items) |s| self.allocator.free(s);
        self.list.deinit(self.allocator);
        self.* = undefined;
    }

    fn filter(ctx: *anyopaque, line: []const u8) !bool {
        const self: *SeenList = @ptrCast(@alignCast(ctx));
        try self.list.append(self.allocator, try self.allocator.dupe(u8, line));
        return true;
    }
};

/// Opens a file under a tmp dir, writes `contents`, and returns an open read
/// handle plus the absolute path. Both must outlive the caller's use of the
/// handle in events. `path` keeps the `[:0]u8` sentinel so `free` accounts for
/// the null terminator `realPathFileAlloc` allocates.
const Opened = struct {
    file: std.Io.File,
    path: [:0]u8,
};

fn openTmp(io: std.Io, dir: std.Io.Dir, name: []const u8, contents: []const u8) !Opened {
    try dir.writeFile(io, .{ .sub_path = name, .data = contents });
    const path = try dir.realPathFileAlloc(io, name, testing.allocator);
    const file = try std.Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    return .{ .file = file, .path = path };
}

test "processBatchScalar: partial line from one file never merges into another" {
    const io = std.Options.debug_io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var a = try openTmp(io, tmp.dir, "a.log", "line1\npartial");
    defer {
        a.file.close(io);
        testing.allocator.free(a.path);
    }
    var b = try openTmp(io, tmp.dir, "b.log", "hello\nworld\n");
    defer {
        b.file.close(io);
        testing.allocator.free(b.path);
    }

    var framer = try framer_mod.LineFramer.init(testing.allocator, 16, 1024);
    defer framer.deinit();
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();

    const events = [_]watch_mod.Event{
        .{ .file = &a.file, .start_offset = 0, .end_offset = 13, .identity = null },
        .{ .file = &b.file, .start_offset = 0, .end_offset = 12, .identity = null },
    };

    _ = try processBatchScalar(io, &framer, &out.writer, &events, &framer, keepAll);

    // A's partial line stays buffered. B's lines are emitted alone.
    try testing.expectEqualStrings("line1\nhello\nworld\n", out.written());
    try testing.expect(std.mem.indexOf(u8, out.written(), "partialhello") == null);
    try testing.expect(std.mem.indexOf(u8, out.written(), "partial") == null);
}

test "processBatchScalar: per-file partial survives across batches (no cross-file merge, single-file continuation)" {
    const io = std.Options.debug_io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var a = try openTmp(io, tmp.dir, "a.log", "line1\npartial");
    defer {
        a.file.close(io);
        testing.allocator.free(a.path);
    }
    var b = try openTmp(io, tmp.dir, "b.log", "hello\nworld\n");
    defer {
        b.file.close(io);
        testing.allocator.free(b.path);
    }

    var framer = try framer_mod.LineFramer.init(testing.allocator, 16, 1024);
    defer framer.deinit();
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();

    // Batch 1: file_a leaves its partial line buffered, file_b is not seen.
    const batch1 = [_]watch_mod.Event{
        .{ .file = &a.file, .start_offset = 0, .end_offset = 13, .identity = null },
    };
    _ = try processBatchScalar(io, &framer, &out.writer, &batch1, &framer, keepAll);
    // No framer.finish() between batches, mirroring PollLoop.runIteration.

    // Batch 2: file_b's complete lines must NOT be completed with file_a's
    // buffered "partial".
    const batch2 = [_]watch_mod.Event{
        .{ .file = &b.file, .start_offset = 0, .end_offset = 12, .identity = null },
    };
    _ = try processBatchScalar(io, &framer, &out.writer, &batch2, &framer, keepAll);

    // Batch 3: the SAME file_a handle (therefore the same per-file key) grows
    // with the rest of the line, so the buffered "partial" is restored and the
    // logical line "partialrest" is emitted as ONE record, not two.
    {
        const f = try tmp.dir.openFile(io, "a.log", .{ .mode = .read_write });
        defer f.close(io);
        try f.writePositionalAll(io, "rest\nmore\n", 13);
    }
    const batch3 = [_]watch_mod.Event{
        .{ .file = &a.file, .start_offset = 13, .end_offset = 23, .identity = null },
    };
    _ = try processBatchScalar(io, &framer, &out.writer, &batch3, &framer, keepAll);

    try testing.expectEqualStrings("line1\nhello\nworld\npartialrest\nmore\n", out.written());
    try testing.expect(std.mem.indexOf(u8, out.written(), "partialhello") == null);
}

test "processBatchScalar: fail-open overflow from one file does not contaminate another file's record" {
    const io = std.Options.debug_io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // file_a's record exceeds max_line and has no newline: it fails open and
    // is copied through unevaluated, leaving overflowed=true in the framer.
    const partial_a = "Q" ** 40 ++ "PARTIAL"; // 47 bytes, no newline
    var a = try openTmp(io, tmp.dir, "a.log", partial_a);
    defer {
        a.file.close(io);
        testing.allocator.free(a.path);
    }
    // B's "hello" must be evaluated as its own record.
    var b = try openTmp(io, tmp.dir, "b.log", "hello\n");
    defer {
        b.file.close(io);
        testing.allocator.free(b.path);
    }

    var framer = try framer_mod.LineFramer.init(testing.allocator, 64, 32);
    defer framer.deinit();
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var seen: SeenList = .{ .allocator = testing.allocator };
    defer seen.deinit();

    const events = [_]watch_mod.Event{
        .{ .file = &a.file, .start_offset = 0, .end_offset = partial_a.len, .identity = null },
        .{ .file = &b.file, .start_offset = 0, .end_offset = 6, .identity = null },
    };

    _ = try processBatchScalar(io, &framer, &out.writer, &events, &seen, SeenList.filter);

    // file_b's "hello" was framed and evaluated independently.
    try testing.expectEqual(@as(usize, 1), seen.list.items.len);
    try testing.expectEqualStrings("hello", seen.list.items[0]);
    // file_a's fail-open bytes were forwarded verbatim (not lost).
    try testing.expect(std.mem.indexOf(u8, out.written(), "PARTIAL") != null);
}

test "processBatchScalar: single-file cross-batch line continuation is unchanged" {
    // Re-selecting the same key keeps one file's partial line across batches.
    const io = std.Options.debug_io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var one = try openTmp(io, tmp.dir, "one.log", "foo\nbar");
    defer {
        one.file.close(io);
        testing.allocator.free(one.path);
    }

    var framer = try framer_mod.LineFramer.init(testing.allocator, 16, 1024);
    defer framer.deinit();
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();

    const batch1 = [_]watch_mod.Event{
        .{ .file = &one.file, .start_offset = 0, .end_offset = 7, .identity = null },
    };
    _ = try processBatchScalar(io, &framer, &out.writer, &batch1, &framer, keepAll);

    // The same file grows; the same handle (same key) is reused so the
    // buffered "bar" is completed with "baz", not flushed or dropped.
    {
        const f = try tmp.dir.openFile(io, "one.log", .{ .mode = .read_write });
        defer f.close(io);
        try f.writePositionalAll(io, "baz\n", 7);
    }
    const batch2 = [_]watch_mod.Event{
        .{ .file = &one.file, .start_offset = 7, .end_offset = 11, .identity = null },
    };
    _ = try processBatchScalar(io, &framer, &out.writer, &batch2, &framer, keepAll);

    try testing.expectEqualStrings("foo\nbarbaz\n", out.written());
}
