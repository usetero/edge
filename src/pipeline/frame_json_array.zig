//! Top-level JSON array framer: each array element is one record (the
//! Datadog logs intake body shape, `[ {...}, {...} ]`).
//!
//! Output is re-emitted canonically — `[` + kept elements joined by `,` + `]`
//! — which is semantically identical JSON; byte-identity is not preserved
//! (inter-element whitespace is dropped). Element boundaries are found with a
//! depth/string state machine, so nested arrays, objects, and bracket
//! characters inside strings are handled without parsing values.
//!
//! Failure semantics (PLAN.md §6.5): an element larger than scratch streams
//! through verbatim without evaluation (fail-open); structurally invalid
//! input flips to desync, copying the remainder of the stream verbatim. The
//! framer never drops bytes on its own.
const std = @import("std");
const framer_mod = @import("framer.zig");

pub const JsonArrayFramer = struct {
    scratch: []u8,
    scratch_len: usize = 0,
    state: State = .expect_array_start,
    /// JSON container depth within the current element ('{'/'[' nesting).
    depth: u32 = 0,
    in_string: bool = false,
    escaped: bool = false,
    /// Current element outgrew scratch and is streaming verbatim.
    overflowed: bool = false,
    /// Start (within the current ingest chunk) of element bytes not yet copied
    /// to scratch or emitted. Enables zero-copy framing: an element contained
    /// in a single chunk is handed to the sink as a direct chunk slice, and
    /// cross-chunk elements are bulk-copied one run per boundary, never per byte.
    run_start: usize = 0,
    /// '[' has been written to the output.
    wrote_open: bool = false,
    /// At least one element was written (controls comma placement).
    emitted_any: bool = false,
    stats: framer_mod.Stats = .{},

    const State = enum {
        expect_array_start,
        expect_element_or_end,
        in_element,
        done,
        desync,
    };

    pub fn init(scratch: []u8) JsonArrayFramer {
        return .{ .scratch = scratch };
    }

    pub fn ingest(self: *JsonArrayFramer, chunk: []const u8, out: *std.Io.Writer, sink: anytype) !void {
        // A continued element (carried from a previous chunk) resumes at byte 0.
        self.run_start = 0;
        var i: usize = 0;
        while (i < chunk.len) {
            switch (self.state) {
                .expect_array_start => {
                    const byte = chunk[i];
                    i += 1;
                    if (isJsonWhitespace(byte)) continue;
                    if (byte == '[') {
                        self.state = .expect_element_or_end;
                        continue;
                    }
                    // Not an array body: copy everything (including this
                    // byte) through verbatim. Leading whitespace already
                    // consumed is dropped — insignificant in JSON.
                    try self.enterDesync(out, chunk[i - 1 ..]);
                    return;
                },
                .expect_element_or_end => {
                    const byte = chunk[i];
                    i += 1;
                    if (isJsonWhitespace(byte)) continue;
                    if (byte == ']') {
                        self.state = .done;
                        continue;
                    }
                    if (byte == ',') {
                        try self.enterDesync(out, chunk[i - 1 ..]);
                        return;
                    }
                    // First element byte: rewind, mark the element start, and let
                    // the in_element state track '{'/'['/'"' structure.
                    self.state = .in_element;
                    self.depth = 0;
                    self.in_string = false;
                    self.escaped = false;
                    self.overflowed = false;
                    i -= 1;
                    self.run_start = i;
                    continue;
                },
                .in_element => {
                    // Pure register state machine: scan for the depth-0 element
                    // terminator without touching memory per byte. Bytes are
                    // materialized (bulk-copied or emitted) only at run
                    // boundaries — a terminator or the end of the chunk.
                    while (i < chunk.len) {
                        const byte = chunk[i];
                        i += 1;
                        if (self.in_string) {
                            if (self.escaped) {
                                self.escaped = false;
                            } else if (byte == '\\') {
                                self.escaped = true;
                            } else if (byte == '"') {
                                self.in_string = false;
                            }
                            continue;
                        }
                        switch (byte) {
                            '"' => self.in_string = true,
                            '{', '[' => self.depth += 1,
                            '}' => {
                                if (self.depth == 0) {
                                    try self.enterDesyncInElement(out, chunk);
                                    return;
                                }
                                self.depth -= 1;
                            },
                            ']' => {
                                if (self.depth == 0) {
                                    try self.emitElement(chunk, i - 1, out, sink);
                                    self.state = .done;
                                    break;
                                }
                                self.depth -= 1;
                            },
                            ',' => {
                                if (self.depth == 0) {
                                    try self.emitElement(chunk, i - 1, out, sink);
                                    self.state = .expect_element_or_end;
                                    break;
                                }
                            },
                            else => {},
                        }
                    } else {
                        // Chunk ended mid-element: preserve this run (and any
                        // spilled prefix) in scratch for the next chunk.
                        try self.bufferElement(chunk[self.run_start..], out);
                        return;
                    }
                    continue;
                },
                .done => {
                    const byte = chunk[i];
                    i += 1;
                    if (isJsonWhitespace(byte)) continue;
                    try self.enterDesync(out, chunk[i - 1 ..]);
                    return;
                },
                .desync => {
                    try out.writeAll(chunk[i..]);
                    return;
                },
            }
        }
    }

    pub fn finish(self: *JsonArrayFramer, out: *std.Io.Writer, sink: anytype) !void {
        switch (self.state) {
            .expect_array_start => {
                // Empty or whitespace-only body: emit nothing.
            },
            .in_element => {
                // Truncated input mid-element. Flush unevaluated bytes so
                // nothing is lost, close the array best-effort, and record
                // the desync. The sink never sees a truncated element.
                if (self.overflowed) {
                    self.overflowed = false;
                    self.stats.failed_open += 1;
                } else if (self.scratch_len > 0) {
                    try self.writeSeparator(out);
                    try out.writeAll(self.scratch[0..self.scratch_len]);
                    self.scratch_len = 0;
                    self.stats.failed_open += 1;
                }
                try self.writeClose(out);
                self.stats.desynced = true;
            },
            .expect_element_or_end => {
                // Truncated after '[' or ','; close best-effort.
                try self.writeClose(out);
                self.stats.desynced = true;
            },
            .done => try self.writeClose(out),
            .desync => {},
        }
        _ = sink;
    }

    /// Appends an element run to scratch. When the element outgrows scratch it
    /// fails open (PLAN §6.5): the buffered prefix and this run are emitted
    /// verbatim and the rest of the element streams unevaluated.
    fn bufferElement(self: *JsonArrayFramer, run: []const u8, out: *std.Io.Writer) !void {
        if (self.overflowed) {
            try out.writeAll(run);
            return;
        }
        if (self.scratch_len + run.len <= self.scratch.len) {
            @memcpy(self.scratch[self.scratch_len..][0..run.len], run);
            self.scratch_len += run.len;
            return;
        }
        try self.writeSeparator(out);
        try out.writeAll(self.scratch[0..self.scratch_len]);
        try out.writeAll(run);
        self.scratch_len = 0;
        self.overflowed = true;
    }

    /// Finalizes the element ending at `end` (exclusive) in `chunk`: evaluates
    /// it through the sink and emits the verdict. Zero-copy when the whole
    /// element lives in this chunk; falls back to scratch across chunk
    /// boundaries; forwards verbatim (unevaluated) when it exceeds the scratch
    /// bound, matching the byte-at-a-time fail-open behavior it replaces.
    fn emitElement(
        self: *JsonArrayFramer,
        chunk: []const u8,
        end: usize,
        out: *std.Io.Writer,
        sink: anytype,
    ) !void {
        if (self.overflowed) {
            // Prefix already on the wire; flush the verbatim tail, fail open.
            try out.writeAll(chunk[self.run_start..end]);
            self.overflowed = false;
            self.scratch_len = 0;
            self.stats.failed_open += 1;
            return;
        }

        var record: []const u8 = undefined;
        if (self.scratch_len == 0) {
            const elem = chunk[self.run_start..end];
            if (elem.len > self.scratch.len) {
                // Too large to evaluate within the record-scratch bound: the
                // sink never sees it — forward verbatim.
                try self.writeSeparator(out);
                try out.writeAll(elem);
                self.stats.failed_open += 1;
                return;
            }
            record = elem; // zero-copy: element contained in this chunk
        } else {
            // Spanned chunks: append this chunk's tail, evaluate from scratch.
            try self.bufferElement(chunk[self.run_start..end], out);
            if (self.overflowed) {
                self.overflowed = false;
                self.scratch_len = 0;
                self.stats.failed_open += 1;
                return;
            }
            record = self.scratch[0..self.scratch_len];
        }

        record = std.mem.trimEnd(u8, record, " \t\r\n");
        self.scratch_len = 0;
        self.stats.records += 1;
        switch (try sink.onRecord(record)) {
            .keep => {
                self.stats.kept += 1;
                try self.writeSeparator(out);
                try out.writeAll(record);
            },
            .drop => self.stats.dropped += 1,
            .replace => |bytes| {
                self.stats.replaced += 1;
                try self.writeSeparator(out);
                try out.writeAll(bytes);
            },
        }
    }

    /// Writes '[' on first emission, ',' before every subsequent one.
    fn writeSeparator(self: *JsonArrayFramer, out: *std.Io.Writer) !void {
        if (!self.wrote_open) {
            try out.writeByte('[');
            self.wrote_open = true;
        } else if (self.emitted_any) {
            try out.writeByte(',');
        }
        self.emitted_any = true;
    }

    fn writeClose(self: *JsonArrayFramer, out: *std.Io.Writer) !void {
        if (!self.wrote_open) {
            try out.writeByte('[');
            self.wrote_open = true;
        }
        try out.writeByte(']');
    }

    /// Flushes any buffered element bytes plus `rest` verbatim and copies all
    /// future input through untouched. Output may be syntactically broken;
    /// PLAN §6.5.2 prefers data fidelity over syntax once framing is lost.
    fn enterDesync(self: *JsonArrayFramer, out: *std.Io.Writer, rest: []const u8) !void {
        if (self.scratch_len > 0) {
            try out.writeAll(self.scratch[0..self.scratch_len]);
            self.scratch_len = 0;
        }
        try out.writeAll(rest);
        self.state = .desync;
        self.stats.desynced = true;
    }

    /// Desync triggered mid-element: flush the element bytes seen so far (any
    /// spilled prefix plus this chunk's run) and the rest of the chunk
    /// verbatim, then copy all future input through untouched.
    fn enterDesyncInElement(self: *JsonArrayFramer, out: *std.Io.Writer, chunk: []const u8) !void {
        if (!self.overflowed and self.scratch_len > 0) {
            try out.writeAll(self.scratch[0..self.scratch_len]);
        }
        self.scratch_len = 0;
        self.overflowed = false;
        try out.writeAll(chunk[self.run_start..]);
        self.state = .desync;
        self.stats.desynced = true;
    }

    fn isJsonWhitespace(byte: u8) bool {
        return byte == ' ' or byte == '\t' or byte == '\n' or byte == '\r';
    }
};

// ============================== Tests ==============================

const testing = std.testing;

const TestSink = struct {
    seen: std.ArrayList([]u8) = .empty,
    allocator: std.mem.Allocator,
    replacement: []const u8 = "{\"swapped\":true}",

    fn deinit(self: *TestSink) void {
        for (self.seen.items) |record| self.allocator.free(record);
        self.seen.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn onRecord(self: *TestSink, bytes: []const u8) !framer_mod.Decision {
        try self.seen.append(self.allocator, try self.allocator.dupe(u8, bytes));
        if (std.mem.indexOf(u8, bytes, "drop") != null) return .drop;
        if (std.mem.indexOf(u8, bytes, "swap") != null) return .{ .replace = self.replacement };
        return .keep;
    }
};

fn runChunked(input: []const u8, chunk_len: usize, scratch_len: usize, sink: *TestSink) ![]u8 {
    const scratch = try testing.allocator.alloc(u8, scratch_len);
    defer testing.allocator.free(scratch);
    var framer: JsonArrayFramer = .init(scratch);

    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    errdefer out.deinit();

    var offset: usize = 0;
    while (offset < input.len) {
        const end = @min(offset + chunk_len, input.len);
        try framer.ingest(input[offset..end], &out.writer, sink);
        offset = end;
    }
    try framer.finish(&out.writer, sink);
    return out.toOwnedSlice();
}

test "keep-all re-emits canonical array across chunk sizes" {
    const input = "[ {\"a\":1} ,\n  {\"b\":[1,2,{\"c\":3}]} , \"plain\" , 42 ]";
    const expected = "[{\"a\":1},{\"b\":[1,2,{\"c\":3}]},\"plain\",42]";
    for ([_]usize{ 1, 7, 4096 }) |chunk| {
        var sink: TestSink = .{ .allocator = testing.allocator };
        defer sink.deinit();
        const got = try runChunked(input, chunk, 128, &sink);
        defer testing.allocator.free(got);
        try testing.expectEqualStrings(expected, got);
        try testing.expectEqual(@as(usize, 4), sink.seen.items.len);
    }
}

test "brackets and escapes inside strings do not break framing" {
    const input =
        \\[{"msg":"a ] b , c [ d"},{"esc":"quote \" and slash \\"}]
    ;
    var sink: TestSink = .{ .allocator = testing.allocator };
    defer sink.deinit();
    const got = try runChunked(input, 3, 128, &sink);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(input, got);
    try testing.expectEqual(@as(usize, 2), sink.seen.items.len);
}

test "drop removes element and separator" {
    const input = "[{\"k\":1},{\"x\":\"drop\"},{\"k\":2}]";
    for ([_]usize{ 1, 7, 4096 }) |chunk| {
        var sink: TestSink = .{ .allocator = testing.allocator };
        defer sink.deinit();
        const got = try runChunked(input, chunk, 128, &sink);
        defer testing.allocator.free(got);
        try testing.expectEqualStrings("[{\"k\":1},{\"k\":2}]", got);
    }
}

test "dropping every element yields empty array" {
    const input = "[{\"x\":\"drop\"},{\"y\":\"drop\"}]";
    var sink: TestSink = .{ .allocator = testing.allocator };
    defer sink.deinit();
    const got = try runChunked(input, 7, 128, &sink);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("[]", got);
}

test "replace substitutes element" {
    const input = "[1,{\"x\":\"swap\"},3]";
    var sink: TestSink = .{ .allocator = testing.allocator };
    defer sink.deinit();
    const got = try runChunked(input, 5, 128, &sink);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("[1,{\"swapped\":true},3]", got);
}

test "empty array and whitespace-only inputs" {
    {
        var sink: TestSink = .{ .allocator = testing.allocator };
        defer sink.deinit();
        const got = try runChunked("[]", 1, 16, &sink);
        defer testing.allocator.free(got);
        try testing.expectEqualStrings("[]", got);
    }
    {
        var sink: TestSink = .{ .allocator = testing.allocator };
        defer sink.deinit();
        const got = try runChunked("  \n ", 1, 16, &sink);
        defer testing.allocator.free(got);
        try testing.expectEqualStrings("", got);
    }
}

test "oversized element fails open without evaluation" {
    // Element bigger than scratch contains "drop" — must pass through.
    const big = "{\"pad\":\"" ++ "p" ** 64 ++ "drop\"}";
    const input = "[{\"a\":1}," ++ big ++ ",{\"b\":2}]";
    for ([_]usize{ 1, 7, 4096 }) |chunk| {
        var sink: TestSink = .{ .allocator = testing.allocator };
        defer sink.deinit();
        const got = try runChunked(input, chunk, 32, &sink);
        defer testing.allocator.free(got);
        try testing.expectEqualStrings(input, got);
        try testing.expectEqual(@as(usize, 2), sink.seen.items.len);
    }
}

test "non-array body desyncs to verbatim copy" {
    const input = "{\"single\":\"object with drop\"}";
    var sink: TestSink = .{ .allocator = testing.allocator };
    defer sink.deinit();
    const got = try runChunked(input, 7, 64, &sink);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(input, got);
    try testing.expectEqual(@as(usize, 0), sink.seen.items.len);
}

test "truncated input flushes buffered bytes and closes best-effort" {
    const input = "[{\"a\":1},{\"b\":"; // cut mid-element
    var sink: TestSink = .{ .allocator = testing.allocator };
    defer sink.deinit();
    const got = try runChunked(input, 4, 64, &sink);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("[{\"a\":1},{\"b\":]", got);
}

test "stats are accounted" {
    const input = "[1,\"drop\",\"swap\",2]";
    var sink: TestSink = .{ .allocator = testing.allocator };
    defer sink.deinit();
    const scratch = try testing.allocator.alloc(u8, 64);
    defer testing.allocator.free(scratch);
    var framer: JsonArrayFramer = .init(scratch);
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try framer.ingest(input, &out.writer, &sink);
    try framer.finish(&out.writer, &sink);

    try testing.expectEqual(@as(u64, 4), framer.stats.records);
    try testing.expectEqual(@as(u64, 2), framer.stats.kept);
    try testing.expectEqual(@as(u64, 1), framer.stats.dropped);
    try testing.expectEqual(@as(u64, 1), framer.stats.replaced);
    try testing.expectEqual(false, framer.stats.desynced);
}
