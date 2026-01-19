const std = @import("std");

/// Callback function type for intercepting response body chunks.
/// Called with each chunk of data as it streams through the writer.
/// The callback can inspect, log, modify, or filter the data.
///
/// Return values:
/// - `null`: Remove/filter this chunk (don't write it to the inner writer)
/// - `data`: Pass through unchanged (return the input slice)
/// - Other slice: Replace with different content (e.g., from context's buffer)
///
/// Note: If returning a modified slice, the caller is responsible for ensuring
/// the returned slice remains valid until the write completes. Typically this
/// means storing modified data in the context struct's buffer.
pub const InterceptFn = *const fn (data: []const u8, context: ?*anyopaque) ?[]const u8;

/// Context for line-by-line printing of intercepted data
pub const LinePrinterContext = struct {
    /// Buffer to accumulate partial lines
    line_buffer: std.ArrayListUnmanaged(u8) = .{},
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) LinePrinterContext {
        return .{
            .line_buffer = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *LinePrinterContext) void {
        self.line_buffer.deinit(self.allocator);
    }

    /// Flush any remaining partial line
    pub fn flush(self: *LinePrinterContext) void {
        if (self.line_buffer.items.len > 0) {
            std.debug.print("[intercept] {s}\n", .{self.line_buffer.items});
            self.line_buffer.clearRetainingCapacity();
        }
    }
};

/// Intercept callback that prints data line by line.
/// Returns the data unchanged (pass-through) after printing.
pub fn linePrinterCallback(data: []const u8, context: ?*anyopaque) ?[]const u8 {
    const ctx: *LinePrinterContext = @ptrCast(@alignCast(context.?));

    var start: usize = 0;
    for (data, 0..) |byte, i| {
        if (byte == '\n') {
            // Found a newline - print accumulated buffer + this segment
            const segment = data[start .. i + 1];
            if (ctx.line_buffer.items.len > 0) {
                // Have buffered data - append segment and print
                ctx.line_buffer.appendSlice(ctx.allocator, segment) catch return data;
                // Print without the trailing newline for cleaner output
                const line = ctx.line_buffer.items;
                const trimmed = if (line.len > 0 and line[line.len - 1] == '\n')
                    line[0 .. line.len - 1]
                else
                    line;
                std.debug.print("[intercept] {s}\n", .{trimmed});
                ctx.line_buffer.clearRetainingCapacity();
            } else {
                // No buffered data - print segment directly
                const trimmed = if (segment.len > 0 and segment[segment.len - 1] == '\n')
                    segment[0 .. segment.len - 1]
                else
                    segment;
                std.debug.print("[intercept] {s}\n", .{trimmed});
            }
            start = i + 1;
        }
    }

    // Buffer any remaining data after the last newline
    if (start < data.len) {
        ctx.line_buffer.appendSlice(ctx.allocator, data[start..]) catch return data;
    }

    // Pass through unchanged
    return data;
}

/// A writer wrapper that intercepts data before passing it to the inner writer.
/// Useful for logging, transforming, or inspecting streaming response bodies.
///
/// The interface field must be first so @fieldParentPtr works correctly.
pub const InterceptingWriter = struct {
    /// Embedded Writer interface - MUST be first field for @fieldParentPtr
    interface: std.Io.Writer,
    inner: *std.Io.Writer,
    intercept_fn: ?InterceptFn,
    intercept_context: ?*anyopaque,

    const vtable: std.Io.Writer.VTable = .{
        .drain = drain,
        .flush = flush,
    };

    pub fn init(
        inner: *std.Io.Writer,
        buffer: []u8,
        intercept_fn: ?InterceptFn,
        intercept_context: ?*anyopaque,
    ) InterceptingWriter {
        return .{
            .interface = .{
                .vtable = &vtable,
                .buffer = buffer,
                .end = 0,
            },
            .inner = inner,
            .intercept_fn = intercept_fn,
            .intercept_context = intercept_context,
        };
    }

    /// Returns a pointer to the Writer interface.
    /// IMPORTANT: Never copy the returned Writer - always use it via pointer.
    pub fn writer(self: *InterceptingWriter) *std.Io.Writer {
        return &self.interface;
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *InterceptingWriter = @fieldParentPtr("interface", w);

        // Intercept and forward buffered data first
        const buffered = w.buffer[0..w.end];
        if (buffered.len > 0) {
            if (self.intercept_fn) |intercept| {
                // Intercept can modify or filter the data
                if (intercept(buffered, self.intercept_context)) |to_write| {
                    try self.inner.writeAll(to_write);
                }
                // If intercept returns null, data is filtered out
            } else {
                // No intercept function - pass through unchanged
                try self.inner.writeAll(buffered);
            }
        }

        // Clear our buffer since we processed it
        w.end = 0;

        // Process the data slices
        const slice = data[0..data.len -| 1]; // all but last (pattern)
        const pattern: []const u8 = if (data.len > 0) data[data.len - 1] else "";

        for (slice) |s| {
            if (self.intercept_fn) |intercept| {
                if (intercept(s, self.intercept_context)) |to_write| {
                    try self.inner.writeAll(to_write);
                }
            } else {
                try self.inner.writeAll(s);
            }
        }

        // Process the pattern repeated splat times
        for (0..splat) |_| {
            if (self.intercept_fn) |intercept| {
                if (intercept(pattern, self.intercept_context)) |to_write| {
                    try self.inner.writeAll(to_write);
                }
            } else {
                try self.inner.writeAll(pattern);
            }
        }

        // Calculate and return bytes consumed from input data (NOT including our buffer)
        // Note: We return the original input size regardless of filtering
        var written: usize = pattern.len * splat;
        for (slice) |s| {
            written += s.len;
        }
        return written;
    }

    fn flush(w: *std.Io.Writer) std.Io.Writer.Error!void {
        const self: *InterceptingWriter = @fieldParentPtr("interface", w);

        // Intercept and forward any remaining buffered data
        const buffered = w.buffer[0..w.end];
        if (buffered.len > 0) {
            if (self.intercept_fn) |intercept| {
                if (intercept(buffered, self.intercept_context)) |to_write| {
                    try self.inner.writeAll(to_write);
                }
                // If intercept returns null, data is filtered out
            } else {
                // No intercept function - pass through unchanged
                try self.inner.writeAll(buffered);
            }
            w.end = 0;
        }

        // Flush the inner writer
        try self.inner.flush();
    }
};

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;

/// Test context for tracking intercepted data
const TestInterceptContext = struct {
    chunks: std.ArrayListUnmanaged([]const u8),
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) TestInterceptContext {
        return .{
            .chunks = .{},
            .allocator = allocator,
        };
    }

    fn deinit(self: *TestInterceptContext) void {
        for (self.chunks.items) |chunk| {
            self.allocator.free(chunk);
        }
        self.chunks.deinit(self.allocator);
    }

    fn totalBytes(self: *const TestInterceptContext) usize {
        var total: usize = 0;
        for (self.chunks.items) |chunk| {
            total += chunk.len;
        }
        return total;
    }

    fn allData(self: *const TestInterceptContext, allocator: std.mem.Allocator) ![]u8 {
        var result: std.ArrayListUnmanaged(u8) = .{};
        for (self.chunks.items) |chunk| {
            try result.appendSlice(allocator, chunk);
        }
        return result.toOwnedSlice(allocator);
    }
};

fn testInterceptCallback(data: []const u8, context: ?*anyopaque) ?[]const u8 {
    const ctx: *TestInterceptContext = @ptrCast(@alignCast(context.?));
    const copy = ctx.allocator.dupe(u8, data) catch return data;
    ctx.chunks.append(ctx.allocator, copy) catch {
        ctx.allocator.free(copy);
    };
    // Pass through unchanged
    return data;
}

test "InterceptingWriter: basic write without interception" {
    var inner_writer = std.Io.Writer.Allocating.init(testing.allocator);
    defer inner_writer.deinit();

    var intercept_buffer: [256]u8 = undefined;
    var intercepting = InterceptingWriter.init(
        &inner_writer.writer,
        &intercept_buffer,
        null,
        null,
    );

    const w = intercepting.writer();
    try w.writeAll("Hello, World!");
    try w.flush();

    const result = inner_writer.writer.buffered();
    try testing.expectEqualStrings("Hello, World!", result);
}

test "InterceptingWriter: intercepts all data" {
    var inner_writer = std.Io.Writer.Allocating.init(testing.allocator);
    defer inner_writer.deinit();

    var ctx = TestInterceptContext.init(testing.allocator);
    defer ctx.deinit();

    var intercept_buffer: [256]u8 = undefined;
    var intercepting = InterceptingWriter.init(
        &inner_writer.writer,
        &intercept_buffer,
        testInterceptCallback,
        @ptrCast(&ctx),
    );

    const w = intercepting.writer();
    try w.writeAll("Hello");
    try w.writeAll(", ");
    try w.writeAll("World!");
    try w.flush();

    // Verify inner writer received all data
    const result = inner_writer.writer.buffered();
    try testing.expectEqualStrings("Hello, World!", result);

    // Verify interceptor saw all data
    const intercepted = try ctx.allData(testing.allocator);
    defer testing.allocator.free(intercepted);
    try testing.expectEqualStrings("Hello, World!", intercepted);
}

test "InterceptingWriter: handles empty writes" {
    var inner_writer = std.Io.Writer.Allocating.init(testing.allocator);
    defer inner_writer.deinit();

    var ctx = TestInterceptContext.init(testing.allocator);
    defer ctx.deinit();

    var intercept_buffer: [256]u8 = undefined;
    var intercepting = InterceptingWriter.init(
        &inner_writer.writer,
        &intercept_buffer,
        testInterceptCallback,
        @ptrCast(&ctx),
    );

    const w = intercepting.writer();
    try w.writeAll("");
    try w.writeAll("data");
    try w.writeAll("");
    try w.flush();

    const result = inner_writer.writer.buffered();
    try testing.expectEqualStrings("data", result);
}

test "InterceptingWriter: handles large data exceeding buffer" {
    var inner_writer = std.Io.Writer.Allocating.init(testing.allocator);
    defer inner_writer.deinit();

    var ctx = TestInterceptContext.init(testing.allocator);
    defer ctx.deinit();

    // Use a small buffer to force drain calls
    var intercept_buffer: [16]u8 = undefined;
    var intercepting = InterceptingWriter.init(
        &inner_writer.writer,
        &intercept_buffer,
        testInterceptCallback,
        @ptrCast(&ctx),
    );

    const w = intercepting.writer();

    // Write data larger than buffer
    const large_data = "This is a much longer string that exceeds the buffer size";
    try w.writeAll(large_data);
    try w.flush();

    const result = inner_writer.writer.buffered();
    try testing.expectEqualStrings(large_data, result);

    // Verify interceptor saw all data
    const intercepted = try ctx.allData(testing.allocator);
    defer testing.allocator.free(intercepted);
    try testing.expectEqualStrings(large_data, intercepted);
}

test "InterceptingWriter: print formatting works" {
    var inner_writer = std.Io.Writer.Allocating.init(testing.allocator);
    defer inner_writer.deinit();

    var intercept_buffer: [256]u8 = undefined;
    var intercepting = InterceptingWriter.init(
        &inner_writer.writer,
        &intercept_buffer,
        null,
        null,
    );

    const w = intercepting.writer();
    try w.print("Value: {d}, Name: {s}\n", .{ 42, "test" });
    try w.flush();

    const result = inner_writer.writer.buffered();
    try testing.expectEqualStrings("Value: 42, Name: test\n", result);
}

test "InterceptingWriter: multiple flushes are safe" {
    var inner_writer = std.Io.Writer.Allocating.init(testing.allocator);
    defer inner_writer.deinit();

    var intercept_buffer: [256]u8 = undefined;
    var intercepting = InterceptingWriter.init(
        &inner_writer.writer,
        &intercept_buffer,
        null,
        null,
    );

    const w = intercepting.writer();
    try w.writeAll("data");
    try w.flush();
    try w.flush(); // Second flush should be safe
    try w.flush(); // Third flush should be safe

    const result = inner_writer.writer.buffered();
    try testing.expectEqualStrings("data", result);
}

test "InterceptingWriter: write after flush works" {
    var inner_writer = std.Io.Writer.Allocating.init(testing.allocator);
    defer inner_writer.deinit();

    var intercept_buffer: [256]u8 = undefined;
    var intercepting = InterceptingWriter.init(
        &inner_writer.writer,
        &intercept_buffer,
        null,
        null,
    );

    const w = intercepting.writer();
    try w.writeAll("first");
    try w.flush();
    try w.writeAll("second");
    try w.flush();

    const result = inner_writer.writer.buffered();
    try testing.expectEqualStrings("firstsecond", result);
}

test "InterceptingWriter: writeByte works" {
    var inner_writer = std.Io.Writer.Allocating.init(testing.allocator);
    defer inner_writer.deinit();

    var intercept_buffer: [256]u8 = undefined;
    var intercepting = InterceptingWriter.init(
        &inner_writer.writer,
        &intercept_buffer,
        null,
        null,
    );

    const w = intercepting.writer();
    try w.writeByte('H');
    try w.writeByte('i');
    try w.flush();

    const result = inner_writer.writer.buffered();
    try testing.expectEqualStrings("Hi", result);
}

test "InterceptingWriter: works with fixed buffer inner writer" {
    var fixed_buffer: [1024]u8 = undefined;
    var fixed_writer: std.Io.Writer = .fixed(&fixed_buffer);

    var intercept_buffer: [256]u8 = undefined;
    var intercepting = InterceptingWriter.init(
        &fixed_writer,
        &intercept_buffer,
        null,
        null,
    );

    const w = intercepting.writer();
    try w.writeAll("Hello, Fixed!");
    try w.flush();

    const result = fixed_writer.buffered();
    try testing.expectEqualStrings("Hello, Fixed!", result);
}

/// Test context for filtering (removing) data
const FilterContext = struct {
    /// Pattern to filter out
    filter_pattern: []const u8,
};

fn filterCallback(data: []const u8, context: ?*anyopaque) ?[]const u8 {
    const ctx: *FilterContext = @ptrCast(@alignCast(context.?));
    // If the data contains the filter pattern, remove it entirely
    if (std.mem.indexOf(u8, data, ctx.filter_pattern) != null) {
        return null; // Filter out this chunk
    }
    return data; // Pass through unchanged
}

test "InterceptingWriter: filter removes matching data" {
    var inner_writer = std.Io.Writer.Allocating.init(testing.allocator);
    defer inner_writer.deinit();

    var ctx = FilterContext{ .filter_pattern = "SECRET" };

    var intercept_buffer: [256]u8 = undefined;
    var intercepting = InterceptingWriter.init(
        &inner_writer.writer,
        &intercept_buffer,
        filterCallback,
        @ptrCast(&ctx),
    );

    const w = intercepting.writer();
    try w.writeAll("public data");
    try w.flush();
    try w.writeAll("SECRET_KEY=abc123");
    try w.flush();
    try w.writeAll("more public");
    try w.flush();

    const result = inner_writer.writer.buffered();
    // The SECRET line should be filtered out
    try testing.expectEqualStrings("public datamore public", result);
}

/// Test context for modifying data
const ModifyContext = struct {
    /// Buffer to hold modified data
    modified_buffer: [256]u8 = undefined,
    /// Length of modified data
    modified_len: usize = 0,

    fn setModified(self: *ModifyContext, data: []const u8) []const u8 {
        @memcpy(self.modified_buffer[0..data.len], data);
        self.modified_len = data.len;
        return self.modified_buffer[0..self.modified_len];
    }
};

fn modifyCallback(data: []const u8, context: ?*anyopaque) ?[]const u8 {
    const ctx: *ModifyContext = @ptrCast(@alignCast(context.?));

    // Replace "foo" with "bar" if found
    if (std.mem.indexOf(u8, data, "foo")) |_| {
        // Simple replacement for test - copy and modify
        var i: usize = 0;
        var j: usize = 0;
        while (i < data.len) {
            if (i + 3 <= data.len and std.mem.eql(u8, data[i .. i + 3], "foo")) {
                ctx.modified_buffer[j] = 'b';
                ctx.modified_buffer[j + 1] = 'a';
                ctx.modified_buffer[j + 2] = 'r';
                i += 3;
                j += 3;
            } else {
                ctx.modified_buffer[j] = data[i];
                i += 1;
                j += 1;
            }
        }
        ctx.modified_len = j;
        return ctx.modified_buffer[0..ctx.modified_len];
    }
    return data; // Pass through unchanged
}

test "InterceptingWriter: modify changes data content" {
    var inner_writer = std.Io.Writer.Allocating.init(testing.allocator);
    defer inner_writer.deinit();

    var ctx = ModifyContext{};

    var intercept_buffer: [256]u8 = undefined;
    var intercepting = InterceptingWriter.init(
        &inner_writer.writer,
        &intercept_buffer,
        modifyCallback,
        @ptrCast(&ctx),
    );

    const w = intercepting.writer();
    try w.writeAll("foo is great");
    try w.flush();

    const result = inner_writer.writer.buffered();
    try testing.expectEqualStrings("bar is great", result);
}

test "InterceptingWriter: modify with multiple replacements" {
    var inner_writer = std.Io.Writer.Allocating.init(testing.allocator);
    defer inner_writer.deinit();

    var ctx = ModifyContext{};

    var intercept_buffer: [256]u8 = undefined;
    var intercepting = InterceptingWriter.init(
        &inner_writer.writer,
        &intercept_buffer,
        modifyCallback,
        @ptrCast(&ctx),
    );

    const w = intercepting.writer();
    try w.writeAll("foo and foo");
    try w.flush();

    const result = inner_writer.writer.buffered();
    try testing.expectEqualStrings("bar and bar", result);
}
