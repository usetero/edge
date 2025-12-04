const std = @import("std");
const Level = @import("level.zig").Level;

/// 8-byte span identifier, displayed as 16 hex characters (e.g., "00f067aa0ba902b7")
pub const SpanId = [8]u8;

/// Generate a random span ID
pub fn generateSpanId() SpanId {
    var id: SpanId = undefined;
    std.crypto.random.bytes(&id);
    return id;
}

/// Format a span ID as a 16-character hex string
pub fn formatSpanId(id: SpanId, buf: *[16]u8) []const u8 {
    const hex_chars = "0123456789abcdef";
    for (id, 0..) |byte, i| {
        buf[i * 2] = hex_chars[byte >> 4];
        buf[i * 2 + 1] = hex_chars[byte & 0x0f];
    }
    return buf[0..16];
}

/// A span represents a timed operation with a start and end.
/// Created via EventBus.started() and completed via span.completed().
pub const Span = struct {
    id: SpanId,
    name: []const u8,
    level: Level,
    start_time: i64,
    parent: ?*const Span,

    /// Generate a random span ID
    pub fn generateSpanId() SpanId {
        var id: SpanId = undefined;
        std.crypto.random.bytes(&id);
        return id;
    }

    /// Format a span ID as a 16-character hex string
    pub fn formatSpanId(id: SpanId, buf: *[16]u8) []const u8 {
        const hex_chars = "0123456789abcdef";
        for (id, 0..) |byte, i| {
            buf[i * 2] = hex_chars[byte >> 4];
            buf[i * 2 + 1] = hex_chars[byte & 0x0f];
        }
        return buf[0..16];
    }

    /// Get elapsed time in nanoseconds since span started
    pub fn elapsedNs(self: *const Span) i64 {
        const now = std.time.microTimestamp();
        return (now - self.start_time) * 1000;
    }

    /// Get elapsed time in milliseconds since span started
    pub fn elapsedMs(self: *const Span) i64 {
        return @divFloor(self.elapsedNs(), std.time.ns_per_ms);
    }

    /// Format elapsed time as a human-readable string
    pub fn formatElapsed(self: *const Span, buf: []u8) []const u8 {
        const elapsed_ns = self.elapsedNs();

        if (elapsed_ns < std.time.ns_per_ms) {
            // Microseconds
            const us = @divFloor(elapsed_ns, std.time.ns_per_us);
            return std.fmt.bufPrint(buf, "{d}µs", .{us}) catch "?";
        } else if (elapsed_ns < std.time.ns_per_s) {
            // Milliseconds
            const ms = @divFloor(elapsed_ns, std.time.ns_per_ms);
            return std.fmt.bufPrint(buf, "{d}ms", .{ms}) catch "?";
        } else {
            // Seconds with one decimal
            const ms = @divFloor(elapsed_ns, std.time.ns_per_ms);
            const secs = @divFloor(ms, 1000);
            const frac = @divFloor(@mod(ms, 1000), 100);
            return std.fmt.bufPrint(buf, "{d}.{d}s", .{ secs, frac }) catch "?";
        }
    }
};

test "Span.elapsedMs" {
    const span = Span{
        .id = .{ 0, 1, 2, 3, 4, 5, 6, 7 },
        .name = "test",
        .level = .info,
        .start_time = std.time.microTimestamp() - 100_000, // 100ms ago
        .parent = null,
    };

    const elapsed = span.elapsedMs();
    try std.testing.expect(elapsed >= 99 and elapsed <= 110);
}

test "Span.formatElapsed" {
    var buf: [32]u8 = undefined;

    // Test microseconds
    const span_us = Span{
        .id = .{ 0, 1, 2, 3, 4, 5, 6, 7 },
        .name = "test",
        .level = .info,
        .start_time = std.time.microTimestamp() - 500, // 500µs ago
        .parent = null,
    };
    const us_str = span_us.formatElapsed(&buf);
    try std.testing.expect(std.mem.endsWith(u8, us_str, "µs"));

    // Test milliseconds
    const span_ms = Span{
        .id = .{ 0, 1, 2, 3, 4, 5, 6, 7 },
        .name = "test",
        .level = .info,
        .start_time = std.time.microTimestamp() - 50_000, // 50ms ago
        .parent = null,
    };
    const ms_str = span_ms.formatElapsed(&buf);
    try std.testing.expect(std.mem.endsWith(u8, ms_str, "ms"));
}

test "Span.formatSpanId" {
    var buf: [16]u8 = undefined;
    const id: SpanId = .{ 0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7 };
    const formatted = Span.formatSpanId(id, &buf);
    try std.testing.expectEqualStrings("00f067aa0ba902b7", formatted);
}

test "Span.generateSpanId" {
    const id1 = Span.generateSpanId();
    const id2 = Span.generateSpanId();
    // IDs should be different (with extremely high probability)
    try std.testing.expect(!std.mem.eql(u8, &id1, &id2));
}
