//! Preserve opaque top-level envelope fields around transformed OTLP resources.
const std = @import("std");

/// Serializers know resource fields but older schemas may not know newly added
/// envelope fields. Copy those from the original without evaluating them.
pub fn json(allocator: std.mem.Allocator, original: []const u8, candidate: []const u8, writer: *std.Io.Writer) !void {
    var before = try std.json.parseFromSlice(std.json.Value, allocator, original, .{ .allocate = .alloc_if_needed, .parse_numbers = false });
    defer before.deinit();
    var after = try std.json.parseFromSlice(std.json.Value, allocator, candidate, .{ .allocate = .alloc_if_needed, .parse_numbers = false });
    defer after.deinit();
    if (before.value != .object or after.value != .object) return error.InvalidEnvelope;
    var output: std.json.Stringify = .{ .writer = writer };
    try output.beginObject();
    var fields = after.value.object.iterator();
    while (fields.next()) |field| {
        try output.objectField(field.key_ptr.*);
        try output.write(field.value_ptr.*);
    }
    fields = before.value.object.iterator();
    while (fields.next()) |field| {
        const key = field.key_ptr.*;
        if (after.value.object.contains(key) or resourceField(key)) continue;
        try output.objectField(key);
        try output.write(field.value_ptr.*);
    }
    try output.endObject();
}

fn resourceField(key: []const u8) bool {
    const names = [_][]const u8{
        "resourceLogs", "resource_logs", "resourceMetrics", "resource_metrics", "resourceSpans", "resource_spans",
    };
    for (names) |name| if (std.mem.eql(u8, name, key)) return true;
    return false;
}

/// OTLP exports use repeated field 1 for resource messages. Retain every other
/// top-level field byte-for-byte, including unknown length-delimited payloads.
pub fn protobuf(original: []const u8, candidate: []const u8, writer: *std.Io.Writer) !void {
    try writer.writeAll(candidate);
    var position: usize = 0;
    while (position < original.len) {
        const start = position;
        const tag = try varint(original, &position);
        if (tag >> 3 == 0 or tag >> 3 > 0x1fffffff) return error.InvalidTag;
        switch (@as(u3, @truncate(tag))) {
            0 => _ = try varint(original, &position),
            1 => try skip(original, &position, 8),
            2 => {
                const length = try varint(original, &position);
                try skip(original, &position, length);
            },
            5 => try skip(original, &position, 4),
            else => return error.UnsupportedWireType,
        }
        if (tag >> 3 != 1) try writer.writeAll(original[start..position]);
    }
}

fn varint(bytes: []const u8, position: *usize) !u64 {
    var value: u64 = 0;
    for (0..10) |index| {
        if (position.* == bytes.len) return error.Truncated;
        const byte = bytes[position.*];
        position.* += 1;
        if (index == 9 and byte > 1) return error.Overflow;
        value |= @as(u64, byte & 127) << @as(u6, @intCast(index * 7));
        if (byte & 128 == 0) return value;
    }
    return error.Overflow;
}

fn skip(bytes: []const u8, position: *usize, count: u64) !void {
    if (count > bytes.len - position.*) return error.Truncated;
    position.* += @intCast(count);
}

test "v2 envelope retains unknown JSON values and protobuf wire fields" {
    var bytes: [256]u8 = undefined;
    var output: std.Io.Writer = .fixed(&bytes);
    try json(std.testing.allocator, "{\"resourceLogs\":[{}],\"future\":{\"x\":42}}", "{\"resourceLogs\":[]}", &output);
    try std.testing.expectEqualStrings("{\"resourceLogs\":[],\"future\":{\"x\":42}}", output.buffered());
    output = .fixed(&bytes);
    try protobuf("\x0a\x00\x12\x03abc\x18\x96\x01", "\x0a\x00", &output);
    try std.testing.expectEqualStrings("\x0a\x00\x12\x03abc\x18\x96\x01", output.buffered());
    try std.testing.expectError(error.Truncated, protobuf("\x12\x03a", "", &output));
}
