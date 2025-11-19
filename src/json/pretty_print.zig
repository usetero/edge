const std = @import("std");

// prettyPrint prints a JSON value to the given writer in a pretty format. It is up to the caller to flush the writer.
pub fn prettyPrint(writer: *std.io.Writer, json_text: []const u8, allocator: std.mem.Allocator) !void {
    // Parse JSON
    const parsed = std.json.parseFromSlice(
        std.json.Value,
        allocator,
        json_text,
        .{},
    ) catch |err| {
        // If parsing fails, just write the raw text
        try writer.writeAll(json_text);
        return err;
    };
    defer parsed.deinit();

    // Pretty print the value
    try printValue(writer, parsed.value, 0);
    try writer.writeAll("\n");
    // try writer.flush();
}

fn printValue(writer: anytype, value: std.json.Value, indent: usize) anyerror!void {
    switch (value) {
        .null => try writer.writeAll("null"),
        .bool => |b| try writer.writeAll(if (b) "true" else "false"),
        .integer => |i| try writer.print("{d}", .{i}),
        .float => |f| try writer.print("{d}", .{f}),
        .number_string => |s| try writer.writeAll(s),
        .string => |s| {
            try writer.writeAll("\"");
            try writeEscapedString(writer, s);
            try writer.writeAll("\"");
        },
        .array => |arr| {
            if (arr.items.len == 0) {
                try writer.writeAll("[]");
                return;
            }

            try writer.writeAll("[\n");
            for (arr.items, 0..) |item, i| {
                try writeIndent(writer, indent + 2);
                try printValue(writer, item, indent + 2);
                if (i < arr.items.len - 1) {
                    try writer.writeAll(",");
                }
                try writer.writeAll("\n");
            }
            try writeIndent(writer, indent);
            try writer.writeAll("]");
        },
        .object => |obj| {
            if (obj.count() == 0) {
                try writer.writeAll("{}");
                return;
            }

            try writer.writeAll("{\n");
            var iter = obj.iterator();
            var i: usize = 0;
            const count = obj.count();
            while (iter.next()) |entry| : (i += 1) {
                try writeIndent(writer, indent + 2);
                try writer.writeAll("\"");
                try writeEscapedString(writer, entry.key_ptr.*);
                try writer.writeAll("\": ");
                try printValue(writer, entry.value_ptr.*, indent + 2);
                if (i < count - 1) {
                    try writer.writeAll(",");
                }
                try writer.writeAll("\n");
            }
            try writeIndent(writer, indent);
            try writer.writeAll("}");
        },
    }
}

fn writeIndent(writer: anytype, indent: usize) !void {
    var i: usize = 0;
    while (i < indent) : (i += 1) {
        try writer.writeAll(" ");
    }
}

fn writeEscapedString(writer: anytype, s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => try writer.writeByte(c),
        }
    }
}

test "prettyPrint - simple object" {
    const json = "{\"name\":\"Alice\",\"age\":30}";

    var buffer: [512]u8 = undefined;
    var bufferedWriter = std.io.Writer.fixed(&buffer);
    try prettyPrint(&bufferedWriter, json, std.testing.allocator);
    try bufferedWriter.flush();
    const expected =
        \\{
        \\  "name": "Alice",
        \\  "age": 30
        \\}
        \\
    ;
    try std.testing.expectEqualStrings(expected, &buffer);
}

test "prettyPrint - nested object" {
    const json = "{\"user\":{\"name\":\"Bob\"},\"active\":true}";

    var buffer: [512]u8 = undefined;
    var bufferedWriter = std.io.Writer.fixed(&buffer);
    try prettyPrint(&bufferedWriter, json, std.testing.allocator);
    try bufferedWriter.flush();
    const expected =
        \\{
        \\  "user": {
        \\    "name": "Bob"
        \\  },
        \\  "active": true
        \\}
        \\
    ;
    try std.testing.expectEqualStrings(expected, &buffer);
}
