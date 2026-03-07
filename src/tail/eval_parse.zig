const std = @import("std");
const types = @import("types.zig");
const context = @import("eval_context.zig");

pub fn parseLine(
    allocator: std.mem.Allocator,
    input_format: types.InputFormat,
    line: []const u8,
) !context.TailLineContext {
    var ctx = context.TailLineContext{ .allocator = allocator };
    switch (input_format) {
        .raw => {
            ctx.message = line;
        },
        .logfmt => {
            ctx.message = line;
            try parseLogfmtAttrs(&ctx, line);
        },
        .json => {
            ctx.message = line;
            try parseJsonAttrs(&ctx, line);
        },
    }
    return ctx;
}

pub fn parseLogfmtAttrs(ctx: *context.TailLineContext, line: []const u8) !void {
    var it = std.mem.tokenizeAny(u8, line, " \t");
    while (it.next()) |part| {
        const eq = std.mem.indexOfScalar(u8, part, '=') orelse continue;
        const key = part[0..eq];
        var value = part[eq + 1 ..];
        value = std.mem.trim(u8, value, "\"");
        const owned_key = try ctx.allocator.dupe(u8, key);
        const owned_value = try ctx.allocator.dupe(u8, value);
        try ctx.attrs.append(ctx.allocator, .{ .key = owned_key, .value = owned_value });
        if (ctx.message == null and (std.mem.eql(u8, key, "message") or std.mem.eql(u8, key, "body"))) {
            ctx.message = owned_value;
        }
        if (ctx.severity == null and (std.mem.eql(u8, key, "severity_text") or std.mem.eql(u8, key, "severity") or std.mem.eql(u8, key, "level"))) {
            ctx.severity = owned_value;
        }
    }
}

pub fn parseJsonAttrs(ctx: *context.TailLineContext, line: []const u8) !void {
    const parsed = try std.json.parseFromSliceLeaky(std.json.Value, ctx.allocator, line, .{});
    if (parsed != .object) return;

    var it = parsed.object.iterator();
    while (it.next()) |entry| {
        const key = entry.key_ptr.*;
        switch (entry.value_ptr.*) {
            .string => |s| {
                const owned_key = try ctx.allocator.dupe(u8, key);
                const owned_value = try ctx.allocator.dupe(u8, s);
                try ctx.attrs.append(ctx.allocator, .{ .key = owned_key, .value = owned_value });
                if (ctx.message == null and (std.mem.eql(u8, key, "message") or std.mem.eql(u8, key, "body"))) {
                    ctx.message = owned_value;
                }
                if (ctx.severity == null and (std.mem.eql(u8, key, "severity_text") or std.mem.eql(u8, key, "severity") or std.mem.eql(u8, key, "level"))) {
                    ctx.severity = owned_value;
                }
            },
            .object => |obj| {
                if (std.mem.eql(u8, key, "attributes")) {
                    var attr_it = obj.iterator();
                    while (attr_it.next()) |attr_entry| {
                        if (attr_entry.value_ptr.* != .string) continue;
                        const owned_key = try ctx.allocator.dupe(u8, attr_entry.key_ptr.*);
                        const owned_value = try ctx.allocator.dupe(u8, attr_entry.value_ptr.*.string);
                        try ctx.attrs.append(ctx.allocator, .{ .key = owned_key, .value = owned_value });
                    }
                }
            },
            else => {},
        }
    }
}

const testing = std.testing;

test "eval parse: raw keeps message" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const ctx = try parseLine(arena.allocator(), .raw, "hello");
    try testing.expectEqualStrings("hello", ctx.message.?);
    try testing.expect(ctx.severity == null);
}

test "eval parse: json extracts severity and attrs" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const ctx = try parseLine(
        arena.allocator(),
        .json,
        "{\"message\":\"x\",\"severity_text\":\"DEBUG\",\"attributes\":{\"ddsource\":\"nginx\"}}",
    );
    try testing.expectEqualStrings("x", ctx.message.?);
    try testing.expectEqualStrings("DEBUG", ctx.severity.?);
    try testing.expectEqual(@as(usize, 3), ctx.attrs.items.len);
}

test "eval parse: logfmt extracts severity and attrs" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const ctx = try parseLine(arena.allocator(), .logfmt, "severity_text=INFO ddsource=app msg=ok");
    try testing.expectEqualStrings("INFO", ctx.severity.?);
    try testing.expectEqual(@as(usize, 3), ctx.attrs.items.len);
}
