const std = @import("std");
const types = @import("types.zig");
const context = @import("eval_context.zig");

pub fn parseLine(
    allocator: std.mem.Allocator,
    input_format: types.InputFormat,
    line: []const u8,
) !context.TailLineContext {
    var ctx: context.TailLineContext = .{ .allocator = allocator };
    switch (input_format) {
        .raw => {
            ctx.message = line;
        },
        // Structured formats: the parsers extract message/body when present
        // (their `ctx.message == null` guard requires running them first);
        // the raw line is only the fallback.
        .logfmt => {
            try parseLogfmtAttrs(&ctx, line);
            if (ctx.message == null) ctx.message = line;
        },
        .json => {
            try parseJsonAttrs(&ctx, line);
            if (ctx.message == null) ctx.message = line;
        },
    }
    return ctx;
}

/// Copy `key` and `value` into the line arena and append them as an attribute.
/// Returns the owned value.
fn appendAttr(ctx: *context.TailLineContext, key: []const u8, value: []const u8) ![]const u8 {
    const owned_key = try ctx.allocator.dupe(u8, key);
    const owned_value = try ctx.allocator.dupe(u8, value);
    try ctx.attrs.append(ctx.allocator, .{ .key = owned_key, .value = owned_value });
    return owned_value;
}

/// Use the first message or severity key as the line message or severity.
fn noteWellKnown(ctx: *context.TailLineContext, key: []const u8, owned_value: []const u8) void {
    if (ctx.message == null and (std.mem.eql(u8, key, "message") or std.mem.eql(u8, key, "body"))) {
        ctx.message = owned_value;
    }
    const is_severity_key = std.mem.eql(u8, key, "severity_text") or
        std.mem.eql(u8, key, "severity") or
        std.mem.eql(u8, key, "level");
    if (ctx.severity == null and is_severity_key) {
        ctx.severity = owned_value;
    }
}

fn parseLogfmtAttrs(ctx: *context.TailLineContext, line: []const u8) !void {
    var it = std.mem.tokenizeAny(u8, line, " \t");
    while (it.next()) |part| {
        const eq = std.mem.indexOfScalar(u8, part, '=') orelse continue;
        const key = part[0..eq];
        const value = std.mem.trim(u8, part[eq + 1 ..], "\"");
        noteWellKnown(ctx, key, try appendAttr(ctx, key, value));
    }
}

fn parseJsonAttrs(ctx: *context.TailLineContext, line: []const u8) !void {
    const parsed = std.json.parseFromSliceLeaky(std.json.Value, ctx.allocator, line, .{}) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return,
    };
    if (parsed != .object) return;

    var it = parsed.object.iterator();
    while (it.next()) |entry| {
        const key = entry.key_ptr.*;
        switch (entry.value_ptr.*) {
            .string => |s| noteWellKnown(ctx, key, try appendAttr(ctx, key, s)),
            .object => |obj| {
                if (std.mem.eql(u8, key, "attributes")) {
                    var attr_it = obj.iterator();
                    while (attr_it.next()) |attr_entry| {
                        if (attr_entry.value_ptr.* != .string) continue;
                        _ = try appendAttr(ctx, attr_entry.key_ptr.*, attr_entry.value_ptr.*.string);
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

test "eval parse: malformed json falls back to raw line" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const ctx = try parseLine(arena.allocator(), .json, "{not valid json");
    try testing.expectEqualStrings("{not valid json", ctx.message.?);
    try testing.expect(ctx.severity == null);
    try testing.expectEqual(@as(usize, 0), ctx.attrs.items.len);
}

test "eval parse: truncated json falls back to raw line" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const ctx = try parseLine(arena.allocator(), .json, "{\"message\":\"partia");
    try testing.expectEqualStrings("{\"message\":\"partia", ctx.message.?);
    try testing.expectEqual(@as(usize, 0), ctx.attrs.items.len);
}
