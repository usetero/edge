const std = @import("std");
const http1 = @import("../network/http1.zig");
const json_pp = @import("../json/pretty_print.zig");
const config_types = @import("../config/types.zig");

const Direction = enum {
    request,
    response,
};

pub fn inspectRequest(
    req: http1.Request,
    config: *const config_types.ProxyConfig,
    allocator: std.mem.Allocator,
) !void {
    var buffer: [1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&buffer);
    const stdout = &stdout_writer.interface;
    const mutex = struct {
        var m: std.Thread.Mutex = .{};
    };

    mutex.m.lock();
    defer mutex.m.unlock();

    // Print header
    try stdout.writeAll("\n");
    try stdout.writeAll("╔═══════════════════════════════════════════════════════════════════════════\n");
    try stdout.writeAll("║ → REQUEST ");

    // Timestamp
    const timestamp = std.time.timestamp();
    const dt = try formatTimestamp(timestamp);
    try stdout.print("[{s}]", .{dt});

    try stdout.writeAll("\n");
    try stdout.writeAll("╠═══════════════════════════════════════════════════════════════════════════\n");

    // Request line
    try stdout.print("║ {s} {s} {s}\n", .{ @tagName(req.method), req.target, @tagName(req.version) });
    var contentLength: u32 = 1024;
    // Headers
    for (req.headers) |header| {
        try stdout.print("║ {s}: {s}\n", .{ header.name, header.value });
        if (std.mem.eql(u8, header.name, "Content-Length")) {
            contentLength = std.fmt.parseInt(u32, header.value, 10) catch 0;
        }
    }

    // Body inspection
    if (req.body.len > 0) {
        try stdout.writeAll("║\n");
        try stdout.writeAll("║ ┌─ BODY ");

        if (req.isJson() and config.pretty_print_json) {
            try stdout.writeAll("(JSON) ");
            try stdout.writeAll("─────────────────────────────────────────────────\n");

            var bufferedWriter = try std.io.Writer.Allocating.initCapacity(allocator, contentLength);
            defer bufferedWriter.deinit();

            json_pp.prettyPrint(&bufferedWriter.writer, req.body, allocator) catch |err| {
                try stdout.print("║ │ <JSON parse error: {}>\n", .{err});
                try stdout.print("║ │ {s}\n", .{req.body});
            };

            // Print each line with prefix
            var lines = std.mem.splitScalar(u8, bufferedWriter.written(), '\n');
            while (lines.next()) |line| {
                if (line.len > 0) {
                    try stdout.print("║ │ {s}\n", .{line});
                }
            }
        } else {
            try stdout.writeAll("────────────────────────────────────────────────────\n");
            // Truncate if too large
            const display_body = if (req.body.len > config.max_body_size)
                req.body[0..config.max_body_size]
            else
                req.body;

            var lines = std.mem.splitScalar(u8, display_body, '\n');
            while (lines.next()) |line| {
                if (line.len > 0) {
                    try stdout.print("║ │ {s}\n", .{line});
                }
            }

            if (req.body.len > config.max_body_size) {
                try stdout.print("║ │ ... ({d} bytes truncated)\n", .{req.body.len - config.max_body_size});
            }
        }

        try stdout.writeAll("║ └─────────────────────────────────────────────────────────────────────────\n");
    }

    try stdout.writeAll("╚═══════════════════════════════════════════════════════════════════════════\n");
    try stdout.flush();
}

pub fn inspectResponse(
    resp: http1.Response,
    config: *const config_types.ProxyConfig,
    allocator: std.mem.Allocator,
    duration_ms: ?u64,
) !void {
    var buffer: [1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&buffer);
    const stdout = &stdout_writer.interface;
    const mutex = struct {
        var m: std.Thread.Mutex = .{};
    };

    mutex.m.lock();
    defer mutex.m.unlock();

    // Print header
    try stdout.writeAll("\n");
    try stdout.writeAll("╔═══════════════════════════════════════════════════════════════════════════\n");
    try stdout.writeAll("║ ← RESPONSE ");

    // Timestamp
    const timestamp = std.time.timestamp();
    const dt = try formatTimestamp(timestamp);
    try stdout.print("[{s}]", .{dt});

    if (duration_ms) |dur| {
        try stdout.print(" [{d}ms]", .{dur});
    }

    try stdout.writeAll("\n");
    try stdout.writeAll("╠═══════════════════════════════════════════════════════════════════════════\n");

    // Status line
    const status_phrase = resp.status.phrase() orelse "";
    try stdout.print("║ {s} {d} {s}\n", .{ @tagName(resp.version), @intFromEnum(resp.status), status_phrase });

    // Headers
    for (resp.headers) |header| {
        try stdout.print("║ {s}: {s}\n", .{ header.name, header.value });
    }

    // Body inspection
    if (resp.body.len > 0) {
        try stdout.writeAll("║\n");
        try stdout.writeAll("║ ┌─ BODY ");

        if (resp.isJson() and config.pretty_print_json) {
            try stdout.writeAll("(JSON) ");
            try stdout.writeAll("─────────────────────────────────────────────────\n");

            // Pretty print JSON with prefix

            json_pp.prettyPrint(stdout, resp.body, allocator) catch |err| {
                try stdout.print("║ │ <JSON parse error: {}>\n", .{err});
                try stdout.print("║ │ {s}\n", .{resp.body});
            };

            // Print each line with prefix
            var lines = std.mem.splitScalar(u8, &buffer, '\n');
            while (lines.next()) |line| {
                if (line.len > 0) {
                    try stdout.print("║ │ {s}\n", .{line});
                }
            }
        } else {
            try stdout.writeAll("────────────────────────────────────────────────────\n");
            // Truncate if too large
            const display_body = if (resp.body.len > config.max_body_size)
                resp.body[0..config.max_body_size]
            else
                resp.body;

            var lines = std.mem.splitScalar(u8, display_body, '\n');
            while (lines.next()) |line| {
                if (line.len > 0) {
                    try stdout.print("║ │ {s}\n", .{line});
                }
            }

            if (resp.body.len > config.max_body_size) {
                try stdout.print("║ │ ... ({d} bytes truncated)\n", .{resp.body.len - config.max_body_size});
            }
        }

        try stdout.writeAll("║ └─────────────────────────────────────────────────────────────────────────\n");
    }

    try stdout.writeAll("╚═══════════════════════════════════════════════════════════════════════════\n");
    try stdout.flush();
}

fn formatTimestamp(timestamp: i64) ![24]u8 {
    var buf: [24]u8 = undefined;
    const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = @intCast(timestamp) };
    const day_seconds = epoch_seconds.getDaySeconds();
    const epoch_day = epoch_seconds.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();

    _ = try std.fmt.bufPrint(&buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        year_day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
        day_seconds.getSecondsIntoMinute(),
    });

    return buf;
}
