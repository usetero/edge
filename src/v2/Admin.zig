//! Bounded admin rendering; policy snapshots never escape their read guard.
const std = @import("std");
const policy = @import("policy_zig");
const PolicyStore = @import("PolicyStore.zig");
const TapState = @import("../pipeline/tap.zig").TapState;

pub const Reply = struct { status: []const u8 = "200 OK", content_type: []const u8 = "text/plain", length: usize };

pub fn policies(io: std.Io, store: ?*PolicyStore, writer: *std.Io.Writer, json: bool) !void {
    const owner = store orelse {
        return writer.writeAll(if (json) "{\"version\":0,\"policies\":[]}\n" else "# no policy snapshot loaded (0 policies)\n");
    };
    var guard = switch (owner.tryRead(io)) {
        .ready => |guard| guard,
        else => return error.PolicyUnavailable,
    };
    defer guard.deinit(io);
    const snapshot = guard.snapshot();
    if (json) {
        try writer.print("{{\"version\":{d},\"policies\":", .{if (snapshot) |s| s.version else 0});
        try std.json.Stringify.value(if (snapshot) |s| s.policies else &.{}, .{}, writer);
        return writer.writeAll("}\n");
    }
    const current = snapshot orelse return writer.writeAll("# no policy snapshot loaded (0 policies)\n");
    try writer.print("# snapshot version={d} policies={d} (log={d} metric={d} trace={d})\n", .{
        current.version,                   current.policies.len,             current.log_target_indices.len,
        current.metric_target_indices.len, current.trace_target_indices.len,
    });
    for (current.policies) |*entry| {
        const signal = if (entry.target) |target| @tagName(std.meta.activeTag(target)) else "none";
        try writer.print("id={s} signal={s} enabled={} name={s}\n", .{
            entry.id, signal, entry.enabled, entry.name,
        });
    }
}

/// A fixed writer is pinned by the admin request's existing response reservation.
/// Disarm joins all captures before returning, including errors and cancellation.
pub fn tap(io: std.Io, state: ?*TapState, path_query: []const u8, writer: *std.Io.Writer, deadline: std.Io.Timestamp, stopped: *const std.atomic.Value(bool)) !bool {
    const owner = state orelse return error.TapDisabled;
    const stage: TapState.Stage = if (std.mem.startsWith(u8, path_query, "/_edge/tap/pre")) .pre else .post;
    var count: u32 = 10;
    if (std.mem.indexOf(u8, path_query, "?n=")) |start| {
        const end = std.mem.indexOfScalarPos(u8, path_query, start + 3, '&') orelse path_query.len;
        count = std.fmt.parseInt(u32, path_query[start + 3 .. end], 10) catch 10;
        count = std.math.clamp(count, 1, 1000);
    }
    if (!owner.arm(stage, count, writer)) return false;
    defer owner.disarm();
    const end = @min(deadline.nanoseconds, std.Io.Timestamp.now(io, .awake).nanoseconds + 1_000_000_000);
    while (!stopped.load(.acquire) and !owner.finished() and std.Io.Timestamp.now(io, .awake).nanoseconds < end) {
        try io.sleep(.fromMilliseconds(10), .awake);
    }
    return true;
}

test "v2 admin empty snapshot renders both stable formats" {
    var bytes: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&bytes);
    try policies(std.testing.io, null, &writer, true);
    try std.testing.expectEqualStrings("{\"version\":0,\"policies\":[]}\n", writer.buffered());
}
