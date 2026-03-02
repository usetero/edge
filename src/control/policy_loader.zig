const std = @import("std");
const policy_engine = @import("policy_engine.zig");
const cfg = @import("../config/root.zig");

pub fn loadFromProviders(
    allocator: std.mem.Allocator,
    engine: *policy_engine.PolicyEngine,
    providers: []const cfg.types.PolicyProviderConfig,
) !void {
    var next_version = engine.currentVersion() + 1;
    for (providers) |p| {
        if (!std.mem.eql(u8, p.type, "file")) continue;
        const path = p.path orelse continue;
        try loadFromFile(allocator, engine, path, next_version);
        next_version += 1;
    }
}

pub fn loadFromFile(
    allocator: std.mem.Allocator,
    engine: *policy_engine.PolicyEngine,
    path: []const u8,
    version: u64,
) !void {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const stat = try file.stat();
    const bytes = try file.readToEndAlloc(allocator, stat.size);
    defer allocator.free(bytes);

    const root = try std.json.parseFromSliceLeaky(std.json.Value, allocator, bytes, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    });

    var rules: std.ArrayListUnmanaged(policy_engine.RuleSpec) = .empty;
    defer rules.deinit(allocator);

    if (root != .object) return;
    const policies = root.object.get("policies") orelse return;
    if (policies != .array) return;

    for (policies.array.items) |policy| {
        if (policy != .object) continue;
        const log_obj = policy.object.get("log") orelse continue;
        if (log_obj != .object) continue;
        const keep_raw = log_obj.object.get("keep");
        const drop_action = if (keep_raw != null and keep_raw.? == .string)
            std.mem.eql(u8, keep_raw.?.string, "none")
        else
            false;
        if (!drop_action) continue;

        const match_arr = log_obj.object.get("match") orelse continue;
        if (match_arr != .array) continue;
        for (match_arr.array.items) |m| {
            if (m != .object) continue;
            const lf = m.object.get("log_field") orelse continue;
            if (lf != .string) continue;
            if (!std.mem.eql(u8, lf.string, "body")) continue;

            if (m.object.get("starts_with")) |sv| {
                if (sv == .string) {
                    try rules.append(allocator, .{
                        .kind = .starts_with,
                        .pattern = sv.string,
                        .action = .drop,
                    });
                    continue;
                }
            }
            if (m.object.get("contains")) |cv| {
                if (cv == .string) {
                    try rules.append(allocator, .{
                        .kind = .contains,
                        .pattern = cv.string,
                        .action = .drop,
                    });
                    continue;
                }
            }
            if (m.object.get("equals")) |ev| {
                if (ev == .string) {
                    try rules.append(allocator, .{
                        .kind = .equals,
                        .pattern = ev.string,
                        .action = .drop,
                    });
                    continue;
                }
            }
        }
    }

    try engine.apply(.{
        .version = version,
        .default_action = .keep,
        .rules = rules.items,
    });
}

test "loader maps conformance starts_with to drop rule" {
    var engine = try policy_engine.PolicyEngine.init(std.testing.allocator);
    defer engine.deinit();

    const json =
        \\{
        \\  "policies": [
        \\    {
        \\      "log": {
        \\        "match": [ { "log_field": "body", "starts_with": "ERROR:" } ],
        \\        "keep": "none"
        \\      }
        \\    }
        \\  ]
        \\}
    ;
    const path = "zig-cache-policy-loader-test.json";
    {
        const f = try std.fs.cwd().createFile(path, .{ .truncate = true });
        defer f.close();
        try f.writeAll(json);
    }
    defer std.fs.cwd().deleteFile(path) catch {};

    try loadFromFile(std.testing.allocator, &engine, path, 2);
    try std.testing.expectEqual(.drop, engine.evaluate("ERROR: bad"));
    try std.testing.expectEqual(.keep, engine.evaluate("INFO: ok"));
}
