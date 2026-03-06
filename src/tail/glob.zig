const std = @import("std");

pub const ExpandedPaths = struct {
    allocator: std.mem.Allocator,
    items: std.ArrayList([]u8),

    pub fn init(allocator: std.mem.Allocator) ExpandedPaths {
        return .{
            .allocator = allocator,
            .items = .{},
        };
    }

    pub fn deinit(self: *ExpandedPaths) void {
        for (self.items.items) |p| self.allocator.free(p);
        self.items.deinit(self.allocator);
    }
};

pub fn expandPatterns(allocator: std.mem.Allocator, inputs: []const []const u8) !ExpandedPaths {
    var out = ExpandedPaths.init(allocator);
    errdefer out.deinit();

    for (inputs) |input| {
        if (!isGlobPattern(input)) {
            try out.items.append(allocator, try allocator.dupe(u8, input));
            continue;
        }
        try expandOnePattern(allocator, input, &out.items);
    }

    return out;
}

pub fn isGlobPattern(input: []const u8) bool {
    return std.mem.indexOfAny(u8, input, "*?[") != null;
}

fn expandOnePattern(allocator: std.mem.Allocator, pattern: []const u8, out: *std.ArrayList([]u8)) !void {
    const dir_path = std.fs.path.dirname(pattern) orelse ".";
    const base_pat = std.fs.path.basename(pattern);

    var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer dir.close();

    var it = dir.iterate();
    while (try it.next()) |entry| {
        if (entry.kind == .directory) continue;
        if (!match(base_pat, entry.name)) continue;

        const full = try std.fs.path.join(allocator, &.{ dir_path, entry.name });
        try out.append(allocator, full);
    }
}

fn match(pattern: []const u8, value: []const u8) bool {
    var p: usize = 0;
    var v: usize = 0;
    var star_p: ?usize = null;
    var star_v: usize = 0;

    while (v < value.len) {
        if (p < pattern.len and (pattern[p] == '?' or pattern[p] == value[v])) {
            p += 1;
            v += 1;
            continue;
        }
        if (p < pattern.len and pattern[p] == '*') {
            star_p = p;
            p += 1;
            star_v = v;
            continue;
        }
        if (star_p) |sp| {
            p = sp + 1;
            star_v += 1;
            v = star_v;
            continue;
        }
        return false;
    }

    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

const testing = std.testing;

test "glob: isGlobPattern detects wildcard syntax" {
    try testing.expect(isGlobPattern("/var/log/*.log"));
    try testing.expect(isGlobPattern("foo?bar"));
    try testing.expect(!isGlobPattern("/var/log/syslog"));
}

test "glob: expandPatterns expands wildcard and preserves explicit paths" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    {
        const a = try tmp_dir.dir.createFile("a.log", .{});
        defer a.close();
        const b = try tmp_dir.dir.createFile("b.log", .{});
        defer b.close();
        const c = try tmp_dir.dir.createFile("ignore.txt", .{});
        defer c.close();
    }

    const dir_path = try tmp_dir.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(dir_path);

    const pat = try std.fmt.allocPrint(testing.allocator, "{s}/*.log", .{dir_path});
    defer testing.allocator.free(pat);
    const explicit = try std.fmt.allocPrint(testing.allocator, "{s}/ignore.txt", .{dir_path});
    defer testing.allocator.free(explicit);

    var expanded = try expandPatterns(testing.allocator, &.{ pat, explicit });
    defer expanded.deinit();

    try testing.expectEqual(@as(usize, 3), expanded.items.items.len);
}
