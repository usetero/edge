const std = @import("std");

pub const Program = struct {
    policies: []Policy = &.{},

    pub fn deinit(self: *Program, allocator: std.mem.Allocator) void {
        for (self.policies) |p| p.deinit(allocator);
        allocator.free(self.policies);
        self.* = .{};
    }
};

pub const Policy = struct {
    id: []const u8 = "",
    keep: KeepMode,
    matchers: []Matcher,
    add_body: ?AddBodyTransform = null,
    sample_key: ?SampleKey = null,
    transform_raw: ?std.json.Value = null,

    fn deinit(self: Policy, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        for (self.matchers) |m| {
            allocator.free(m.value);
            if (m.key) |k| allocator.free(k);
        }
        allocator.free(self.matchers);
        if (self.add_body) |t| allocator.free(t.value);
        if (self.sample_key) |sk| if (sk.key) |k| allocator.free(k);
    }
};

pub const KeepRate = struct {
    limit: usize,
    unit: Unit,

    pub const Unit = enum { second, minute };
};

pub const KeepMode = union(enum) {
    all,
    none,
    rate: KeepRate,
    sample_pct: u8,
};

pub const SampleKey = struct {
    field: Field,
    key: ?[]const u8 = null,
};

pub const AddBodyTransform = struct {
    value: []const u8,
    upsert: bool,
};

pub const Matcher = struct {
    field: Field,
    op: Op,
    key: ?[]const u8 = null,
    negate: bool = false,
    case_insensitive: bool = false,
    exists_expected: bool = true,
    value: []const u8,
};

pub const Field = enum {
    body,
    severity_text,
    trace_id,
    span_id,
    event_name,
    resource_schema_url,
    scope_schema_url,
    resource_attribute,
    scope_attribute,
    log_attribute,
};

pub const Op = enum {
    exact,
    contains,
    starts_with,
    ends_with,
    regex,
    exists,
};

pub const RecordContext = struct {
    body: []const u8 = "",
    has_body: bool = false,
    severity_text: []const u8 = "",
    has_severity_text: bool = false,
    trace_id: []const u8 = "",
    has_trace_id: bool = false,
    span_id: []const u8 = "",
    has_span_id: bool = false,
    event_name: []const u8 = "",
    has_event_name: bool = false,
    resource_schema_url: []const u8 = "",
    has_resource_schema_url: bool = false,
    scope_schema_url: []const u8 = "",
    has_scope_schema_url: bool = false,
    resource_attributes: []const Attribute = &.{},
    scope_attributes: []const Attribute = &.{},
    log_attributes: []const Attribute = &.{},
};

pub const Attribute = struct {
    key: []const u8,
    value: []const u8,
};

pub const Decision = struct {
    drop: bool = false,
    add_body_value: ?[]const u8 = null,
    add_body_upsert: bool = false,
};

pub fn loadFromProviders(allocator: std.mem.Allocator, file_paths: []const []const u8) !Program {
    var all: std.ArrayListUnmanaged(Policy) = .empty;
    errdefer {
        for (all.items) |p| p.deinit(allocator);
        all.deinit(allocator);
    }

    for (file_paths) |path| {
        var one = try loadFromFile(allocator, path);
        defer one.deinit(allocator);
        try all.appendSlice(allocator, one.policies);
        one.policies = &.{};
    }

    return .{ .policies = try all.toOwnedSlice(allocator) };
}

pub fn loadFromFile(allocator: std.mem.Allocator, path: []const u8) !Program {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const stat = try file.stat();
    const bytes = try file.readToEndAlloc(allocator, stat.size);
    defer allocator.free(bytes);

    const root = try std.json.parseFromSliceLeaky(std.json.Value, allocator, bytes, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    });
    if (root != .object) return .{};
    const ps = root.object.get("policies") orelse return .{};
    if (ps != .array) return .{};

    var out: std.ArrayListUnmanaged(Policy) = .empty;
    errdefer {
        for (out.items) |p| p.deinit(allocator);
        out.deinit(allocator);
    }

    for (ps.array.items) |p| {
        if (p != .object) continue;
        const policy_id = if (p.object.get("id")) |idv|
            if (idv == .string) try allocator.dupe(u8, idv.string) else try allocator.dupe(u8, "")
        else
            try allocator.dupe(u8, "");
        if (p.object.get("enabled")) |enabled| {
            if (enabled == .bool and !enabled.bool) {
                allocator.free(policy_id);
                continue;
            }
        }
        const log = p.object.get("log") orelse {
            allocator.free(policy_id);
            continue;
        };
        if (log != .object) {
            allocator.free(policy_id);
            continue;
        }

        const keep = parseKeepMode(log.object.get("keep"));

        const ma = log.object.get("match") orelse {
            allocator.free(policy_id);
            continue;
        };
        if (ma != .array) {
            allocator.free(policy_id);
            continue;
        }
        var matchers: std.ArrayListUnmanaged(Matcher) = .empty;
        errdefer {
            for (matchers.items) |m| {
                allocator.free(m.value);
                if (m.key) |k| allocator.free(k);
            }
            matchers.deinit(allocator);
        }

        for (ma.array.items) |m| {
            if (m != .object) continue;
            const parsed = try parseMatcher(allocator, m.object);
            if (parsed) |pm| try matchers.append(allocator, pm);
        }

        var add_body: ?AddBodyTransform = null;
        const sample_key = try parseSampleKey(allocator, log.object.get("sample_key"));
        if (log.object.get("transform")) |t| {
            if (t == .object) {
                if (t.object.get("add")) |adds| {
                    if (adds == .array) {
                        for (adds.array.items) |a| {
                            if (a != .object) continue;
                            const lf = a.object.get("log_field") orelse continue;
                            const v = a.object.get("value") orelse continue;
                            if (lf == .string and std.mem.eql(u8, lf.string, "body") and v == .string) {
                                const upsert = if (a.object.get("upsert")) |u|
                                    (u == .bool and u.bool)
                                else
                                    false;
                                add_body = .{
                                    .value = try allocator.dupe(u8, v.string),
                                    .upsert = upsert,
                                };
                            }
                        }
                    }
                }
            }
        }

        try out.append(allocator, .{
            .id = policy_id,
            .keep = keep,
            .matchers = try matchers.toOwnedSlice(allocator),
            .add_body = add_body,
            .sample_key = sample_key,
            .transform_raw = log.object.get("transform"),
        });
    }
    std.mem.sort(Policy, out.items, {}, policyLessThan);
    return .{ .policies = try out.toOwnedSlice(allocator) };
}

fn parseMatcher(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !?Matcher {
    var field: Field = undefined;
    var key: ?[]const u8 = null;
    if (obj.get("log_field")) |lf| {
        if (lf != .string) return null;
        if (std.mem.eql(u8, lf.string, "body")) field = .body else if (std.mem.eql(u8, lf.string, "severity_text")) field = .severity_text else if (std.mem.eql(u8, lf.string, "trace_id")) field = .trace_id else if (std.mem.eql(u8, lf.string, "span_id")) field = .span_id else if (std.mem.eql(u8, lf.string, "event_name")) field = .event_name else if (std.mem.eql(u8, lf.string, "resource_schema_url")) field = .resource_schema_url else if (std.mem.eql(u8, lf.string, "scope_schema_url")) field = .scope_schema_url else return null;
    } else if (obj.get("resource_attribute")) |ra| {
        key = try parseAttributePath(allocator, ra);
        if (key == null) return null;
        field = .resource_attribute;
    } else if (obj.get("scope_attribute")) |sa| {
        key = try parseAttributePath(allocator, sa);
        if (key == null) return null;
        field = .scope_attribute;
    } else if (obj.get("log_attribute")) |la| {
        key = try parseAttributePath(allocator, la);
        if (key == null) return null;
        field = .log_attribute;
    } else return null;

    const op_keys = [_]struct { name: []const u8, op: Op }{
        .{ .name = "exact", .op = .exact },
        .{ .name = "contains", .op = .contains },
        .{ .name = "starts_with", .op = .starts_with },
        .{ .name = "ends_with", .op = .ends_with },
        .{ .name = "regex", .op = .regex },
    };
    const case_insensitive = if (obj.get("case_insensitive")) |ci|
        (ci == .bool and ci.bool)
    else
        false;
    const negate = if (obj.get("negate")) |n|
        (n == .bool and n.bool)
    else
        false;

    if (obj.get("exists")) |ev| {
        if (ev != .bool) return null;
        return .{
            .field = field,
            .op = .exists,
            .key = key,
            .negate = negate,
            .case_insensitive = false,
            .exists_expected = ev.bool,
            .value = try allocator.dupe(u8, ""),
        };
    }

    inline for (op_keys) |ok| {
        if (obj.get(ok.name)) |v| {
            if (v != .string) break;
            return .{
                .field = field,
                .op = ok.op,
                .key = key,
                .negate = negate,
                .case_insensitive = case_insensitive,
                .value = try allocator.dupe(u8, v.string),
            };
        }
    }

    if (key) |k| allocator.free(k);
    return null;
}

pub fn evaluate(program: *const Program, ctx: RecordContext) Decision {
    var out = Decision{};
    for (program.policies) |p| {
        if (!policyMatches(&p, ctx)) continue;
        if (p.keep == .none) out.drop = true;
        if (!out.drop and p.add_body != null) {
            out.add_body_value = p.add_body.?.value;
            out.add_body_upsert = p.add_body.?.upsert;
        }
    }
    return out;
}

pub fn policyMatches(policy: *const Policy, ctx: RecordContext) bool {
    for (policy.matchers) |m| {
        if (!matchOne(m, ctx)) return false;
    }
    return true;
}

fn matchOne(m: Matcher, ctx: RecordContext) bool {
    const actual = switch (m.field) {
        .body => if (ctx.has_body) ctx.body else null,
        .severity_text => if (ctx.has_severity_text) ctx.severity_text else null,
        .trace_id => if (ctx.has_trace_id) ctx.trace_id else null,
        .span_id => if (ctx.has_span_id) ctx.span_id else null,
        .event_name => if (ctx.has_event_name) ctx.event_name else null,
        .resource_schema_url => if (ctx.has_resource_schema_url) ctx.resource_schema_url else null,
        .scope_schema_url => if (ctx.has_scope_schema_url) ctx.scope_schema_url else null,
        .resource_attribute => attrValue(ctx.resource_attributes, m.key.?),
        .scope_attribute => attrValue(ctx.scope_attributes, m.key.?),
        .log_attribute => attrValue(ctx.log_attributes, m.key.?),
    };
    var matched = switch (m.op) {
        .exists => (actual != null) == m.exists_expected,
        else => if (actual) |a| matchOp(m.op, a, m.value, m.case_insensitive) else false,
    };
    if (m.negate) matched = !matched;
    return matched;
}

fn attrValue(attrs: []const Attribute, key: []const u8) ?[]const u8 {
    for (attrs) |a| if (std.mem.eql(u8, a.key, key)) return a.value;
    return null;
}

fn matchOp(op: Op, actual: []const u8, expected: []const u8, ci: bool) bool {
    return switch (op) {
        .exact => if (ci) std.ascii.eqlIgnoreCase(actual, expected) else std.mem.eql(u8, actual, expected),
        .contains => if (ci) containsCI(actual, expected) else std.mem.indexOf(u8, actual, expected) != null,
        .starts_with => if (ci) startsWithCI(actual, expected) else std.mem.startsWith(u8, actual, expected),
        .ends_with => if (ci) endsWithCI(actual, expected) else std.mem.endsWith(u8, actual, expected),
        .regex => matchRegexLike(actual, expected, ci),
        .exists => false,
    };
}

fn parseAttributePath(allocator: std.mem.Allocator, v: std.json.Value) !?[]const u8 {
    return switch (v) {
        .string => try allocator.dupe(u8, v.string),
        .array => blk: {
            if (v.array.items.len == 0) break :blk null;
            var out: std.ArrayListUnmanaged(u8) = .empty;
            errdefer out.deinit(allocator);
            for (v.array.items, 0..) |part, i| {
                if (part != .string) {
                    out.deinit(allocator);
                    break :blk null;
                }
                if (i != 0) try out.append(allocator, '.');
                try out.appendSlice(allocator, part.string);
            }
            break :blk try out.toOwnedSlice(allocator);
        },
        else => null,
    };
}

fn policyLessThan(_: void, a: Policy, b: Policy) bool {
    return std.mem.lessThan(u8, a.id, b.id);
}

fn parseKeepMode(maybe: ?std.json.Value) KeepMode {
    if (maybe == null or maybe.? != .string) return .all;
    const s = maybe.?.string;
    if (std.mem.eql(u8, s, "all")) return .all;
    if (std.mem.eql(u8, s, "none")) return .none;
    if (std.mem.endsWith(u8, s, "%")) {
        const num = std.fmt.parseInt(u8, s[0 .. s.len - 1], 10) catch return .all;
        return .{ .sample_pct = if (num > 100) 100 else num };
    }
    if (std.mem.endsWith(u8, s, "/s")) {
        const n = std.fmt.parseInt(usize, s[0 .. s.len - 2], 10) catch return .all;
        return .{ .rate = .{ .limit = n, .unit = .second } };
    }
    if (std.mem.endsWith(u8, s, "/m")) {
        const n = std.fmt.parseInt(usize, s[0 .. s.len - 2], 10) catch return .all;
        return .{ .rate = .{ .limit = n, .unit = .minute } };
    }
    return .all;
}

fn parseSampleKey(allocator: std.mem.Allocator, maybe: ?std.json.Value) !?SampleKey {
    if (maybe == null or maybe.? != .object) return null;
    const obj = maybe.?.object;
    if (obj.get("log_field")) |lf| {
        if (lf != .string) return null;
        if (std.mem.eql(u8, lf.string, "body")) return .{ .field = .body };
        if (std.mem.eql(u8, lf.string, "severity_text")) return .{ .field = .severity_text };
        if (std.mem.eql(u8, lf.string, "trace_id")) return .{ .field = .trace_id };
        if (std.mem.eql(u8, lf.string, "span_id")) return .{ .field = .span_id };
        if (std.mem.eql(u8, lf.string, "event_name")) return .{ .field = .event_name };
        return null;
    }
    if (obj.get("resource_attribute")) |ra| {
        const key = try parseAttributePath(allocator, ra) orelse return null;
        return .{ .field = .resource_attribute, .key = key };
    }
    if (obj.get("scope_attribute")) |sa| {
        const key = try parseAttributePath(allocator, sa) orelse return null;
        return .{ .field = .scope_attribute, .key = key };
    }
    if (obj.get("log_attribute")) |la| {
        const key = try parseAttributePath(allocator, la) orelse return null;
        return .{ .field = .log_attribute, .key = key };
    }
    return null;
}

fn matchRegexLike(actual: []const u8, pattern: []const u8, ci: bool) bool {
    if (std.mem.eql(u8, pattern, "^.*$")) return true;

    if (std.mem.indexOfScalar(u8, pattern, '|')) |_| {
        var it = std.mem.splitScalar(u8, pattern, '|');
        while (it.next()) |part| {
            if (matchRegexLike(actual, part, ci)) return true;
        }
        return false;
    }

    const anchored_start = std.mem.startsWith(u8, pattern, "^");
    const anchored_end = std.mem.endsWith(u8, pattern, "$");
    const inner_start: usize = if (anchored_start) 1 else 0;
    const inner_end: usize = if (anchored_end and pattern.len > inner_start) pattern.len - 1 else pattern.len;
    const inner = pattern[inner_start..inner_end];

    if (std.mem.startsWith(u8, inner, ".*")) {
        const suffix = inner[2..];
        return if (ci) endsWithCI(actual, suffix) else std.mem.endsWith(u8, actual, suffix);
    }

    if (std.mem.endsWith(u8, inner, ".*")) {
        const prefix = inner[0 .. inner.len - 2];
        return if (ci) startsWithCI(actual, prefix) else std.mem.startsWith(u8, actual, prefix);
    }

    if (anchored_start and anchored_end) {
        return if (ci) std.ascii.eqlIgnoreCase(actual, inner) else std.mem.eql(u8, actual, inner);
    }
    if (anchored_start) {
        return if (ci) startsWithCI(actual, inner) else std.mem.startsWith(u8, actual, inner);
    }
    if (anchored_end) {
        return if (ci) endsWithCI(actual, inner) else std.mem.endsWith(u8, actual, inner);
    }
    return if (ci) containsCI(actual, inner) else std.mem.indexOf(u8, actual, inner) != null;
}

fn containsCI(h: []const u8, n: []const u8) bool {
    if (n.len == 0) return true;
    if (n.len > h.len) return false;
    var i: usize = 0;
    while (i + n.len <= h.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(h[i .. i + n.len], n)) return true;
    }
    return false;
}
fn startsWithCI(h: []const u8, n: []const u8) bool {
    if (n.len > h.len) return false;
    return std.ascii.eqlIgnoreCase(h[0..n.len], n);
}
fn endsWithCI(h: []const u8, n: []const u8) bool {
    if (n.len > h.len) return false;
    return std.ascii.eqlIgnoreCase(h[h.len - n.len ..], n);
}

test "multi matcher AND + attribute fields" {
    const json =
        \\{"policies":[{"log":{"match":[{"log_field":"body","regex":"error"},{"resource_attribute":"service.name","exact":"payment"}],"keep":"none"}}]}
    ;
    const path = "zig-cache-log-policy-test.json";
    {
        const f = try std.fs.cwd().createFile(path, .{ .truncate = true });
        defer f.close();
        try f.writeAll(json);
    }
    defer std.fs.cwd().deleteFile(path) catch {};
    var p = try loadFromFile(std.testing.allocator, path);
    defer p.deinit(std.testing.allocator);
    const d1 = evaluate(&p, .{
        .body = "error x",
        .has_body = true,
        .resource_attributes = &.{.{ .key = "service.name", .value = "payment" }},
    });
    try std.testing.expect(d1.drop);
    const d2 = evaluate(&p, .{
        .body = "error x",
        .resource_attributes = &.{.{ .key = "service.name", .value = "auth" }},
    });
    try std.testing.expect(!d2.drop);
}
