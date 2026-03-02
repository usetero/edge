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
    keep_percentage: f64 = 100.0,
    matchers: []Matcher = &.{},

    fn deinit(self: Policy, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        for (self.matchers) |m| {
            if (m.key) |k| allocator.free(k);
            allocator.free(m.value);
        }
        allocator.free(self.matchers);
    }
};

pub const Matcher = struct {
    field: Field,
    op: Op,
    key: ?[]const u8 = null,
    value: []const u8 = "",
    exists_expected: bool = true,
    negate: bool = false,
    case_insensitive: bool = false,
};

pub const Field = enum {
    name,
    parent_span_id,
    trace_state,
    scope_name,
    scope_version,
    scope_schema_url,
    span_kind,
    span_status,
    event_name,
    resource_attribute,
    scope_attribute,
    span_attribute,
};

pub const Op = enum {
    exact,
    contains,
    starts_with,
    ends_with,
    regex,
    exists,
};

pub const SpanContext = struct {
    name: []const u8 = "",
    has_name: bool = false,
    parent_span_id: []const u8 = "",
    has_parent_span_id: bool = false,
    trace_state: []const u8 = "",
    has_trace_state: bool = false,
    scope_name: []const u8 = "",
    has_scope_name: bool = false,
    scope_version: []const u8 = "",
    has_scope_version: bool = false,
    scope_schema_url: []const u8 = "",
    has_scope_schema_url: bool = false,
    span_kind: []const u8 = "",
    has_span_kind: bool = false,
    span_status: []const u8 = "",
    has_span_status: bool = false,
    has_event_name: bool = false,
    resource_attributes: []const Attribute = &.{},
    scope_attributes: []const Attribute = &.{},
    span_attributes: []const Attribute = &.{},
};

pub const Attribute = struct {
    key: []const u8,
    value: []const u8,
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
    std.mem.sort(Policy, all.items, {}, policyLessThan);
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
        if (p.object.get("enabled")) |en| if (en == .bool and !en.bool) continue;
        const trace = p.object.get("trace") orelse continue;
        if (trace != .object) continue;

        const id = if (p.object.get("id")) |idv|
            if (idv == .string) try allocator.dupe(u8, idv.string) else try allocator.dupe(u8, "")
        else
            try allocator.dupe(u8, "");

        const keep = if (trace.object.get("keep")) |k| parseKeepPercentage(k) else 100.0;
        const ma = trace.object.get("match") orelse continue;
        if (ma != .array) continue;
        var matchers: std.ArrayListUnmanaged(Matcher) = .empty;
        errdefer {
            for (matchers.items) |m| {
                if (m.key) |key| allocator.free(key);
                allocator.free(m.value);
            }
            matchers.deinit(allocator);
        }
        for (ma.array.items) |m| {
            if (m != .object) continue;
            const parsed = try parseMatcher(allocator, m.object);
            if (parsed) |pm| try matchers.append(allocator, pm);
        }

        try out.append(allocator, .{
            .id = id,
            .keep_percentage = keep,
            .matchers = try matchers.toOwnedSlice(allocator),
        });
    }

    std.mem.sort(Policy, out.items, {}, policyLessThan);
    return .{ .policies = try out.toOwnedSlice(allocator) };
}

pub fn policyMatches(policy: *const Policy, ctx: SpanContext) bool {
    for (policy.matchers) |m| {
        if (!matchOne(m, ctx)) return false;
    }
    return true;
}

fn parseKeepPercentage(v: std.json.Value) f64 {
    if (v != .object) return 100.0;
    const p = v.object.get("percentage") orelse return 100.0;
    return switch (p) {
        .float => std.math.clamp(p.float, 0.0, 100.0),
        .integer => std.math.clamp(@as(f64, @floatFromInt(p.integer)), 0.0, 100.0),
        else => 100.0,
    };
}

fn parseMatcher(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !?Matcher {
    var field: Field = undefined;
    var key: ?[]const u8 = null;

    if (obj.get("trace_field")) |tf| {
        if (tf != .string) return null;
        if (std.mem.eql(u8, tf.string, "TRACE_FIELD_NAME")) field = .name else if (std.mem.eql(u8, tf.string, "parent_span_id")) field = .parent_span_id else if (std.mem.eql(u8, tf.string, "trace_state")) field = .trace_state else if (std.mem.eql(u8, tf.string, "scope_name")) field = .scope_name else if (std.mem.eql(u8, tf.string, "scope_version")) field = .scope_version else if (std.mem.eql(u8, tf.string, "scope_schema_url")) field = .scope_schema_url else return null;
    } else if (obj.get("span_kind")) |sk| {
        if (sk != .string) return null;
        field = .span_kind;
        key = null;
    } else if (obj.get("span_status")) |ss| {
        if (ss != .string) return null;
        field = .span_status;
    } else if (obj.get("event_name")) |en| {
        if (en != .string) return null;
        field = .event_name;
        key = null;
    } else if (obj.get("resource_attribute")) |ra| {
        if (ra != .string) return null;
        field = .resource_attribute;
        key = try allocator.dupe(u8, ra.string);
    } else if (obj.get("scope_attribute")) |sa| {
        if (sa != .string) return null;
        field = .scope_attribute;
        key = try allocator.dupe(u8, sa.string);
    } else if (obj.get("span_attribute")) |la| {
        if (la != .string) return null;
        field = .span_attribute;
        key = try allocator.dupe(u8, la.string);
    } else {
        return null;
    }

    const ci = if (obj.get("case_insensitive")) |x| (x == .bool and x.bool) else false;
    const negate = if (obj.get("negate")) |x| (x == .bool and x.bool) else false;
    if (obj.get("exists")) |ev| {
        if (ev != .bool) return null;
        const val = switch (field) {
            .span_kind => obj.get("span_kind").?.string,
            .span_status => obj.get("span_status").?.string,
            .event_name => obj.get("event_name").?.string,
            else => "",
        };
        return .{
            .field = field,
            .op = .exists,
            .key = key,
            .value = try allocator.dupe(u8, val),
            .exists_expected = ev.bool,
            .negate = negate,
            .case_insensitive = false,
        };
    }

    const ops = [_]struct { name: []const u8, op: Op }{
        .{ .name = "exact", .op = .exact },
        .{ .name = "contains", .op = .contains },
        .{ .name = "starts_with", .op = .starts_with },
        .{ .name = "ends_with", .op = .ends_with },
        .{ .name = "regex", .op = .regex },
    };
    inline for (ops) |op| {
        if (obj.get(op.name)) |v| {
            if (v != .string) break;
            return .{
                .field = field,
                .op = op.op,
                .key = key,
                .value = try allocator.dupe(u8, v.string),
                .negate = negate,
                .case_insensitive = ci,
            };
        }
    }
    if (key) |k| allocator.free(k);
    return null;
}

fn matchOne(m: Matcher, ctx: SpanContext) bool {
    const actual = switch (m.field) {
        .name => if (ctx.has_name) ctx.name else null,
        .parent_span_id => if (ctx.has_parent_span_id and ctx.parent_span_id.len > 0) ctx.parent_span_id else null,
        .trace_state => if (ctx.has_trace_state) ctx.trace_state else null,
        .scope_name => if (ctx.has_scope_name) ctx.scope_name else null,
        .scope_version => if (ctx.has_scope_version) ctx.scope_version else null,
        .scope_schema_url => if (ctx.has_scope_schema_url) ctx.scope_schema_url else null,
        .span_kind => if (ctx.has_span_kind) ctx.span_kind else null,
        .span_status => if (ctx.has_span_status) ctx.span_status else null,
        .event_name => if (ctx.has_event_name) m.value else null,
        .resource_attribute => attrValue(ctx.resource_attributes, m.key.?),
        .scope_attribute => attrValue(ctx.scope_attributes, m.key.?),
        .span_attribute => attrValue(ctx.span_attributes, m.key.?),
    };
    var matched = switch (m.op) {
        .exists => blk: {
            if (m.field == .span_kind or m.field == .span_status) {
                if (actual == null) break :blk !m.exists_expected;
                break :blk opExact(actual.?, m.value, false) == m.exists_expected;
            }
            break :blk (actual != null) == m.exists_expected;
        },
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
        .exact => opExact(actual, expected, ci),
        .contains => if (ci) containsCI(actual, expected) else std.mem.indexOf(u8, actual, expected) != null,
        .starts_with => if (ci) startsWithCI(actual, expected) else std.mem.startsWith(u8, actual, expected),
        .ends_with => if (ci) endsWithCI(actual, expected) else std.mem.endsWith(u8, actual, expected),
        .regex => matchRegexLike(actual, expected, ci),
        .exists => false,
    };
}

fn opExact(actual: []const u8, expected: []const u8, ci: bool) bool {
    if (ci) return std.ascii.eqlIgnoreCase(actual, expected);
    return std.mem.eql(u8, actual, expected);
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

fn matchRegexLike(actual: []const u8, pattern: []const u8, ci: bool) bool {
    if (std.mem.eql(u8, pattern, "^.*$")) return true;
    if (std.mem.startsWith(u8, pattern, "^(")) {
        if (std.mem.indexOf(u8, pattern, ")")) |close_idx| {
            const alts = pattern[2..close_idx];
            const suffix = pattern[close_idx + 1 ..];
            var it_alt = std.mem.splitScalar(u8, alts, '|');
            while (it_alt.next()) |alt| {
                const combo = std.fmt.allocPrint(std.heap.page_allocator, "^{s}{s}", .{ alt, suffix }) catch continue;
                if (matchRegexLike(actual, combo, ci)) return true;
            }
            return false;
        }
    }
    if (std.mem.indexOfScalar(u8, pattern, '|')) |_| {
        var it = std.mem.splitScalar(u8, pattern, '|');
        while (it.next()) |part| if (matchRegexLike(actual, part, ci)) return true;
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
    if (anchored_start and anchored_end) return opExact(actual, inner, ci);
    if (anchored_start) return if (ci) startsWithCI(actual, inner) else std.mem.startsWith(u8, actual, inner);
    if (anchored_end) return if (ci) endsWithCI(actual, inner) else std.mem.endsWith(u8, actual, inner);
    return if (ci) containsCI(actual, inner) else std.mem.indexOf(u8, actual, inner) != null;
}

fn policyLessThan(_: void, a: Policy, b: Policy) bool {
    return std.mem.lessThan(u8, a.id, b.id);
}
