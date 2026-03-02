const std = @import("std");

pub const PolicyAction = enum {
    keep,
    drop,
    transform,
};

pub const CompiledRule = struct {
    kind: MatchKind,
    pattern: []const u8,
    action: PolicyAction,
};

pub const RuleSpec = struct {
    kind: MatchKind = .contains,
    pattern: []const u8,
    action: PolicyAction,
};

pub const MatchKind = enum {
    contains,
    starts_with,
    equals,
};

pub const SnapshotSpec = struct {
    version: u64,
    default_action: PolicyAction = .keep,
    rules: []const RuleSpec = &.{},
};

pub const PolicySnapshot = struct {
    version: u64,
    default_action: PolicyAction,
    rules: []CompiledRule,
    ref_count: std.atomic.Value(usize),
    retired: std.atomic.Value(bool),
};

pub const SnapshotStore = struct {
    allocator: std.mem.Allocator,
    active: std.atomic.Value(?*PolicySnapshot),

    pub fn init(allocator: std.mem.Allocator) !SnapshotStore {
        const base = try compileSnapshot(allocator, .{
            .version = 1,
            .default_action = .keep,
            .rules = &.{},
        });
        return .{
            .allocator = allocator,
            .active = std.atomic.Value(?*PolicySnapshot).init(base),
        };
    }

    pub fn deinit(self: *SnapshotStore) void {
        if (self.active.swap(null, .acq_rel)) |ptr| {
            ptr.retired.store(true, .release);
            self.release(ptr);
        }
    }

    pub fn acquire(self: *const SnapshotStore) ?*PolicySnapshot {
        while (true) {
            const current = self.active.load(.acquire) orelse return null;
            _ = current.ref_count.fetchAdd(1, .acq_rel);
            if (self.active.load(.acquire) == current) {
                return current;
            }
            releaseSnapshot(self.allocator, current);
        }
    }

    pub fn release(self: *const SnapshotStore, snapshot: *PolicySnapshot) void {
        releaseSnapshot(self.allocator, snapshot);
    }

    pub fn swap(self: *SnapshotStore, next: *PolicySnapshot) void {
        const prev = self.active.swap(next, .acq_rel) orelse return;
        prev.retired.store(true, .release);
        self.release(prev);
    }
};

pub const PolicyEngine = struct {
    allocator: std.mem.Allocator,
    snapshots: SnapshotStore,

    pub fn init(allocator: std.mem.Allocator) !PolicyEngine {
        return .{
            .allocator = allocator,
            .snapshots = try SnapshotStore.init(allocator),
        };
    }

    pub fn deinit(self: *PolicyEngine) void {
        self.snapshots.deinit();
    }

    pub fn currentVersion(self: *const PolicyEngine) u64 {
        const snap = self.snapshots.acquire() orelse return 0;
        defer self.snapshots.release(snap);
        return snap.version;
    }

    pub fn hasRules(self: *const PolicyEngine) bool {
        const snap = self.snapshots.acquire() orelse return false;
        defer self.snapshots.release(snap);
        return snap.rules.len > 0;
    }

    pub fn apply(self: *PolicyEngine, spec: SnapshotSpec) !void {
        const next = try compileSnapshot(self.allocator, spec);
        self.snapshots.swap(next);
    }

    pub fn evaluate(self: *const PolicyEngine, payload: []const u8) PolicyAction {
        return self.evaluateWithVersion(payload).action;
    }

    pub const Evaluation = struct {
        action: PolicyAction,
        snapshot_version: u64,
    };

    pub fn evaluateWithVersion(self: *const PolicyEngine, payload: []const u8) Evaluation {
        const snap = self.snapshots.acquire() orelse return .{
            .action = .keep,
            .snapshot_version = 0,
        };
        defer self.snapshots.release(snap);

        for (snap.rules) |rule| {
            if (rule.pattern.len == 0) continue;
            if (matches(rule.kind, payload, rule.pattern)) {
                return .{
                    .action = rule.action,
                    .snapshot_version = snap.version,
                };
            }
        }
        return .{
            .action = snap.default_action,
            .snapshot_version = snap.version,
        };
    }
};

pub fn compileSnapshot(allocator: std.mem.Allocator, spec: SnapshotSpec) !*PolicySnapshot {
    const out = try allocator.create(PolicySnapshot);
    errdefer allocator.destroy(out);

    const rules = try allocator.alloc(CompiledRule, spec.rules.len);
    errdefer allocator.free(rules);

    for (spec.rules, 0..) |r, i| {
        rules[i] = .{
            .kind = r.kind,
            .pattern = try allocator.dupe(u8, r.pattern),
            .action = r.action,
        };
    }

    out.* = .{
        .version = spec.version,
        .default_action = spec.default_action,
        .rules = rules,
        .ref_count = std.atomic.Value(usize).init(1),
        .retired = std.atomic.Value(bool).init(false),
    };
    return out;
}

fn releaseSnapshot(allocator: std.mem.Allocator, snapshot: *PolicySnapshot) void {
    const prev = snapshot.ref_count.fetchSub(1, .acq_rel);
    if (prev != 1) return;
    if (!snapshot.retired.load(.acquire)) return;
    for (snapshot.rules) |rule| allocator.free(rule.pattern);
    allocator.free(snapshot.rules);
    allocator.destroy(snapshot);
}

fn matches(kind: MatchKind, payload: []const u8, pattern: []const u8) bool {
    return switch (kind) {
        .contains => std.mem.indexOf(u8, payload, pattern) != null,
        .starts_with => std.mem.startsWith(u8, payload, pattern),
        .equals => std.mem.eql(u8, payload, pattern),
    };
}

test "policy engine honors first matching rule" {
    var engine = try PolicyEngine.init(std.testing.allocator);
    defer engine.deinit();

    try engine.apply(.{
        .version = 2,
        .default_action = .keep,
        .rules = &.{
            .{ .kind = .contains, .pattern = "error", .action = .drop },
            .{ .kind = .contains, .pattern = "warn", .action = .transform },
        },
    });

    try std.testing.expectEqual(@as(u64, 2), engine.currentVersion());
    try std.testing.expectEqual(.drop, engine.evaluate("error happened"));
    try std.testing.expectEqual(.transform, engine.evaluate("warn signal"));
    try std.testing.expectEqual(.keep, engine.evaluate("info signal"));
}

test "snapshot swap updates behavior" {
    var engine = try PolicyEngine.init(std.testing.allocator);
    defer engine.deinit();

    try std.testing.expectEqual(.keep, engine.evaluate("abc"));
    try engine.apply(.{
        .version = 10,
        .default_action = .drop,
        .rules = &.{
            .{ .kind = .contains, .pattern = "allow", .action = .keep },
        },
    });
    try std.testing.expectEqual(.keep, engine.evaluate("allow this"));
    try std.testing.expectEqual(.drop, engine.evaluate("deny this"));
}

test "snapshot acquire remains valid across swaps" {
    var store = try SnapshotStore.init(std.testing.allocator);
    defer store.deinit();

    const held = store.acquire().?;
    try std.testing.expectEqual(@as(u64, 1), held.version);

    const newer = try compileSnapshot(std.testing.allocator, .{
        .version = 99,
        .default_action = .keep,
        .rules = &.{},
    });
    store.swap(newer);

    try std.testing.expectEqual(@as(u64, 1), held.version);
    store.release(held);

    const now = store.acquire().?;
    defer store.release(now);
    try std.testing.expectEqual(@as(u64, 99), now.version);
}

test "match kinds apply correctly" {
    var engine = try PolicyEngine.init(std.testing.allocator);
    defer engine.deinit();
    try engine.apply(.{
        .version = 7,
        .default_action = .keep,
        .rules = &.{
            .{ .kind = .starts_with, .pattern = "ERR:", .action = .drop },
            .{ .kind = .equals, .pattern = "EXACT", .action = .transform },
        },
    });
    try std.testing.expectEqual(.drop, engine.evaluate("ERR: boom"));
    try std.testing.expectEqual(.transform, engine.evaluate("EXACT"));
    try std.testing.expectEqual(.keep, engine.evaluate("EXACT plus"));
}
