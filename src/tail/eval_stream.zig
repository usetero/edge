const std = @import("std");
const policy = @import("policy_zig");
const o11y = @import("o11y");
const types = @import("types.zig");

const LogField = policy.proto.policy.LogField;
const FieldRef = policy.FieldRef;
const MutateOp = policy.MutateOp;
const FilterDecision = policy.FilterDecision;
const PolicyResult = policy.PolicyResult;

const TailAttr = struct {
    key: []const u8,
    value: []const u8,
};

const TailLineContext = struct {
    allocator: std.mem.Allocator,
    message: ?[]const u8 = null,
    severity: ?[]const u8 = null,
    attrs: std.ArrayListUnmanaged(TailAttr) = .{},

    pub fn fieldAccessor(ctx_ptr: *const anyopaque, field: FieldRef) ?[]const u8 {
        const self: *const TailLineContext = @ptrCast(@alignCast(ctx_ptr));
        return switch (field) {
            .log_field => |lf| switch (lf) {
                .LOG_FIELD_BODY => self.message,
                .LOG_FIELD_SEVERITY_TEXT => self.severity,
                else => null,
            },
            .log_attribute => |attr_path| {
                if (attr_path.path.items.len == 0) return null;
                const key = attr_path.path.items[0];
                return self.getAttr(key);
            },
            .resource_attribute, .scope_attribute => null,
        };
    }

    pub fn fieldMutator(ctx_ptr: *anyopaque, op: MutateOp) bool {
        const self: *TailLineContext = @ptrCast(@alignCast(ctx_ptr));
        return switch (op) {
            .remove => |field| self.removeField(field),
            .set => |set| self.setField(set.field, set.value, set.upsert),
            .rename => |rename| self.renameField(rename.from, rename.to, rename.upsert),
        };
    }

    fn getAttr(self: *const TailLineContext, key: []const u8) ?[]const u8 {
        for (self.attrs.items) |attr| {
            if (std.mem.eql(u8, attr.key, key)) return attr.value;
        }
        return null;
    }

    fn getAttrIndex(self: *const TailLineContext, key: []const u8) ?usize {
        for (self.attrs.items, 0..) |attr, i| {
            if (std.mem.eql(u8, attr.key, key)) return i;
        }
        return null;
    }

    fn putAttr(self: *TailLineContext, key: []const u8, value: []const u8) bool {
        if (self.getAttrIndex(key)) |idx| {
            self.attrs.items[idx].value = value;
            return true;
        }
        self.attrs.append(self.allocator, .{ .key = key, .value = value }) catch return false;
        return true;
    }

    fn removeAttr(self: *TailLineContext, key: []const u8) bool {
        if (self.getAttrIndex(key)) |idx| {
            _ = self.attrs.swapRemove(idx);
            return true;
        }
        return false;
    }

    fn removeField(self: *TailLineContext, field: FieldRef) bool {
        return switch (field) {
            .log_field => |lf| switch (lf) {
                .LOG_FIELD_BODY => blk: {
                    const existed = self.message != null;
                    self.message = null;
                    break :blk existed;
                },
                .LOG_FIELD_SEVERITY_TEXT => blk: {
                    const existed = self.severity != null;
                    self.severity = null;
                    break :blk existed;
                },
                else => false,
            },
            .log_attribute => |attr_path| blk: {
                if (attr_path.path.items.len == 0) break :blk false;
                break :blk self.removeAttr(attr_path.path.items[0]);
            },
            .resource_attribute, .scope_attribute => false,
        };
    }

    fn setField(self: *TailLineContext, field: FieldRef, value: []const u8, upsert: bool) bool {
        return switch (field) {
            .log_field => |lf| switch (lf) {
                .LOG_FIELD_BODY => blk: {
                    if (!upsert and self.message == null) break :blk false;
                    self.message = value;
                    break :blk true;
                },
                .LOG_FIELD_SEVERITY_TEXT => blk: {
                    if (!upsert and self.severity == null) break :blk false;
                    self.severity = value;
                    break :blk true;
                },
                else => false,
            },
            .log_attribute => |attr_path| blk: {
                if (attr_path.path.items.len == 0) break :blk false;
                const key = attr_path.path.items[0];
                if (!upsert and self.getAttr(key) == null) break :blk false;
                break :blk self.putAttr(key, value);
            },
            .resource_attribute, .scope_attribute => false,
        };
    }

    fn renameField(self: *TailLineContext, from: FieldRef, to_key: []const u8, upsert: bool) bool {
        const value = TailLineContext.fieldAccessor(self, from) orelse return false;
        if (!upsert and self.getAttr(to_key) != null) return false;
        if (!self.putAttr(to_key, value)) return false;
        return self.removeField(from);
    }
};

const DisabledEvaluator = struct {};

const ActiveEvaluator = struct {
    noop_bus: o11y.NoopEventBus,
    registry: policy.Registry,
    engine: policy.PolicyEngine,
    policy_id_buf: [policy.MAX_MATCHES_PER_SCAN][]const u8 = undefined,
    arena: std.heap.ArenaAllocator,

    fn deinit(self: *ActiveEvaluator) void {
        self.registry.deinit();
        self.arena.deinit();
    }
};

pub const StreamEvaluator = struct {
    allocator: std.mem.Allocator,
    input_format: types.InputFormat,
    mode: union(enum) {
        disabled: DisabledEvaluator,
        active: ActiveEvaluator,
    },

    pub fn init(
        allocator: std.mem.Allocator,
        input_format: types.InputFormat,
        policy_path: ?[]const u8,
    ) !StreamEvaluator {
        if (policy_path == null) {
            return .{
                .allocator = allocator,
                .input_format = input_format,
                .mode = .{ .disabled = .{} },
            };
        }

        var noop_bus: o11y.NoopEventBus = undefined;
        noop_bus.init();
        var registry = policy.Registry.init(allocator, noop_bus.eventBus());
        errdefer registry.deinit();

        const policies = try policy.parser.parsePoliciesFile(allocator, policy_path.?);
        defer {
            for (policies) |*p| p.deinit(allocator);
            allocator.free(policies);
        }
        try registry.updatePolicies(policies, "tail-policy-file", .file);

        const engine = policy.PolicyEngine.init(noop_bus.eventBus(), &registry);

        return .{
            .allocator = allocator,
            .input_format = input_format,
            .mode = .{
                .active = .{
                    .noop_bus = noop_bus,
                    .registry = registry,
                    .engine = engine,
                    .arena = std.heap.ArenaAllocator.init(allocator),
                },
            },
        };
    }

    pub fn deinit(self: *StreamEvaluator) void {
        switch (self.mode) {
            .disabled => {},
            .active => |*active| active.deinit(),
        }
    }

    pub fn evalLine(self: *StreamEvaluator, line: []const u8) !bool {
        const result = try self.evalLineResult(line, false);
        return result.decision != FilterDecision.drop;
    }

    pub fn evalLineResult(self: *StreamEvaluator, line: []const u8, apply_transforms: bool) !PolicyResult {
        return switch (self.mode) {
            .disabled => PolicyResult.unmatched,
            .active => |*active| blk: {
                _ = active.arena.reset(.retain_capacity);
                const line_alloc = active.arena.allocator();

                var ctx = try parseLine(line_alloc, self.input_format, line);
                const result = active.engine.evaluate(
                    .log,
                    &ctx,
                    TailLineContext.fieldAccessor,
                    if (apply_transforms) TailLineContext.fieldMutator else null,
                    &active.policy_id_buf,
                );
                break :blk result;
            },
        };
    }
};

fn parseLine(
    allocator: std.mem.Allocator,
    input_format: types.InputFormat,
    line: []const u8,
) !TailLineContext {
    var ctx = TailLineContext{ .allocator = allocator };
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

fn parseLogfmtAttrs(ctx: *TailLineContext, line: []const u8) !void {
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

fn parseJsonAttrs(ctx: *TailLineContext, line: []const u8) !void {
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

fn writePolicyFile(tmp: *std.testing.TmpDir, json: []const u8) ![]u8 {
    const f = try tmp.dir.createFile("policies.json", .{ .truncate = true });
    defer f.close();
    try f.writeAll(json);
    return try tmp.dir.realpathAlloc(testing.allocator, "policies.json");
}

test "eval stream public API: raw hit and miss decisions" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const policy_path = try writePolicyFile(&tmp,
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "drop-debug",
        \\      "name": "drop-debug",
        \\      "log": {
        \\        "match": [{ "log_field": "body", "regex": "debug" }],
        \\        "keep": "none"
        \\      }
        \\    }
        \\  ]
        \\}
    );
    defer testing.allocator.free(policy_path);

    var eval = try StreamEvaluator.init(testing.allocator, .raw, policy_path);
    defer eval.deinit();

    try testing.expect(try eval.evalLine("hello"));
    try testing.expect(!(try eval.evalLine("debug trace")));
}

test "eval stream public API: json attribute matching and miss" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const policy_path = try writePolicyFile(&tmp,
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "drop-nginx",
        \\      "name": "drop-nginx",
        \\      "log": {
        \\        "match": [{ "log_attribute": "ddsource", "regex": "^nginx$" }],
        \\        "keep": "none"
        \\      }
        \\    }
        \\  ]
        \\}
    );
    defer testing.allocator.free(policy_path);

    var eval = try StreamEvaluator.init(testing.allocator, .json, policy_path);
    defer eval.deinit();

    try testing.expect(!(try eval.evalLine("{\"message\":\"x\",\"ddsource\":\"nginx\"}")));
    try testing.expect(try eval.evalLine("{\"message\":\"x\",\"ddsource\":\"app\"}"));
}

test "eval stream public API: logfmt severity matching" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const policy_path = try writePolicyFile(&tmp,
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "drop-debug-level",
        \\      "name": "drop-debug-level",
        \\      "log": {
        \\        "match": [{ "log_field": "severity_text", "regex": "^DEBUG$" }],
        \\        "keep": "none"
        \\      }
        \\    }
        \\  ]
        \\}
    );
    defer testing.allocator.free(policy_path);

    var eval = try StreamEvaluator.init(testing.allocator, .logfmt, policy_path);
    defer eval.deinit();

    try testing.expect(!(try eval.evalLine("severity_text=DEBUG msg=test")));
    try testing.expect(try eval.evalLine("severity_text=INFO msg=test"));
}

test "eval stream public API: evaluate result exposes keep hit ids and miss" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const policy_path = try writePolicyFile(&tmp,
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "keep-info",
        \\      "name": "keep-info",
        \\      "log": {
        \\        "match": [{ "log_field": "body", "regex": "info" }],
        \\        "keep": "all"
        \\      }
        \\    }
        \\  ]
        \\}
    );
    defer testing.allocator.free(policy_path);

    var eval = try StreamEvaluator.init(testing.allocator, .raw, policy_path);
    defer eval.deinit();

    const hit = try eval.evalLineResult("info request", false);
    try testing.expectEqual(FilterDecision.keep, hit.decision);
    try testing.expectEqual(@as(usize, 1), hit.matched_policy_ids.len);
    try testing.expectEqualStrings("keep-info", hit.matched_policy_ids[0]);

    const miss = try eval.evalLineResult("debug request", false);
    try testing.expectEqual(FilterDecision.unset, miss.decision);
    try testing.expectEqual(@as(usize, 0), miss.matched_policy_ids.len);
}

test "eval stream public API: transforms report hit and miss via was_transformed" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const policy_path = try writePolicyFile(&tmp,
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "add-env",
        \\      "name": "add-env",
        \\      "log": {
        \\        "match": [{ "log_field": "body", "regex": "order" }],
        \\        "keep": "all",
        \\        "transform": {
        \\          "add": [{ "log_attribute": "env", "value": "prod", "upsert": true }]
        \\        }
        \\      }
        \\    },
        \\    {
        \\      "id": "remove-nonexistent",
        \\      "name": "remove-nonexistent",
        \\      "log": {
        \\        "match": [{ "log_field": "body", "regex": "order" }],
        \\        "keep": "all",
        \\        "transform": {
        \\          "remove": [{ "log_attribute": "missing_key" }]
        \\        }
        \\      }
        \\    }
        \\  ]
        \\}
    );
    defer testing.allocator.free(policy_path);

    var eval = try StreamEvaluator.init(testing.allocator, .raw, policy_path);
    defer eval.deinit();

    const without_transforms = try eval.evalLineResult("order accepted", false);
    try testing.expectEqual(false, without_transforms.was_transformed);

    const with_transforms = try eval.evalLineResult("order accepted", true);
    try testing.expectEqual(FilterDecision.keep, with_transforms.decision);
    try testing.expectEqual(true, with_transforms.was_transformed);
}

test "eval stream public API: transform miss does not set was_transformed" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const policy_path = try writePolicyFile(&tmp,
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "remove-only",
        \\      "name": "remove-only",
        \\      "log": {
        \\        "match": [{ "log_field": "body", "regex": "checkout" }],
        \\        "keep": "all",
        \\        "transform": {
        \\          "remove": [{ "log_attribute": "missing_key" }]
        \\        }
        \\      }
        \\    }
        \\  ]
        \\}
    );
    defer testing.allocator.free(policy_path);

    var eval = try StreamEvaluator.init(testing.allocator, .raw, policy_path);
    defer eval.deinit();

    const with_transforms = try eval.evalLineResult("checkout start", true);
    try testing.expectEqual(FilterDecision.keep, with_transforms.decision);
    try testing.expectEqual(false, with_transforms.was_transformed);
}
