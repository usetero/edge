const std = @import("std");
const policy = @import("policy_zig");
const o11y = @import("o11y");
const types = @import("types.zig");
const context = @import("eval_context.zig");
const parse = @import("eval_parse.zig");

const FilterDecision = policy.FilterDecision;
const PolicyResult = policy.PolicyResult;

const DisabledEvaluator = struct {};

const ActiveEvaluator = struct {
    registry: *policy.Registry,
    engine: policy.PolicyEngine,
    policy_id_buf: [policy.MAX_MATCHES_PER_SCAN][]const u8 = undefined,
    arena: std.heap.ArenaAllocator,
    allocator: std.mem.Allocator,

    fn deinit(self: *ActiveEvaluator) void {
        self.registry.deinit();
        self.allocator.destroy(self.registry);
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
        bus: *o11y.EventBus,
    ) !StreamEvaluator {
        if (policy_path == null) {
            return .{
                .allocator = allocator,
                .input_format = input_format,
                .mode = .{ .disabled = .{} },
            };
        }

        const registry = try allocator.create(policy.Registry);
        errdefer allocator.destroy(registry);
        registry.* = policy.Registry.init(allocator, bus);
        errdefer registry.deinit();

        const policies = try policy.parser.parsePoliciesFile(allocator, policy_path.?);
        defer {
            for (policies) |*p| p.deinit(allocator);
            allocator.free(policies);
        }
        try registry.updatePolicies(policies, "tail-policy-file", .file);

        return .{
            .allocator = allocator,
            .input_format = input_format,
            .mode = .{
                .active = .{
                    .registry = registry,
                    .engine = policy.PolicyEngine.init(bus, registry),
                    .arena = std.heap.ArenaAllocator.init(allocator),
                    .allocator = allocator,
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

                var ctx = try parse.parseLine(line_alloc, self.input_format, line);
                const result = active.engine.evaluate(
                    .log,
                    &ctx,
                    context.TailLineContext.fieldAccessor,
                    if (apply_transforms) context.TailLineContext.fieldMutator else null,
                    &active.policy_id_buf,
                );
                break :blk result;
            },
        };
    }
};

const testing = std.testing;

fn writePolicyFile(tmp: *std.testing.TmpDir, json: []const u8) ![]u8 {
    const f = try tmp.dir.createFile("policies.json", .{ .truncate = true });
    defer f.close();
    try f.writeAll(json);
    return try tmp.dir.realpathAlloc(testing.allocator, "policies.json");
}

fn testBus() o11y.StdioEventBus {
    var stdio_bus: o11y.StdioEventBus = undefined;
    stdio_bus.init();
    stdio_bus.eventBus().setLevel(.err);
    return stdio_bus;
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

    var stdio_bus = testBus();
    var eval = try StreamEvaluator.init(testing.allocator, .raw, policy_path, stdio_bus.eventBus());
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

    var stdio_bus = testBus();
    var eval = try StreamEvaluator.init(testing.allocator, .json, policy_path, stdio_bus.eventBus());
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

    var stdio_bus = testBus();
    var eval = try StreamEvaluator.init(testing.allocator, .logfmt, policy_path, stdio_bus.eventBus());
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

    var stdio_bus = testBus();
    var eval = try StreamEvaluator.init(testing.allocator, .raw, policy_path, stdio_bus.eventBus());
    defer eval.deinit();

    const hit = try eval.evalLineResult("info request", false);
    try testing.expectEqual(policy.FilterDecision.keep, hit.decision);
    try testing.expectEqual(@as(usize, 1), hit.matched_policy_ids.len);
    try testing.expectEqualStrings("keep-info", hit.matched_policy_ids[0]);

    const miss = try eval.evalLineResult("debug request", false);
    try testing.expectEqual(policy.FilterDecision.unset, miss.decision);
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

    var stdio_bus = testBus();
    var eval = try StreamEvaluator.init(testing.allocator, .raw, policy_path, stdio_bus.eventBus());
    defer eval.deinit();

    const without_transforms = try eval.evalLineResult("order accepted", false);
    try testing.expectEqual(false, without_transforms.was_transformed);

    const with_transforms = try eval.evalLineResult("order accepted", true);
    try testing.expectEqual(policy.FilterDecision.keep, with_transforms.decision);
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

    var stdio_bus = testBus();
    var eval = try StreamEvaluator.init(testing.allocator, .raw, policy_path, stdio_bus.eventBus());
    defer eval.deinit();

    const with_transforms = try eval.evalLineResult("checkout start", true);
    try testing.expectEqual(policy.FilterDecision.keep, with_transforms.decision);
    try testing.expectEqual(false, with_transforms.was_transformed);
}

test "eval stream public API: disabled evaluator returns unmatched and keeps lines" {
    var stdio_bus = testBus();
    var eval = try StreamEvaluator.init(testing.allocator, types.InputFormat.raw, null, stdio_bus.eventBus());
    defer eval.deinit();

    try testing.expect(try eval.evalLine("anything"));
    const result = try eval.evalLineResult("anything", true);
    try testing.expectEqual(policy.FilterDecision.unset, result.decision);
}

test "eval stream public API: repeated policy init/eval/deinit is stable" {
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

    var i: usize = 0;
    while (i < 128) : (i += 1) {
        var stdio_bus = testBus();
        var eval = try StreamEvaluator.init(testing.allocator, .raw, policy_path, stdio_bus.eventBus());
        defer eval.deinit();
        try testing.expect(try eval.evalLine("ok"));
        try testing.expect(!(try eval.evalLine("debug")));
    }
}
