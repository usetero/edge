const std = @import("std");
const proto = @import("proto");
const types = @import("./types.zig");

const LogTransform = proto.policy.LogTransform;
const LogRemove = proto.policy.LogRemove;
const LogRedact = proto.policy.LogRedact;
const LogRename = proto.policy.LogRename;
const LogAdd = proto.policy.LogAdd;

// Re-export types for convenience
pub const FieldRef = types.FieldRef;
pub const FieldAccessor = types.FieldAccessor;
pub const FieldMutator = types.FieldMutator;
pub const MutateOp = types.MutateOp;

/// Result of applying transforms
pub const TransformResult = struct {
    /// Number of remove operations applied
    removes_applied: usize = 0,
    /// Number of redact operations applied
    redacts_applied: usize = 0,
    /// Number of rename operations applied
    renames_applied: usize = 0,
    /// Number of add operations applied
    adds_applied: usize = 0,

    pub fn totalApplied(self: TransformResult) usize {
        return self.removes_applied + self.redacts_applied + self.renames_applied + self.adds_applied;
    }
};

/// Apply all transforms from a LogTransform in order: remove → redact → rename → add
pub fn applyTransforms(
    transform: *const LogTransform,
    ctx: *anyopaque,
    accessor: *const FieldAccessor,
    mutator: *const FieldMutator,
) TransformResult {
    var result = TransformResult{};

    // 1. Remove
    for (transform.remove.items) |*rule| {
        if (applyRemove(rule, ctx, mutator)) {
            result.removes_applied += 1;
        }
    }

    // 2. Redact
    for (transform.redact.items) |*rule| {
        if (applyRedact(rule, ctx, accessor, mutator)) {
            result.redacts_applied += 1;
        }
    }

    // 3. Rename
    for (transform.rename.items) |*rule| {
        if (applyRename(rule, ctx, accessor, mutator)) {
            result.renames_applied += 1;
        }
    }

    // 4. Add
    for (transform.add.items) |*rule| {
        if (applyAdd(rule, ctx, accessor, mutator)) {
            result.adds_applied += 1;
        }
    }

    return result;
}

/// Apply a single remove rule
/// Returns true if the field was removed
pub fn applyRemove(
    rule: *const LogRemove,
    ctx: *anyopaque,
    mutator: *const FieldMutator,
) bool {
    const field_ref = FieldRef.fromRemoveField(rule.field) orelse return false;
    return mutator(ctx, .{ .remove = field_ref });
}

/// Apply a single redact rule
/// Replaces the field value with the replacement string
/// Returns true if the field was redacted
pub fn applyRedact(
    rule: *const LogRedact,
    ctx: *anyopaque,
    accessor: *const FieldAccessor,
    mutator: *const FieldMutator,
) bool {
    const field_ref = FieldRef.fromRedactField(rule.field) orelse return false;

    // Only redact if the field exists
    if (accessor(ctx, field_ref) == null) return false;

    // Replace the value with the replacement string
    return mutator(ctx, .{
        .set = .{
            .field = field_ref,
            .value = rule.replacement,
            .upsert = false, // Must exist to redact
        },
    });
}

/// Apply a single rename rule
/// Moves the value from one field to another
/// Returns true if the field was renamed
pub fn applyRename(
    rule: *const LogRename,
    ctx: *anyopaque,
    accessor: *const FieldAccessor,
    mutator: *const FieldMutator,
) bool {
    const from_ref = FieldRef.fromRenameFrom(rule.from) orelse return false;

    // Check the source value exists
    if (accessor(ctx, from_ref) == null) {
        // Source doesn't exist - nothing to rename
        return false;
    }

    // Perform the rename operation
    return mutator(ctx, .{
        .rename = .{
            .from = from_ref,
            .to = rule.to,
            .upsert = rule.upsert,
        },
    });
}

/// Apply a single add rule
/// Inserts a field with the given value
/// If upsert is false, only adds if field doesn't exist
/// Returns true if the field was added/updated
pub fn applyAdd(
    rule: *const LogAdd,
    ctx: *anyopaque,
    accessor: *const FieldAccessor,
    mutator: *const FieldMutator,
) bool {
    const field_ref = FieldRef.fromAddField(rule.field) orelse return false;

    // Check if field already exists
    const exists = accessor(ctx, field_ref) != null;

    // If not upsert and field exists, don't overwrite
    if (!rule.upsert and exists) return false;

    return mutator(ctx, .{
        .set = .{
            .field = field_ref,
            .value = rule.value,
            .upsert = rule.upsert,
        },
    });
}

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;

/// Test context that holds a simple key-value store
const TestContext = struct {
    fields: std.StringHashMap([]const u8),
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) TestContext {
        return .{
            .fields = std.StringHashMap([]const u8).init(allocator),
            .allocator = allocator,
        };
    }

    fn deinit(self: *TestContext) void {
        var it = self.fields.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.fields.deinit();
    }

    fn set(self: *TestContext, key: []const u8, value: []const u8) !void {
        const value_copy = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(value_copy);

        const gop = try self.fields.getOrPut(key);
        if (gop.found_existing) {
            // Key already exists - just update the value
            self.allocator.free(gop.value_ptr.*);
            gop.value_ptr.* = value_copy;
        } else {
            // New key - need to dupe it
            gop.key_ptr.* = try self.allocator.dupe(u8, key);
            gop.value_ptr.* = value_copy;
        }
    }

    fn fieldAccessor(ctx: *const anyopaque, field: FieldRef) ?[]const u8 {
        const self: *const TestContext = @ptrCast(@alignCast(ctx));
        const key = switch (field) {
            .log_field => |f| @tagName(f),
            .log_attribute => |k| k,
            .resource_attribute => |k| k,
            .scope_attribute => |k| k,
        };
        return self.fields.get(key);
    }

    fn fieldMutator(ctx: *anyopaque, op: MutateOp) bool {
        const self: *TestContext = @ptrCast(@alignCast(ctx));
        switch (op) {
            .remove => |field| {
                const key = switch (field) {
                    .log_field => |f| @tagName(f),
                    .log_attribute => |k| k,
                    .resource_attribute => |k| k,
                    .scope_attribute => |k| k,
                };
                if (self.fields.fetchRemove(key)) |removed| {
                    self.allocator.free(removed.key);
                    self.allocator.free(removed.value);
                    return true;
                }
                return false;
            },
            .set => |s| {
                const key = switch (s.field) {
                    .log_field => |f| @tagName(f),
                    .log_attribute => |k| k,
                    .resource_attribute => |k| k,
                    .scope_attribute => |k| k,
                };
                const exists = self.fields.contains(key);
                if (!s.upsert and !exists) return false;

                self.set(key, s.value) catch return false;
                return true;
            },
            .rename => |r| {
                const from_key = switch (r.from) {
                    .log_field => |f| @tagName(f),
                    .log_attribute => |k| k,
                    .resource_attribute => |k| k,
                    .scope_attribute => |k| k,
                };

                // Get and remove the source value
                const removed = self.fields.fetchRemove(from_key) orelse return false;
                defer self.allocator.free(removed.key);

                // Check if target exists
                const target_exists = self.fields.contains(r.to);
                if (!r.upsert and target_exists) {
                    // Put the value back since we can't rename
                    self.fields.put(removed.key, removed.value) catch {};
                    return false;
                }

                // Set the new field
                self.set(r.to, removed.value) catch {
                    // Put the value back on failure
                    self.fields.put(removed.key, removed.value) catch {};
                    return false;
                };
                self.allocator.free(removed.value);
                return true;
            },
        }
    }
};

test "applyRemove: removes existing field" {
    const allocator = testing.allocator;
    var ctx = TestContext.init(allocator);
    defer ctx.deinit();

    try ctx.set("service", "payment-api");

    var rule = LogRemove{
        .field = .{ .log_attribute = "service" },
    };

    const result = applyRemove(&rule, @ptrCast(&ctx), &TestContext.fieldMutator);
    try testing.expect(result);
    try testing.expect(ctx.fields.get("service") == null);
}

test "applyRemove: returns false for non-existent field" {
    const allocator = testing.allocator;
    var ctx = TestContext.init(allocator);
    defer ctx.deinit();

    var rule = LogRemove{
        .field = .{ .log_attribute = "nonexistent" },
    };

    const result = applyRemove(&rule, @ptrCast(&ctx), &TestContext.fieldMutator);
    try testing.expect(!result);
}

test "TestContext: set and update" {
    const allocator = testing.allocator;
    var ctx = TestContext.init(allocator);
    defer ctx.deinit();

    try ctx.set("key", "value1");
    try testing.expectEqualStrings("value1", ctx.fields.get("key").?);

    try ctx.set("key", "value2");
    try testing.expectEqualStrings("value2", ctx.fields.get("key").?);
}

test "applyRedact: replaces field value" {
    const allocator = testing.allocator;
    var ctx = TestContext.init(allocator);
    defer ctx.deinit();

    try ctx.set("password", "secret123");
    try testing.expectEqualStrings("secret123", ctx.fields.get("password").?);

    var rule = LogRedact{
        .field = .{ .log_attribute = "password" },
        .replacement = "[REDACTED]",
    };

    const result = applyRedact(&rule, @ptrCast(&ctx), &TestContext.fieldAccessor, &TestContext.fieldMutator);
    try testing.expect(result);
    try testing.expectEqualStrings("[REDACTED]", ctx.fields.get("password").?);
}

test "applyRedact: returns false for non-existent field" {
    const allocator = testing.allocator;
    var ctx = TestContext.init(allocator);
    defer ctx.deinit();

    var rule = LogRedact{
        .field = .{ .log_attribute = "nonexistent" },
        .replacement = "[REDACTED]",
    };

    const result = applyRedact(&rule, @ptrCast(&ctx), &TestContext.fieldAccessor, &TestContext.fieldMutator);
    try testing.expect(!result);
}

test "applyRename: renames existing field" {
    const allocator = testing.allocator;
    var ctx = TestContext.init(allocator);
    defer ctx.deinit();

    try ctx.set("old_name", "value123");

    var rule = LogRename{
        .from = .{ .from_log_attribute = "old_name" },
        .to = "new_name",
        .upsert = true,
    };

    const result = applyRename(&rule, @ptrCast(&ctx), &TestContext.fieldAccessor, &TestContext.fieldMutator);
    try testing.expect(result);
    try testing.expect(ctx.fields.get("old_name") == null);
    try testing.expectEqualStrings("value123", ctx.fields.get("new_name").?);
}

test "applyRename: returns false for non-existent source" {
    const allocator = testing.allocator;
    var ctx = TestContext.init(allocator);
    defer ctx.deinit();

    var rule = LogRename{
        .from = .{ .from_log_attribute = "nonexistent" },
        .to = "new_name",
        .upsert = true,
    };

    const result = applyRename(&rule, @ptrCast(&ctx), &TestContext.fieldAccessor, &TestContext.fieldMutator);
    try testing.expect(!result);
}

test "applyAdd: adds new field" {
    const allocator = testing.allocator;
    var ctx = TestContext.init(allocator);
    defer ctx.deinit();

    var rule = LogAdd{
        .field = .{ .log_attribute = "new_field" },
        .value = "new_value",
        .upsert = true,
    };

    const result = applyAdd(&rule, @ptrCast(&ctx), &TestContext.fieldAccessor, &TestContext.fieldMutator);
    try testing.expect(result);
    try testing.expectEqualStrings("new_value", ctx.fields.get("new_field").?);
}

test "applyAdd: upsert=false skips existing field" {
    const allocator = testing.allocator;
    var ctx = TestContext.init(allocator);
    defer ctx.deinit();

    try ctx.set("existing", "original");

    var rule = LogAdd{
        .field = .{ .log_attribute = "existing" },
        .value = "new_value",
        .upsert = false,
    };

    const result = applyAdd(&rule, @ptrCast(&ctx), &TestContext.fieldAccessor, &TestContext.fieldMutator);
    try testing.expect(!result);
    try testing.expectEqualStrings("original", ctx.fields.get("existing").?);
}

test "applyAdd: upsert=true overwrites existing field" {
    const allocator = testing.allocator;
    var ctx = TestContext.init(allocator);
    defer ctx.deinit();

    try ctx.set("existing", "original");

    var rule = LogAdd{
        .field = .{ .log_attribute = "existing" },
        .value = "new_value",
        .upsert = true,
    };

    const result = applyAdd(&rule, @ptrCast(&ctx), &TestContext.fieldAccessor, &TestContext.fieldMutator);
    try testing.expect(result);
    try testing.expectEqualStrings("new_value", ctx.fields.get("existing").?);
}

test "applyTransforms: applies in correct order" {
    const allocator = testing.allocator;
    var ctx = TestContext.init(allocator);
    defer ctx.deinit();

    // Setup initial state
    try ctx.set("to_remove", "value1");
    try ctx.set("to_redact", "sensitive");
    try ctx.set("to_rename", "rename_me");

    // Build transform with all operation types
    var transform = LogTransform{};

    // Remove
    try transform.remove.append(allocator, .{
        .field = .{ .log_attribute = "to_remove" },
    });

    // Redact
    try transform.redact.append(allocator, .{
        .field = .{ .log_attribute = "to_redact" },
        .replacement = "[HIDDEN]",
    });

    // Rename
    try transform.rename.append(allocator, .{
        .from = .{ .from_log_attribute = "to_rename" },
        .to = "renamed",
        .upsert = true,
    });

    // Add
    try transform.add.append(allocator, .{
        .field = .{ .log_attribute = "added" },
        .value = "new_value",
        .upsert = true,
    });

    defer transform.remove.deinit(allocator);
    defer transform.redact.deinit(allocator);
    defer transform.rename.deinit(allocator);
    defer transform.add.deinit(allocator);

    const result = applyTransforms(
        &transform,
        @ptrCast(&ctx),
        &TestContext.fieldAccessor,
        &TestContext.fieldMutator,
    );

    try testing.expectEqual(@as(usize, 1), result.removes_applied);
    try testing.expectEqual(@as(usize, 1), result.redacts_applied);
    try testing.expectEqual(@as(usize, 1), result.renames_applied);
    try testing.expectEqual(@as(usize, 1), result.adds_applied);
    try testing.expectEqual(@as(usize, 4), result.totalApplied());

    // Verify final state
    try testing.expect(ctx.fields.get("to_remove") == null);
    try testing.expectEqualStrings("[HIDDEN]", ctx.fields.get("to_redact").?);
    try testing.expect(ctx.fields.get("to_rename") == null);
    try testing.expectEqualStrings("rename_me", ctx.fields.get("renamed").?);
    try testing.expectEqualStrings("new_value", ctx.fields.get("added").?);
}
