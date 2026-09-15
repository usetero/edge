//! Records extension callback ordering and verifies the outer publication gate.
const Self = @This();

const std = @import("std");
const policy = @import("policy_zig");
const PolicyStore = @import("../PolicyStore.zig");

store: *PolicyStore,
configured: usize = 0,
resolved: usize = 0,
capability_calls: usize = 0,
gate_violation: bool = false,
order_violation: bool = false,

pub fn hooks(self: *Self) policy.ExtensionSyncHooks {
    return .{ .ctx = self, .capabilities = capabilities, .apply_configs = applyConfigs };
}

pub fn resolver(self: *Self) policy.types.ExtensionResolver {
    return .{ .ctx = self, .resolve = resolve };
}

fn capabilities(io: std.Io, ctx: *anyopaque, arena: std.mem.Allocator) ![]policy.proto.policy.ExtensionCapability {
    const self: *Self = @ptrCast(@alignCast(ctx));
    self.capability_calls += 1;
    if (self.store.gate.tryLock(io)) {
        self.store.gate.unlock(io);
        self.gate_violation = true;
    }
    const result = try arena.alloc(policy.proto.policy.ExtensionCapability, 1);
    result[0] = .{ .type = try arena.dupe(u8, "test/probe") };
    return result;
}

fn applyConfigs(io: std.Io, ctx: *anyopaque, configs: []const policy.proto.policy.ExtensionConfig) void {
    const self: *Self = @ptrCast(@alignCast(ctx));
    self.checkExclusive(io);
    for (configs) |config| {
        if (std.mem.eql(u8, config.type, "test/probe")) self.configured += 1;
    }
}

fn resolve(
    io: std.Io,
    ctx: *anyopaque,
    _: policy.TelemetryType,
    _: []const u8,
    extension: *const policy.proto.policy.Extension,
) ?policy.types.ExtensionResolution {
    const self: *Self = @ptrCast(@alignCast(ctx));
    self.checkExclusive(io);
    if (!std.mem.eql(u8, extension.type, "test/probe")) return null;
    self.resolved += 1;
    if (self.configured == 0) self.order_violation = true;
    return .{ .handler = 0, .slot = 0 };
}

fn checkExclusive(self: *Self, io: std.Io) void {
    // Probe the lock directly: pending writer admission alone does not prove
    // exclusion. Always release unexpected acquisition before failing a test.
    if (self.store.gate.tryLockShared(io)) {
        self.store.gate.unlockShared(io);
        self.gate_violation = true;
    }
}
