//! Reader lifetime boundary for the unchanged policy-zig registry.
const Self = @This();

const std = @import("std");
const policy = @import("policy_zig");

registry: policy.Registry,
gate: std.Io.RwLock = .init,
pending_updates: std.atomic.Value(u32) = .init(0),
state: enum { available, quarantined } = .available,
updates_started: bool = false,

pub const DeinitResult = enum { released, quarantined };

pub const Read = union(enum) {
    ready: ReadGuard,
    busy,
    unavailable,
};

pub const ReadGuard = struct {
    store: *Self,

    /// End the borrow only after consuming snapshot fields and engine results.
    pub fn deinit(self: *ReadGuard, io: std.Io) void {
        self.store.gate.unlockShared(io);
        self.* = undefined;
    }

    /// The pointer and all nested slices are borrowed until this guard ends.
    pub fn snapshot(self: *const ReadGuard) ?*const policy.Snapshot {
        return self.store.registry.getSnapshot();
    }

    /// Neither the engine nor its borrowed results may outlive this guard.
    pub fn engine(self: *const ReadGuard) policy.PolicyEngine {
        return .init(self.store.registry.bus, &self.store.registry);
    }
};

/// Caller-owned callback storage. Keep it and the store alive until the provider
/// is stopped and joined, including when subscribe returns an error: providers
/// can retain a callback before delivering their initial update.
pub const Binding = struct {
    store: *Self,
    io: std.Io,
    source_type: policy.SourceType,
    extension_hooks: ?policy.ExtensionSyncHooks,

    /// Use public provider hooks so future updates cannot bypass the outer gate.
    pub fn init(
        self: *Binding,
        store: *Self,
        io: std.Io,
        provider: policy.Provider,
        extension_hooks: ?policy.ExtensionSyncHooks,
    ) !void {
        self.* = .{
            .store = store,
            .io = io,
            .source_type = provider.sourceType(),
            .extension_hooks = extension_hooks,
        };
        provider.setStatsCollector(self.statsCollector());
        if (extension_hooks != null) provider.setExtensionSyncHooks(.{
            .ctx = self,
            .capabilities = capabilities,
            .apply_configs = applyConfigs,
        });
        try provider.subscribe(.{ .context = self, .onUpdate = onUpdate });
    }

    /// The provider invokes this on its control-plane thread, not a reactor.
    pub fn statsCollector(self: *Binding) policy.provider.StatsCollector {
        return .{ .context = self, .collect = collect, .collect_volume = drainVolume };
    }

    fn onUpdate(context: *anyopaque, change: policy.PolicyUpdate) anyerror!void {
        const self: *Binding = @ptrCast(@alignCast(context));
        try self.store.update(self.io, change, self.source_type);
    }

    fn collect(
        allocator: std.mem.Allocator,
        context: *anyopaque,
    ) anyerror![]policy.provider.PolicyStatsSnapshot {
        const self: *Binding = @ptrCast(@alignCast(context));
        return self.store.collectStats(allocator, self.io);
    }

    fn drainVolume(context: *anyopaque) policy.provider.VolumeSnapshot {
        const self: *Binding = @ptrCast(@alignCast(context));
        self.store.gate.lockSharedUncancelable(self.io);
        defer self.store.gate.unlockShared(self.io);
        if (self.store.state != .available) return .{};
        return self.store.registry.volume.readAndReset();
    }

    fn capabilities(
        _: std.Io,
        context: *anyopaque,
        arena: std.mem.Allocator,
    ) anyerror![]policy.proto.policy.ExtensionCapability {
        const self: *Binding = @ptrCast(@alignCast(context));
        try self.store.gate.lockShared(self.io);
        defer self.store.gate.unlockShared(self.io);
        if (self.store.state != .available) return error.PolicyUnavailable;
        const hooks = self.extension_hooks.?;
        return hooks.capabilities(self.io, hooks.ctx, arena);
    }

    fn applyConfigs(_: std.Io, context: *anyopaque, configs: []const policy.proto.policy.ExtensionConfig) void {
        const self: *Binding = @ptrCast(@alignCast(context));
        _ = self.store.pending_updates.fetchAdd(1, .acq_rel);
        defer _ = self.store.pending_updates.fetchSub(1, .release);
        self.store.gate.lockUncancelable(self.io);
        defer self.store.gate.unlock(self.io);
        if (self.store.state != .available) return;
        const hooks = self.extension_hooks.?;
        hooks.apply_configs(self.io, hooks.ctx, configs);
    }
};

/// Keep this store at a stable address from the first binding/read until teardown.
pub fn init(allocator: std.mem.Allocator, bus: *policy.observability.EventBus) Self {
    return .{ .registry = .init(allocator, bus) };
}

/// Stop/join providers and readers first. Retain a failed registry until process
/// exit: failed replacement is not transactional, even with safe OOM cleanup.
pub fn deinit(self: *Self, io: std.Io) DeinitResult {
    self.gate.lockUncancelable(io);
    defer self.* = undefined;
    defer self.gate.unlock(io);
    std.debug.assert(self.pending_updates.load(.acquire) == 0);
    if (self.state == .quarantined) return .quarantined;
    self.registry.deinit();
    return .released;
}

/// Data-plane callers bypass processing instead of waiting behind compilation.
pub fn tryRead(self: *Self, io: std.Io) Read {
    if (self.pending_updates.load(.acquire) != 0) return .busy;
    if (!self.gate.tryLockShared(io)) return .busy;
    if (self.state != .available) {
        self.gate.unlockShared(io);
        return .unavailable;
    }
    return .{ .ready = .{ .store = self } };
}

/// Install before any update. Resolver callbacks run under the exclusive gate;
/// they and extension hooks must not reenter this store or retain borrowed data.
/// Keep their contexts alive until providers and the registry have been destroyed.
pub fn setExtensionResolver(self: *Self, io: std.Io, resolver: policy.types.ExtensionResolver) !void {
    try self.gate.lock(io);
    defer self.gate.unlock(io);
    if (self.state != .available) return error.PolicyUnavailable;
    if (self.updates_started) return error.PolicyUpdatesStarted;
    self.registry.setExtensionResolver(resolver);
}

/// The provider owns update slices until this synchronous call returns.
pub fn update(self: *Self, io: std.Io, change: policy.PolicyUpdate, source_type: policy.SourceType) !void {
    _ = self.pending_updates.fetchAdd(1, .acq_rel);
    defer _ = self.pending_updates.fetchSub(1, .release);
    try self.gate.lock(io);
    defer self.gate.unlock(io);
    if (self.state != .available) return error.PolicyUnavailable;
    self.updates_started = true;
    self.registry.updatePolicies(change.policies, change.provider_id, source_type) catch |err| {
        self.state = .quarantined;
        return err;
    };
}

/// Stats copies outlive the guard; the dependency loads its snapshot before
/// taking its own mutex, so guarding only evaluation would leave a race here.
pub fn collectStats(self: *Self, allocator: std.mem.Allocator, io: std.Io) ![]policy.provider.PolicyStatsSnapshot {
    try self.gate.lockShared(io);
    defer self.gate.unlockShared(io);
    if (self.state != .available) return error.PolicyUnavailable;
    return self.registry.collectStats(allocator);
}

test "v2 policy store permits guarded reads before the first policy arrives" {
    const io = std.testing.io;
    var bus: policy.observability.NoopEventBus = undefined;
    bus.init(io);
    var store: Self = .init(std.testing.allocator, bus.eventBus());
    defer _ = store.deinit(io);

    var read = store.tryRead(io);
    try std.testing.expect(read == .ready);
    defer read.ready.deinit(io);
    try std.testing.expect(read.ready.snapshot() == null);
}

test "v2 policy store binds public providers and preserves policy evaluation" {
    const io = std.testing.io;
    var bus: policy.observability.NoopEventBus = undefined;
    bus.init(io);
    var store: Self = .init(std.testing.allocator, bus.eventBus());
    defer _ = store.deinit(io);
    var provider: policy.TestProvider = .init(std.testing.allocator, "local", .file);
    defer provider.deinit();
    const policies = try policy.parser.parsePoliciesBytes(std.testing.allocator,
        \\{"policies":[{"id":"drop-debug","name":"drop-debug","log":{
        \\  "match":[{"log_field":"body","exact":"debug"}],"keep":"none"
        \\}}]}
    );
    defer freeTestPolicies(policies);
    try provider.addPolicy(policies[0]);
    var binding: Binding = undefined;
    try binding.init(&store, io, provider.provider(), null);

    var read = store.tryRead(io);
    try std.testing.expect(read == .ready);
    defer read.ready.deinit(io);
    var engine = read.ready.engine();
    var ids: [256][]const u8 = undefined;
    var record: TestLog = .{ .body = "debug" };
    const dropped = engine.evaluate(.log, &TestLog.accessor, &record, &ids, .{ .io = io });
    try std.testing.expectEqual(policy.FilterDecision.drop, dropped.decision);
    record.body = "info";
    const kept = engine.evaluate(.log, &TestLog.accessor, &record, &ids, .{ .io = io });
    try std.testing.expect(kept.decision != .drop);
}

test "v2 policy store fences callback stats and teardown after observable update failure" {
    const io = std.testing.io;
    var failing: std.testing.FailingAllocator = .init(std.testing.allocator, .{ .fail_index = 0 });
    var bus: policy.observability.NoopEventBus = undefined;
    bus.init(io);
    var store: Self = .init(failing.allocator(), bus.eventBus());
    var store_active = true;
    defer if (store_active) {
        _ = store.deinit(io);
    };
    var provider: policy.TestProvider = .init(std.testing.allocator, "local", .file);
    defer provider.deinit();
    // This first-allocation case checks callback fencing. The exhaustive test
    // below covers containment after deeper publish/replacement failures.
    try provider.addPolicy(.{ .id = "p", .name = "p", .enabled = true });
    var binding: Binding = undefined;
    try std.testing.expectError(error.OutOfMemory, binding.init(&store, io, provider.provider(), null));
    try expectBypass(&store, io, .unavailable);
    try std.testing.expectError(error.PolicyUnavailable, provider.notifySubscribers());
    try std.testing.expectError(error.PolicyUnavailable, binding.statsCollector().call(std.testing.allocator));
    try std.testing.expectEqual(@as(usize, 0), failing.allocated_bytes);
    // The caller must join providers before destroying the callback target.
    // TestProvider has no threads; deinit below never invokes its callbacks.
    const disposition = store.deinit(io);
    store_active = false;
    try std.testing.expectEqual(DeinitResult.quarantined, disposition);
}

test "v2 policy store contains every publish and replacement allocation failure" {
    const count = try allocationProbe(std.math.maxInt(usize));
    for (0..count) |index| _ = try allocationProbe(index);
    if (std.testing.environ.getPosix("TERO_V2_ALLOC_PROBE") != null) {
        std.debug.print("\nv2 allocation containment: {d} failure points passed\n", .{count});
    }
}

test "v2 policy store dependency cleanup is leak free after allocation failure" {
    // Required regression for the local policy-zig ownership fixes. Keep direct
    // dependency teardown here to detect leaks hidden by Edge's quarantine.
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        replaceUnderFailingAllocator,
        .{std.testing.io},
    );
}

fn allocationProbe(index: usize) !usize {
    // A plain arena exercises the dependency's declared allocation alignment.
    // The separate direct cleanup test detects ownership leaks with DebugAllocator.
    // Production does not use a growing arena across successful policy reloads.
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var failing: std.testing.FailingAllocator = .init(arena.allocator(), .{ .fail_index = index });
    replaceUnderFailingAllocator(failing.allocator(), std.testing.io) catch |err| {
        if (err != error.OutOfMemory) return err;
        try std.testing.expect(failing.has_induced_failure);
        return failing.alloc_index;
    };
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(std.math.maxInt(usize), index);
    return failing.alloc_index;
}

fn replaceUnderFailingAllocator(allocator: std.mem.Allocator, io: std.Io) !void {
    var bus: policy.observability.NoopEventBus = undefined;
    bus.init(io);
    var store: Self = .init(allocator, bus.eventBus());
    // Test direct dependency destruction even after Edge has fenced its reads.
    // Otherwise intentional quarantine retention would mask dependency regressions.
    defer store.registry.deinit();
    var first_match = try matchers(allocator, "body");
    defer first_match.deinit(allocator);
    const first = [_]policy.proto.policy.Policy{
        .{ .id = "keep-all", .name = "keep-all", .enabled = true, .target = .{ .log = .{
            .match = first_match,
            .keep = "all",
        } } },
    };
    try publishForAllocationTest(&store, io, &first);
    var second_match = try matchers(allocator, "debug");
    defer second_match.deinit(allocator);
    const second = [_]policy.proto.policy.Policy{
        .{ .id = "keep-all", .name = "drop-debug", .enabled = true, .target = .{ .log = .{
            .match = second_match,
            .keep = "none",
        } } },
    };
    try publishForAllocationTest(&store, io, &second);
    // Duplicate ids in a batch previously leaked an owned hash-map key.
    try publishForAllocationTest(&store, io, &.{ second[0], second[0] });
    try publishForAllocationTest(&store, io, &.{});
}

fn publishForAllocationTest(store: *Self, io: std.Io, policies: []const policy.proto.policy.Policy) !void {
    store.update(io, .{ .provider_id = "probe", .policies = policies }, .file) catch |err| {
        try expectBypass(store, io, .unavailable);
        try std.testing.expectEqual(@as(u32, 0), store.pending_updates.load(.acquire));
        try std.testing.expectError(error.PolicyUnavailable, store.collectStats(std.testing.allocator, io));
        return err;
    };
}

fn matchers(allocator: std.mem.Allocator, needle: []const u8) !std.ArrayList(policy.proto.policy.LogMatcher) {
    var list: std.ArrayList(policy.proto.policy.LogMatcher) = .empty;
    errdefer list.deinit(allocator);
    try list.append(allocator, .{ .field = .{ .log_field = .LOG_FIELD_BODY }, .match = .{ .contains = needle } });
    return list;
}

const TestLog = struct {
    body: []const u8,
    const accessor: policy.LogAccessor = .{ .typed_value = typedValue };

    fn typedValue(ctx: *const anyopaque, field: policy.FieldRef) ?policy.TypedValue {
        const record: *const TestLog = @ptrCast(@alignCast(ctx));
        return switch (field) {
            .log_field => |f| if (f == .LOG_FIELD_BODY) .{ .string = record.body } else null,
            else => null,
        };
    }
};

fn freeTestPolicies(policies: []policy.proto.policy.Policy) void {
    for (policies) |*p| p.deinit(std.testing.allocator);
    std.testing.allocator.free(policies);
}

test "v2 policy store copies stats before provider replacement" {
    const io = std.testing.io;
    var bus: policy.observability.NoopEventBus = undefined;
    bus.init(io);
    var store: Self = .init(std.testing.allocator, bus.eventBus());
    defer _ = store.deinit(io);
    var provider: policy.TestProvider = .init(std.testing.allocator, "local", .file);
    defer provider.deinit();
    try provider.addPolicy(.{ .id = "before", .name = "before", .enabled = true });
    var binding: Binding = undefined;
    try binding.init(&store, io, provider.provider(), null);
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const stats = try binding.statsCollector().call(arena.allocator());
    provider.clearPolicies();
    try provider.addPolicy(.{ .id = "after", .name = "after", .enabled = true });
    try provider.notifySubscribers();
    try std.testing.expectEqual(@as(usize, 1), stats.len);
    try std.testing.expectEqualStrings("before", stats[0].id);
    const current = try binding.statsCollector().call(arena.allocator());
    try std.testing.expectEqualStrings("after", current[0].id);
}

test "v2 policy store protects a delayed reader and blocks new readers behind updates" {
    const io = std.testing.io;
    var bus: policy.observability.NoopEventBus = undefined;
    bus.init(io);
    var store: Self = .init(std.testing.allocator, bus.eventBus());
    defer _ = store.deinit(io);
    const before: policy.proto.policy.Policy = .{ .id = "before", .name = "before", .enabled = true };
    try store.update(io, .{ .provider_id = "local", .policies = &.{before} }, .file);
    var read = store.tryRead(io);
    try std.testing.expect(read == .ready);
    var read_active = true;
    defer if (read_active) read.ready.deinit(io);
    const snapshot = read.ready.snapshot().?;
    var updating: TestUpdate = .{ .store = &store, .io = io };
    const thread = try std.Thread.spawn(.{}, TestUpdate.run, .{&updating});
    defer {
        if (read_active) {
            read.ready.deinit(io);
            read_active = false;
        }
        thread.join();
    }
    try waitForUpdate(&store, io);
    try expectBypass(&store, io, .busy);
    // Deliberately hold the real snapshot beyond the dependency's 100 ms grace.
    try io.sleep(.fromMilliseconds(150), .awake);
    try std.testing.expect(!updating.done.isSet());
    try std.testing.expectEqualStrings("before", snapshot.policies[0].id);
    read.ready.deinit(io);
    read_active = false;
    try updating.done.waitTimeout(io, .{ .duration = .{ .raw = .fromSeconds(5), .clock = .awake } });
    if (updating.err) |err| return err;

    // Reclamation under >8 updates is safe after the reader relinquishes its lease.
    for (0..10) |_| try TestUpdate.replace(&store, io);
    var latest = store.tryRead(io);
    try std.testing.expect(latest == .ready);
    defer latest.ready.deinit(io);
    try std.testing.expectEqualStrings("after", latest.ready.snapshot().?.policies[0].id);
}

const TestUpdate = struct {
    store: *Self,
    io: std.Io,
    done: std.Io.Event = .unset,
    err: ?anyerror = null,

    fn run(self: *TestUpdate) void {
        replace(self.store, self.io) catch |err| {
            self.err = err;
        };
        self.done.set(self.io);
    }

    fn replace(store: *Self, io: std.Io) !void {
        const replacement: policy.proto.policy.Policy = .{ .id = "after", .name = "after", .enabled = true };
        try store.update(io, .{ .provider_id = "local", .policies = &.{replacement} }, .file);
    }
};

fn waitForUpdate(store: *Self, io: std.Io) !void {
    for (0..1000) |_| {
        if (store.pending_updates.load(.acquire) != 0) return;
        try io.sleep(.fromMilliseconds(1), .awake);
    }
    return error.TestUpdateDidNotStart;
}

fn expectBypass(store: *Self, io: std.Io, expected: Read) !void {
    var actual = store.tryRead(io);
    // Release an unexpected lease before reporting failure, otherwise teardown
    // would deadlock and hide the regression this assertion is meant to detect.
    defer if (actual == .ready) actual.ready.deinit(io);
    try std.testing.expectEqual(expected, actual);
}

test "v2 policy store provider volume drains once including records without policies" {
    const io = std.testing.io;
    var bus: policy.observability.NoopEventBus = undefined;
    bus.init(io);
    var store: Self = .init(std.testing.allocator, bus.eventBus());
    defer _ = store.deinit(io);
    var provider: policy.TestProvider = .init(std.testing.allocator, "local", .file);
    defer provider.deinit();
    var binding: Binding = undefined;
    try binding.init(&store, io, provider.provider(), null);
    {
        var read = store.tryRead(io);
        try std.testing.expect(read == .ready);
        defer read.ready.deinit(io);
        var engine = read.ready.engine();
        var ids: [256][]const u8 = undefined;
        var record: TestLog = .{ .body = "info" };
        _ = engine.evaluate(.log, &TestLog.accessor, &record, &ids, .{ .io = io });
        _ = engine.evaluate(.log, &TestLog.accessor, &record, &ids, .{ .io = io });
    }
    const collector = binding.statsCollector();
    try std.testing.expectEqual(@as(i64, 2), collector.drainVolume().log_records);
    try std.testing.expectEqual(@as(i64, 0), collector.drainVolume().log_records);
}

test "v2 policy store reports clean teardown when no update failed" {
    const io = std.testing.io;
    var bus: policy.observability.NoopEventBus = undefined;
    bus.init(io);
    var store: Self = .init(std.testing.allocator, bus.eventBus());
    try std.testing.expectEqual(DeinitResult.released, store.deinit(io));
}
