//! Fixed provider slots keep callback targets alive through shutdown and final sync.
const Self = @This();

const std = @import("std");
const policy = @import("policy_zig");
const PolicyStore = @import("PolicyStore.zig");

slots: []Slot,
state: enum { fresh, started, closed } = .fresh,

pub const Slot = struct {
    provider: ?policy.Provider = null,
    binding: PolicyStore.Binding = undefined,
    start_error: ?anyerror = null,
    close_error: ?anyerror = null,
};

pub const Options = struct {
    bus: *policy.observability.EventBus,
    service: policy.ServiceMetadata = .{},
    extension_hooks: ?policy.ExtensionSyncHooks = null,
};

/// Allocate every callback slot before any provider can publish or spawn a thread.
pub fn init(allocator: std.mem.Allocator, provider_count: usize) !Self {
    const slots = try allocator.alloc(Slot, provider_count);
    @memset(slots, .{});
    return .{ .slots = slots };
}

/// Destruction joins all pollers but does not initiate a final network sync.
/// Call close explicitly while the store, extension hooks and I/O remain alive.
pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
    defer self.* = undefined;
    self.stopAll();
    for (self.slots) |slot| if (slot.provider) |provider| provider.deinit();
    allocator.free(self.slots);
}

/// Failed providers remain observable per slot and cannot prevent other sources
/// from starting. HTTP subscribe success does not imply a successful initial sync.
pub fn start(
    self: *Self,
    allocator: std.mem.Allocator,
    io: std.Io,
    store: *PolicyStore,
    configs: []const policy.ProviderConfig,
    options: Options,
) void {
    std.debug.assert(self.state == .fresh);
    std.debug.assert(configs.len == self.slots.len);
    self.state = .started;
    for (self.slots, configs) |*slot, config| {
        const provider = createProvider(allocator, io, config, options) catch |err| {
            slot.start_error = err;
            continue;
        };
        slot.provider = provider;
        slot.binding.init(store, io, provider, options.extension_hooks) catch |err| {
            slot.start_error = err;
        };
    }
}

/// Stop every background publisher before final HTTP syncs, whose callbacks can
/// still update the store. Attempt each provider once even if an earlier one fails.
pub fn close(self: *Self) !void {
    if (self.state == .closed) return;
    self.state = .closed;
    self.stopAll();
    var first_error: ?anyerror = null;
    for (self.slots) |*slot| {
        const provider = slot.provider orelse continue;
        provider.close() catch |err| {
            slot.close_error = err;
            if (first_error == null) first_error = err;
        };
    }
    if (first_error) |err| return err;
}

fn stopAll(self: *Self) void {
    for (self.slots) |slot| {
        const provider = slot.provider orelse continue;
        switch (provider) {
            .file => |p| p.shutdown(),
            .http => |p| p.shutdown(),
            .testing => {},
        }
    }
}

fn createProvider(
    allocator: std.mem.Allocator,
    io: std.Io,
    config: policy.ProviderConfig,
    options: Options,
) !policy.Provider {
    return switch (config.type) {
        .file => .{ .file = try policy.FileProvider.init(allocator, io, options.bus, .{
            .id = config.id,
            .path = config.path orelse return error.FileProviderRequiresPath,
        }) },
        .http => .{ .http = try policy.HttpProvider.init(allocator, io, options.bus, .{
            .id = config.id,
            .url = config.url orelse return error.HttpProviderRequiresUrl,
            .poll_interval_seconds = config.poll_interval orelse 60,
            .headers = config.headers,
            .service = options.service,
        }) },
    };
}

const testing = std.testing;
const SyncServer = @import("testing/SyncServer.zig");
const ExtensionProbe = @import("testing/ExtensionProbe.zig");

test "v2 providers isolate a missing file and close the valid watcher" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{
        .sub_path = "policies.json",
        .data = "{\"policies\":[{\"id\":\"file-policy\",\"name\":\"file-policy\"}]}",
    });
    const path = try tmp.dir.realPathFileAlloc(io, "policies.json", testing.allocator);
    defer testing.allocator.free(path);
    const missing = try std.fmt.allocPrint(testing.allocator, "{s}.missing", .{path});
    defer testing.allocator.free(missing);
    var bus: policy.observability.NoopEventBus = undefined;
    bus.init(io);
    var store: PolicyStore = .init(testing.allocator, bus.eventBus());
    defer _ = store.deinit(io);
    const configs = [_]policy.ProviderConfig{
        .{ .id = "missing", .type = .file, .path = missing },
        .{ .id = "working", .type = .file, .path = path },
    };
    var providers: Self = try .init(testing.allocator, configs.len);
    defer providers.deinit(testing.allocator);
    providers.start(testing.allocator, io, &store, &configs, .{ .bus = bus.eventBus() });
    try testing.expectEqual(error.FileNotFound, providers.slots[0].start_error.?);
    try testing.expect(providers.slots[1].start_error == null);
    try expectPolicy(&store, io, "file-policy");
    try providers.close();
    try testing.expect(providers.slots[1].provider.?.file.watch_thread == null);
    try providers.close();
    try expectPolicy(&store, io, "file-policy");
}

test "v2 providers continue after invalid configuration and support empty startup" {
    const io = testing.io;
    var bus: policy.observability.NoopEventBus = undefined;
    bus.init(io);
    var store: PolicyStore = .init(testing.allocator, bus.eventBus());
    defer _ = store.deinit(io);
    const configs = [_]policy.ProviderConfig{ .{ .id = "no-path" }, .{ .id = "no-url", .type = .http } };
    var providers: Self = try .init(testing.allocator, configs.len);
    defer providers.deinit(testing.allocator);
    providers.start(testing.allocator, io, &store, &configs, .{ .bus = bus.eventBus() });
    try testing.expectEqual(error.FileProviderRequiresPath, providers.slots[0].start_error.?);
    try testing.expectEqual(error.HttpProviderRequiresUrl, providers.slots[1].start_error.?);
    try providers.close();
    var empty: Self = try .init(testing.allocator, 0);
    defer empty.deinit(testing.allocator);
    empty.start(testing.allocator, io, &store, &.{}, .{ .bus = bus.eventBus() });
    try empty.close();
}

fn expectPolicy(store: *PolicyStore, io: std.Io, id: []const u8) !void {
    var read = store.tryRead(io);
    try testing.expect(read == .ready);
    defer read.ready.deinit(io);
    const snapshot = read.ready.snapshot() orelse return error.TestExpectedPolicy;
    try testing.expectEqual(@as(usize, 1), snapshot.policies.len);
    try testing.expectEqualStrings(id, snapshot.policies[0].id);
}

test "v2 providers HTTP final close publishes policies and sends stats exactly once" {
    const io = testing.io;
    var exchanges = [_]SyncServer.Exchange{
        .{ .response = "{\"policies\":[{\"id\":\"initial\",\"name\":\"initial\"}],\"hash\":\"first\"}" },
        .{ .response = "{\"policies\":[{\"id\":\"final\",\"name\":\"final\"}],\"hash\":\"last\"}" },
    };
    var server: SyncServer = undefined;
    try server.init(testing.allocator, io, &exchanges);
    defer server.deinit(testing.allocator, io);
    var url_buffer: [128]u8 = undefined;
    const configs = [_]policy.ProviderConfig{
        .{ .id = "remote", .type = .http, .url = try server.url(&url_buffer), .poll_interval = 3600 },
    };
    var bus: policy.observability.NoopEventBus = undefined;
    bus.init(io);
    var store: PolicyStore = .init(testing.allocator, bus.eventBus());
    defer _ = store.deinit(io);
    var providers: Self = try .init(testing.allocator, configs.len);
    defer providers.deinit(testing.allocator);
    providers.start(testing.allocator, io, &store, &configs, .{ .bus = bus.eventBus() });
    try expectPolicy(&store, io, "initial");
    try providers.close();
    try server.waitFor(io, 2);
    try expectPolicy(&store, io, "final");
    try testing.expect(providers.slots[0].provider.?.http.poll_thread == null);
    const final_body = exchanges[1].request_body;
    var final_request = try policy.proto.policy.SyncRequest.jsonDecode(final_body, .{}, testing.allocator);
    defer final_request.deinit();
    try testing.expectEqualStrings("first", final_request.value.last_successful_hash);
    try testing.expectEqual(@as(usize, 1), final_request.value.policy_statuses.items.len);
    try testing.expectEqualStrings("initial", final_request.value.policy_statuses.items[0].id);
    try providers.close();
    try testing.expectEqual(@as(usize, 2), server.served.load(.acquire));
}

test "v2 providers HTTP initial failure stays usable and recovers on final sync" {
    const io = testing.io;
    var exchanges = [_]SyncServer.Exchange{
        .{ .status = .service_unavailable },
        .{ .response = "{\"policies\":[{\"id\":\"recovered\",\"name\":\"recovered\"}]}" },
    };
    var server: SyncServer = undefined;
    try server.init(testing.allocator, io, &exchanges);
    defer server.deinit(testing.allocator, io);
    var url_buffer: [128]u8 = undefined;
    const configs = [_]policy.ProviderConfig{
        .{ .id = "remote", .type = .http, .url = try server.url(&url_buffer), .poll_interval = 3600 },
    };
    var bus: policy.observability.NoopEventBus = undefined;
    bus.init(io);
    var store: PolicyStore = .init(testing.allocator, bus.eventBus());
    defer _ = store.deinit(io);
    var providers: Self = try .init(testing.allocator, configs.len);
    defer providers.deinit(testing.allocator);
    providers.start(testing.allocator, io, &store, &configs, .{ .bus = bus.eventBus() });
    try testing.expect(providers.slots[0].start_error == null);
    {
        var read = store.tryRead(io);
        try testing.expect(read == .ready);
        defer read.ready.deinit(io);
        try testing.expect(read.ready.snapshot() == null);
    }
    try providers.close();
    try expectPolicy(&store, io, "recovered");
    try server.waitFor(io, 2);
}

test "v2 providers close continues final syncs after one provider fails" {
    const io = testing.io;
    var exchanges = [_]SyncServer.Exchange{ .{}, .{}, .{ .status = .service_unavailable }, .{} };
    var server: SyncServer = undefined;
    try server.init(testing.allocator, io, &exchanges);
    defer server.deinit(testing.allocator, io);
    var url_buffer: [128]u8 = undefined;
    const url = try server.url(&url_buffer);
    const configs = [_]policy.ProviderConfig{
        .{ .id = "a", .type = .http, .url = url, .poll_interval = 3600 },
        .{ .id = "b", .type = .http, .url = url, .poll_interval = 3600 },
    };
    var bus: policy.observability.NoopEventBus = undefined;
    bus.init(io);
    var store: PolicyStore = .init(testing.allocator, bus.eventBus());
    defer _ = store.deinit(io);
    var providers: Self = try .init(testing.allocator, configs.len);
    defer providers.deinit(testing.allocator);
    providers.start(testing.allocator, io, &store, &configs, .{ .bus = bus.eventBus() });
    try testing.expectError(error.HttpRequestFailed, providers.close());
    try server.waitFor(io, 4);
    try testing.expectEqual(error.HttpRequestFailed, providers.slots[0].close_error.?);
    try testing.expect(providers.slots[1].close_error == null);
    for (providers.slots) |slot| try testing.expect(slot.provider.?.http.poll_thread == null);
    try providers.close();
    try testing.expectEqual(@as(usize, 4), server.served.load(.acquire));
}

test "v2 providers gate extension hooks and apply config before compiling policies" {
    const io = testing.io;
    var exchanges = [_]SyncServer.Exchange{
        .{ .response =
        \\{"policies":[{"id":"extended","name":"extended","enabled":true,
        \\ "log":{"match":[{"logField":1,"exists":true}],"keep":"all"},
        \\ "extensions":[{"type":"test/probe"}]}],
        \\ "extensionConfigs":[{"type":"test/probe"}],"hash":"first"}
        },
        .{ .response = "{\"hash\":\"first\"}" },
    };
    var server: SyncServer = undefined;
    try server.init(testing.allocator, io, &exchanges);
    defer server.deinit(testing.allocator, io);
    var url_buffer: [128]u8 = undefined;
    const configs = [_]policy.ProviderConfig{
        .{ .id = "remote", .type = .http, .url = try server.url(&url_buffer), .poll_interval = 3600 },
    };
    var bus: policy.observability.NoopEventBus = undefined;
    bus.init(io);
    var store: PolicyStore = .init(testing.allocator, bus.eventBus());
    defer _ = store.deinit(io);
    var probe: ExtensionProbe = .{ .store = &store };
    try store.setExtensionResolver(io, probe.resolver());
    var providers: Self = try .init(testing.allocator, configs.len);
    defer providers.deinit(testing.allocator);
    providers.start(testing.allocator, io, &store, &configs, .{
        .bus = bus.eventBus(),
        .extension_hooks = probe.hooks(),
    });
    try expectPolicy(&store, io, "extended");
    try providers.close();
    try server.waitFor(io, 2);
    try testing.expectEqual(@as(usize, 1), probe.configured);
    try testing.expectEqual(@as(usize, 1), probe.resolved);
    try testing.expectEqual(@as(usize, 2), probe.capability_calls);
    try testing.expect(!probe.gate_violation);
    try testing.expect(!probe.order_violation);
    for (exchanges) |exchange| {
        var request = try policy.proto.policy.SyncRequest.jsonDecode(exchange.request_body, .{}, testing.allocator);
        defer request.deinit();
        const capabilities = request.value.client_metadata.?.supported_extensions.items;
        try testing.expectEqual(@as(usize, 1), capabilities.len);
        try testing.expectEqualStrings("test/probe", capabilities[0].type);
    }
}
