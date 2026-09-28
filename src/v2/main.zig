//! Opt-in relay composition. Current production distributions retain their frontend.
const std = @import("std");
const Relay = @import("Relay.zig");
const Origin = @import("Origin.zig");
const Routes = @import("Routes.zig");
const zonfig = @import("../zonfig/root.zig");
const config_types = @import("../config/types.zig");
const extension_runtime = @import("../runtime/extensions.zig");
const policy = @import("policy_zig");
const PolicyStore = @import("PolicyStore.zig");
const ProviderSet = @import("ProviderSet.zig");

var stopped: std.atomic.Value(bool) = .init(false);

fn stop(_: std.posix.SIG) callconv(.c) void {
    stopped.store(true, .release);
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var config_path: ?[]const u8 = null;
    for (args, 0..) |arg, position| {
        if (std.mem.eql(u8, arg, "--config")) {
            if (position + 1 == args.len) return error.MissingArgument;
            config_path = args[position + 1];
        }
    }
    const loaded = try zonfig.load(config_types.ProxyConfig, init.gpa, init.io, .{
        .json_path = config_path,
        .env_prefix = "TERO",
        .environ = init.environ_map,
        .allow_env_only = config_path == null,
    });
    defer zonfig.deinit(config_types.ProxyConfig, init.gpa, loaded);
    var config: Relay.Config = .{
        .listen = try .parseLiteral("127.0.0.1:8080"),
        .upstream = try .parseLiteral("127.0.0.1:8081"),
        .authority = "127.0.0.1:8081",
        .default_origin = try .parse(loaded.upstream_url),
        .logs_upstream = if (loaded.logs_url) |url| try .parse(url) else null,
        .metrics_upstream = if (loaded.metrics_url) |url| try .parse(url) else null,
        .connections = loaded.max_connections,
        .workers = loaded.thread_pool_count orelse 4,
        .body_bytes = loaded.max_body_size,
        .budget_bytes = 512 * 1024 * 1024,
        .prometheus = .{
            .prometheus_max_input_bytes = loaded.prometheus.max_input_bytes_per_scrape,
            .prometheus_max_output_bytes = loaded.prometheus.max_output_bytes_per_scrape,
        },
    };
    var listen_text: [32]u8 = undefined;
    config.listen = try .parseLiteral(try std.fmt.bufPrint(&listen_text, "{d}.{d}.{d}.{d}:{d}", .{
        loaded.listen_address[0], loaded.listen_address[1], loaded.listen_address[2],
        loaded.listen_address[3], loaded.listen_port,
    }));
    config.requests = @max(config.workers, 16);
    if (loaded.max_decoded_bytes) |cap| config.processing.decoded_bytes = cap;
    var authority: ?[]const u8 = null;
    var ca_file: ?[]const u8 = null;
    var policy_file: ?[]const u8 = null;
    var index: usize = 1;
    while (index < args.len) : (index += 2) {
        if (std.mem.eql(u8, args[index], "--help")) {
            std.debug.print("edge-v2 --listen IP:PORT --upstream IP:PORT [--authority HOST] " ++
                "[--connections N] [--requests N] [--workers N] [--body-bytes N] " ++
                "[--response-bytes N] [--budget-bytes N] [--timeout-ms N] [--policy-file PATH]\n", .{});
            return;
        }
        if (index + 1 == args.len) return error.MissingArgument;
        const value = args[index + 1];
        if (std.mem.eql(u8, args[index], "--listen")) {
            config.listen = try .parseLiteral(value);
        } else if (std.mem.eql(u8, args[index], "--upstream")) {
            if (std.mem.indexOf(u8, value, "://") != null) {
                config.default_origin = try .parse(value);
            } else {
                config.upstream = try .parseLiteral(value);
                config.authority = value;
                config.default_origin = null;
            }
        } else if (std.mem.eql(u8, args[index], "--authority")) {
            authority = value;
        } else if (std.mem.eql(u8, args[index], "--connections")) {
            config.connections = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, args[index], "--requests")) {
            config.requests = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, args[index], "--workers")) {
            config.workers = try std.fmt.parseInt(u16, value, 10);
        } else if (std.mem.eql(u8, args[index], "--body-bytes")) {
            config.body_bytes = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, args[index], "--response-bytes")) {
            config.response_bytes = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, args[index], "--budget-bytes")) {
            config.budget_bytes = try std.fmt.parseInt(u64, value, 10);
        } else if (std.mem.eql(u8, args[index], "--timeout-ms")) {
            config.timeout_ms = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, args[index], "--policy-file")) {
            policy_file = value;
        } else if (std.mem.eql(u8, args[index], "--scratch-bytes")) {
            config.processing.scratch_bytes = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, args[index], "--output-bytes")) {
            config.processing.output_bytes = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, args[index], "--decoded-bytes")) {
            config.processing.decoded_bytes = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, args[index], "--distribution")) {
            config.distribution = std.meta.stringToEnum(Routes.Distribution, value) orelse
                return error.InvalidDistribution;
        } else if (std.mem.eql(u8, args[index], "--logs-upstream")) {
            config.logs_upstream = try .parse(value);
        } else if (std.mem.eql(u8, args[index], "--metrics-upstream")) {
            config.metrics_upstream = try .parse(value);
        } else if (std.mem.eql(u8, args[index], "--ca-file")) {
            ca_file = value;
        } else if (!std.mem.eql(u8, args[index], "--config")) return error.UnknownArgument;
    }
    if (authority) |value| {
        config.authority = value;
        if (config.default_origin) |*origin| origin.authority = value;
    }
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(init.gpa);
    var ca_lock: std.Io.RwLock = .init;
    const origins = [_]?Origin{ config.default_origin, config.logs_upstream, config.metrics_upstream };
    var tls_needed = false;
    for (origins) |maybe| if (maybe) |origin| {
        tls_needed = tls_needed or origin.secure;
    };
    if (tls_needed) {
        if (ca_file) |path| {
            try ca_bundle.addCertsFromFilePath(init.gpa, init.io, .now(init.io, .real), .cwd(), path);
        } else try ca_bundle.rescan(init.gpa, init.io, .now(init.io, .real));
        config.ca_bundle = &ca_bundle;
        config.ca_lock = &ca_lock;
        config.tls_allocator = init.gpa;
    }
    var extensions = extension_runtime.Extensions.init(init.gpa, .{ .log = extension_runtime.datadogLogEncode });
    defer extensions.deinit();
    if (loaded.s3_dump.enabled) {
        try extension_runtime.configure(&extensions, init.gpa, init.io, loaded.s3_dump, init.environ_map);
        config.extension_sink = extensions.sink();
    }
    var bus: policy.observability.NoopEventBus = undefined;
    bus.init(init.io);
    // The control-plane allocator remains valid through process exit if a failed
    // dependency publication quarantines the registry. Normal teardown frees it.
    var store: PolicyStore = .init(std.heap.page_allocator, bus.eventBus());
    defer if (store.deinit(init.io) == .quarantined) {
        std.log.err("policy registry quarantined; restart required; raw relay remains available", .{});
    };
    try store.setExtensionResolver(init.io, extensions.resolver());
    const provider_count = loaded.policy_providers.len + @as(usize, if (policy_file != null) 1 else 0);
    const configs = try init.arena.allocator().alloc(policy.ProviderConfig, provider_count);
    @memcpy(configs[0..loaded.policy_providers.len], loaded.policy_providers);
    if (policy_file) |path| configs[configs.len - 1] = .{ .id = "file", .type = .file, .path = path };
    var providers: ProviderSet = try .init(init.gpa, configs.len);
    defer providers.deinit(init.gpa);
    providers.start(init.gpa, init.io, &store, configs, .{
        .bus = bus.eventBus(),
        .service = loaded.service,
        .extension_hooks = extensions.syncHooks(),
    });
    var tap: @import("../pipeline/tap.zig").TapState = .{ .io = init.io };
    if (loaded.tap_enabled) {
        if (config.workers < 2 or config.requests < 2) return error.TapNeedsTwoWorkers;
        config.tap = &tap;
    }
    if (configs.len > 0 or loaded.tap_enabled) config.policy_store = &store;
    for (providers.slots) |slot| if (slot.start_error) |err| {
        std.log.err("policy provider unavailable: {t}", .{err});
    };
    const reserved = try Relay.requiredBytes(config);
    var relay: Relay = try .init(init.gpa, init.io, config);
    defer relay.deinit(init.gpa, init.io);
    const action: std.posix.Sigaction = .{
        .handler = .{ .handler = stop },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(.INT, &action, null);
    std.posix.sigaction(.TERM, &action, null);
    std.debug.print("edge-v2 listening on {f}; reserved_bytes={d}\n", .{
        relay.acceptor.server.socket.address, reserved,
    });
    var monitor_stop: std.atomic.Value(bool) = .init(false);
    const monitor = try std.Thread.spawn(
        .{ .stack_size = Relay.STACK_BYTES },
        monitorPolicies,
        .{ init.io, &store, &providers, &monitor_stop },
    );
    defer {
        monitor_stop.store(true, .release);
        monitor.join();
    }
    var flush: ?std.Io.Future(void) = if (loaded.s3_dump.enabled)
        try init.io.concurrent(
            extension_runtime.flushLoop,
            .{ &extensions, init.io, loaded.s3_dump.flush_interval_ms, null },
        )
    else
        null;
    defer if (flush) |*task| task.cancel(init.io);
    try relay.run(init.io, &stopped);
    const evaluated = relay.evaluated.load(.monotonic);
    const dropped = relay.policy_dropped.load(.monotonic);
    const bypassed = relay.processing_bypassed.load(.monotonic);
    std.debug.print("edge-v2 stopped: completed={d} failed={d} peak_requests={d} " ++
        "evaluated={d} policy_dropped={d} bypassed={d}\n", .{
        relay.completed, relay.failed, relay.peak_requests, evaluated, dropped, bypassed,
    });
}

fn monitorPolicies(io: std.Io, store: *PolicyStore, providers: *ProviderSet, done: *const std.atomic.Value(bool)) void {
    while (!done.load(.acquire)) {
        switch (store.tryRead(io)) {
            .ready => |value| {
                var guard = value;
                guard.deinit(io);
            },
            .busy => {},
            .unavailable => {
                std.log.err("policy registry quarantined; stopping publishers; raw forwarding continues", .{});
                providers.stopAll();
                return;
            },
        }
        io.sleep(.fromMilliseconds(50), .awake) catch return;
    }
}
