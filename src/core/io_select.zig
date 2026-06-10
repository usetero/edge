//! Selects and owns the std.Io implementation for the process.
//!
//! This file is the ONLY place outside platform backends (src/tail) that may
//! name a concrete Io implementation or touch std.posix. Everything below the
//! composition root programs against the std.Io interface, so swapping the
//! backend here is invisible to the rest of the tree.
const std = @import("std");

const log = std.log.scoped(.io_select);

pub const IoBackend = enum {
    /// Default: the Io handed to juicy main (Io.Threaded on current targets).
    inherited,
    /// Io.Threaded pinned to single-threaded mode: concurrent() fails with
    /// error.ConcurrencyUnavailable, cancellation is a no-op. For tests,
    /// lambda, and tiny footprints.
    single_threaded,
    /// Reserved. std.Io.Evented does not implement networking in Zig 0.16.0
    /// (release notes: "work-in-progress, experimental").
    evented,
    /// Reserved. std's uring Io is a proof of concept in 0.16.0 (no
    /// networking); the tail ring scheduler may be promoted here later.
    uring,

    pub fn parse(name: []const u8) ?IoBackend {
        return std.meta.stringToEnum(IoBackend, name);
    }
};

pub const SelectError = error{IoBackendUnavailable};

/// Owns whatever concrete implementation backs the selected Io. The Io
/// interface vtable points into this struct, so it must be pinned: store it
/// in the application's stack frame and never copy or move it after `io()`
/// has been called.
pub const IoRuntime = struct {
    backend: IoBackend,
    inherited_io: std.Io,
    threaded: std.Io.Threaded,

    pub fn init(init_io: std.Io, backend: IoBackend) SelectError!IoRuntime {
        switch (backend) {
            .inherited => return .{
                .backend = backend,
                .inherited_io = init_io,
                .threaded = undefined,
            },
            .single_threaded => return .{
                .backend = backend,
                .inherited_io = init_io,
                .threaded = .init_single_threaded,
            },
            .evented, .uring => {
                // warn (not err): the returned error already fails startup
                // loudly; err-level here would also trip the test runner.
                log.warn(
                    "io backend '{s}' is not available: zig 0.16.0 ships it without networking support",
                    .{@tagName(backend)},
                );
                return error.IoBackendUnavailable;
            },
        }
    }

    pub fn deinit(self: *IoRuntime) void {
        switch (self.backend) {
            // init_single_threaded documents deinit as safe but unnecessary;
            // call it anyway so adding owned backends later can't leak.
            .single_threaded => self.threaded.deinit(),
            .inherited, .evented, .uring => {},
        }
        self.* = undefined;
    }

    pub fn io(self: *IoRuntime) std.Io {
        return switch (self.backend) {
            .inherited => self.inherited_io,
            .single_threaded => self.threaded.io(),
            .evented, .uring => unreachable, // init rejected these
        };
    }

    /// Resolve the backend from the TERO_IO_BACKEND environment variable.
    /// Env-only on purpose: ProxyConfig's shape is frozen, and the backend is
    /// a deployment concern, not an application config concern.
    pub fn fromEnv(
        init_io: std.Io,
        environ_map: *const std.process.Environ.Map,
    ) SelectError!IoRuntime {
        const raw = environ_map.get("TERO_IO_BACKEND") orelse
            return init(init_io, .inherited);
        const backend = IoBackend.parse(raw) orelse {
            log.warn("unknown TERO_IO_BACKEND '{s}', using inherited", .{raw});
            return init(init_io, .inherited);
        };
        return init(init_io, backend);
    }
};

test "inherited backend hands back the same io" {
    var runtime: IoRuntime = try .init(std.testing.io, .inherited);
    defer runtime.deinit();
    const got = runtime.io();
    try std.testing.expectEqual(std.testing.io.vtable, got.vtable);
}

test "single_threaded backend owns a Threaded instance" {
    var runtime: IoRuntime = try .init(std.testing.io, .single_threaded);
    defer runtime.deinit();
    // The returned Io must point at our pinned instance, not the inherited one.
    try std.testing.expect(runtime.io().userdata == @as(*anyopaque, @ptrCast(&runtime.threaded)));
}

test "reserved backends are rejected loudly" {
    try std.testing.expectError(error.IoBackendUnavailable, IoRuntime.init(std.testing.io, .evented));
    try std.testing.expectError(error.IoBackendUnavailable, IoRuntime.init(std.testing.io, .uring));
}

test "fromEnv parses and falls back" {
    var env_map = std.process.Environ.Map.init(std.testing.allocator);
    defer env_map.deinit();

    var inherited: IoRuntime = try .fromEnv(std.testing.io, &env_map);
    defer inherited.deinit();
    try std.testing.expectEqual(IoBackend.inherited, inherited.backend);

    try env_map.put("TERO_IO_BACKEND", "single_threaded");
    var single: IoRuntime = try .fromEnv(std.testing.io, &env_map);
    defer single.deinit();
    try std.testing.expectEqual(IoBackend.single_threaded, single.backend);

    try env_map.put("TERO_IO_BACKEND", "bogus");
    var fallback: IoRuntime = try .fromEnv(std.testing.io, &env_map);
    defer fallback.deinit();
    try std.testing.expectEqual(IoBackend.inherited, fallback.backend);

    try env_map.put("TERO_IO_BACKEND", "uring");
    try std.testing.expectError(error.IoBackendUnavailable, IoRuntime.fromEnv(std.testing.io, &env_map));
}
