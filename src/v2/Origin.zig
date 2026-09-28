//! Validated origin identity and cancellable DNS; no per-request URL allocation.
const Self = @This();
const std = @import("std");
const RequestHead = @import("RequestHead.zig");
const native_connect = @import("os/connect.zig");

address: ?std.Io.net.IpAddress = null,
host: []const u8 = "",
port: u16 = 80,
authority: []const u8,
secure: bool = false,

/// Borrow URL bytes for the runtime lifetime. Origins are authorities: request
/// paths and queries remain owned by the incoming request, as in the old relay.
pub fn parse(url: []const u8) !Self {
    const uri = try std.Uri.parse(url);
    const secure = std.ascii.eqlIgnoreCase(uri.scheme, "https");
    if (!secure and !std.ascii.eqlIgnoreCase(uri.scheme, "http")) return error.UnsupportedScheme;
    if (uri.user != null or uri.password != null or uri.fragment != null) return error.InvalidOrigin;
    const host = switch (uri.host orelse return error.InvalidOrigin) {
        .raw, .percent_encoded => |value| value,
    };
    if (std.mem.indexOfScalar(u8, host, '%') != null) return error.InvalidOrigin;
    const begin = (std.mem.indexOf(u8, url, "://") orelse return error.InvalidOrigin) + 3;
    const end = std.mem.indexOfAnyPos(u8, url, begin, "/?#") orelse url.len;
    const authority = url[begin..end];
    try RequestHead.validateAuthority(authority, false);
    const port = uri.port orelse @as(u16, if (secure) 443 else 80);
    if (port == 0) return error.InvalidOrigin;
    const address = std.Io.net.IpAddress.parse(host, port) catch null;
    if (address == null) _ = try std.Io.net.HostName.init(host);
    return .{ .address = address, .host = host, .port = port, .authority = authority, .secure = secure };
}

/// The lookup owns no borrowed data after cancellation returns. Polling has a
/// finite turn so resolver-file reads and DNS waits share the exchange deadline.
pub fn resolve(
    self: Self,
    io: std.Io,
    deadline: std.Io.Timestamp,
    stopped: *const std.atomic.Value(bool),
) !std.Io.net.IpAddress {
    var addresses: [16]std.Io.net.IpAddress = undefined;
    const count = try self.resolveAll(io, deadline, stopped, &addresses);
    if (count == 0) return error.DnsFailed;
    return addresses[0];
}

/// Try resolved addresses only before any HTTP bytes have been sent. A failed
/// connection attempt is not a request retry and cannot duplicate ingestion.
pub fn connect(
    self: Self,
    io: std.Io,
    deadline: std.Io.Timestamp,
    stopped: *const std.atomic.Value(bool),
) !std.Io.net.Stream {
    var addresses: [16]std.Io.net.IpAddress = undefined;
    const count = try self.resolveAll(io, deadline, stopped, &addresses);
    var last_error: anyerror = error.DnsFailed;
    for (addresses[0..count]) |address| {
        // Reserve opportunities for alternative families without extending the
        // absolute request deadline. This is serial fallback, not Happy Eyeballs.
        const now: std.Io.Timestamp = .now(io, .awake);
        const attempt: std.Io.Timestamp = .{ .nanoseconds = @min(deadline.nanoseconds, now.nanoseconds + 500_000_000) };
        return native_connect.connect(io, address, attempt, stopped) catch |err| {
            last_error = err;
            continue;
        };
    }
    return last_error;
}

fn resolveAll(
    self: Self,
    io: std.Io,
    deadline: std.Io.Timestamp,
    stopped: *const std.atomic.Value(bool),
    addresses: *[16]std.Io.net.IpAddress,
) !usize {
    if (stopped.load(.acquire) or std.Io.Timestamp.now(io, .awake).nanoseconds >= deadline.nanoseconds)
        return error.Timeout;
    if (self.address) |address| {
        addresses[0] = address;
        return 1;
    }
    const hostname = try std.Io.net.HostName.init(self.host);
    var results: [16]std.Io.net.HostName.LookupResult = undefined;
    var queue: std.Io.Queue(std.Io.net.HostName.LookupResult) = .init(&results);
    const options: std.Io.net.HostName.LookupOptions = .{ .port = self.port };
    var lookup = try io.concurrent(std.Io.net.HostName.lookup, .{ hostname, io, &queue, options });
    defer lookup.cancel(io) catch {};
    var found: usize = 0;
    while (!stopped.load(.acquire) and std.Io.Timestamp.now(io, .awake).nanoseconds < deadline.nanoseconds) {
        var batch: [16]std.Io.net.HostName.LookupResult = undefined;
        const count = queue.get(io, &batch, 0) catch |err| return switch (err) {
            error.Closed => if (found > 0) found else error.DnsFailed,
            else => err,
        };
        for (batch[0..count]) |result| if (result == .address and found < addresses.len) {
            addresses[found] = result.address;
            found += 1;
        };
        try io.sleep(.fromMilliseconds(1), .awake);
    }
    return error.Timeout;
}

test "v2 origin rejects ambiguous schemes and preserves verified identity" {
    const testing = std.testing;
    const https = try parse("https://localhost:8443/path?ignored");
    try testing.expect(https.secure);
    try testing.expectEqualStrings("localhost", https.host);
    try testing.expectEqualStrings("localhost:8443", https.authority);
    try testing.expectEqual(8443, https.port);
    try testing.expectEqual(80, (try parse("http://127.0.0.1")).address.?.getPort());
    try testing.expectError(error.UnsupportedScheme, parse("ftp://example.com"));
    try testing.expectError(error.InvalidOrigin, parse("https://user:secret@example.com"));
}

test "v2 origin resolves localhost and expired DNS skips lookup" {
    var stopped: std.atomic.Value(bool) = .init(false);
    const origin = try parse("http://localhost:8081");
    try std.testing.expectError(error.Timeout, origin.resolve(std.testing.io, .{ .nanoseconds = 0 }, &stopped));
    const now: std.Io.Timestamp = .now(std.testing.io, .awake);
    const address = try origin.resolve(std.testing.io, .{ .nanoseconds = now.nanoseconds + 2_000_000_000 }, &stopped);
    try std.testing.expectEqual(8081, address.getPort());
}
