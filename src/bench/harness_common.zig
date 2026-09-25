//! Shared parts of the real-binary harnesses: config files, the mock bind, and the edge spawn.
const std = @import("std");

pub const edge_bin = "zig-out/bin/edge";

/// Keep-all policies for the .log and .metric signals, so the pipe paths run
/// the pipeline and do not fall back to forward_raw.
pub const policies_json =
    \\{
    \\  "policies": [
    \\    { "id": "keep-logs", "name": "keep-logs",
    \\      "log": { "match": [{ "log_field": "body", "regex": ".*" }], "keep": "all" } },
    \\    { "id": "keep-metrics", "name": "keep-metrics",
    \\      "metric": { "match": [{ "metric_field": "name", "regex": ".*" }], "keep": true } }
    \\  ]
    \\}
    \\
;

pub fn readFile(io: std.Io, gpa: std.mem.Allocator, path: []const u8) ![]u8 {
    const file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var fr = file.reader(io, &.{});
    return fr.interface.allocRemaining(gpa, .limited(8 * 1024 * 1024));
}

/// GET `uri`. Returns the body (the caller frees it), or null on a failure.
pub fn get(client: *std.http.Client, gpa: std.mem.Allocator, uri: std.Uri) ?[]u8 {
    var req = client.request(.GET, uri, .{}) catch return null;
    defer req.deinit();
    req.sendBodiless() catch return null;
    var res = req.receiveHead(&.{}) catch return null;
    if (res.head.status != .ok) return null;
    var buf: [1024]u8 = undefined;
    return res.reader(&buf).allocRemaining(gpa, .limited(64 * 1024)) catch null;
}

/// Polls `path` until `probe` accepts the body or the deadline passes.
pub fn waitFor(
    io: std.Io,
    gpa: std.mem.Allocator,
    port: u16,
    path: []const u8,
    probe: *const fn ([]const u8) bool,
) !void {
    var client: std.http.Client = .{ .allocator = gpa, .io = io };
    defer client.deinit();
    var buf: [96]u8 = undefined;
    const uri = try std.Uri.parse(try std.fmt.bufPrint(&buf, "http://127.0.0.1:{d}{s}", .{ port, path }));

    var waited_ms: u32 = 0;
    while (waited_ms < 8000) : (waited_ms += 50) {
        if (get(&client, gpa, uri)) |body| {
            defer gpa.free(body);
            if (probe(body)) return;
        }
        // ziglint-ignore: Z026 (best-effort poll pacing; a missed sleep is harmless)
        io.sleep(.fromNanoseconds(50 * std.time.ns_per_ms), .awake) catch {};
    }
    return error.NotReady;
}

pub fn healthOk(body: []const u8) bool {
    return std.mem.indexOf(u8, body, "ok") != null;
}

/// Both signals must show a loaded target. Else the pipe paths fall back to
/// forward_raw (see exec.policiesActiveFor).
pub fn policiesActive(body: []const u8) bool {
    return std.mem.indexOf(u8, body, "(log=1 metric=1") != null;
}

/// Finds a free loopback port and releases it for edge. Another process can
/// take the port first. That risk is acceptable for a local harness.
pub fn freePort(io: std.Io, start: u16) !u16 {
    var port = start;
    while (port < start + 200) : (port += 1) {
        const addr = std.Io.net.IpAddress.parse("127.0.0.1", port) catch continue;
        var server = addr.listen(io, .{ .reuse_address = true }) catch continue;
        server.deinit(io);
        return port;
    }
    return error.NoFreePort;
}

/// Binds the first free loopback port in [start, start + 200) and keeps it
/// for the mock upstream.
pub fn bindLoopback(io: std.Io, start: u16) !std.Io.net.Server {
    var port = start;
    while (port < start + 200) : (port += 1) {
        const addr = std.Io.net.IpAddress.parse("127.0.0.1", port) catch continue;
        return addr.listen(io, .{ .reuse_address = true }) catch continue;
    }
    std.debug.print("could not bind a loopback port for the mock upstream\n", .{});
    return error.NoFreePort;
}

pub fn writeFile(io: std.Io, path: []const u8, contents: []const u8) !void {
    var file = try std.Io.Dir.cwd().createFile(io, path, .{});
    defer file.close(io);
    var buf: [256]u8 = undefined;
    var fw = file.writer(io, &buf);
    try fw.interface.writeAll(contents);
    try fw.interface.flush();
}

pub fn writeConfig(
    io: std.Io,
    config_path: []const u8,
    policies_path: []const u8,
    edge_port: u16,
    mock_port: u16,
) !void {
    var buf: [640]u8 = undefined;
    const contents = try std.fmt.bufPrint(&buf,
        \\{{
        \\  "listen_address": "127.0.0.1",
        \\  "listen_port": {d},
        \\  "upstream_url": "http://127.0.0.1:{d}",
        \\  "log_level": "err",
        \\  "max_body_size": 2097152,
        \\  "policy_providers": [{{ "id": "file", "type": "file", "path": "{s}" }}]
        \\}}
        \\
    , .{ edge_port, mock_port, policies_path });
    try writeFile(io, config_path, contents);
}

/// Spawns the edge binary with `config_path`, then waits for /_health and for
/// active policies. The caller kills the child.
pub fn startEdge(io: std.Io, gpa: std.mem.Allocator, config_path: []const u8, edge_port: u16) !std.process.Child {
    var child = try std.process.spawn(io, .{
        .argv = &.{ edge_bin, config_path },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    errdefer child.kill(io);

    try waitFor(io, gpa, edge_port, "/_health", healthOk);
    waitFor(io, gpa, edge_port, "/_edge/policies", policiesActive) catch {
        std.debug.print("policies never became active — pipe paths would fall back to forward_raw\n", .{});
        return error.PoliciesNotLoaded;
    };
    return child;
}
