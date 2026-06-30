//! End-to-end upstream connection-pool recovery harness for the REAL edge
//! binary, exercising all three forward paths.
//!
//! Background: std.http.Client pools keep-alive connections but only evicts a
//! dead one on the *receive* side (receiveHead sets connection.closing). A
//! *send*-side failure — BrokenPipe/ConnectionReset writing to a keep-alive the
//! remote already closed — leaves the dead connection in the pool, so every
//! later request reuses it and fails too: a permanent loop (the still-unfixed
//! half of ziglang/zig#30165, and the Cloud Run symptom we saw). edge guards
//! every forward path with eviction (markUpstreamClosing on error) AND a single
//! in-request retry on a fresh connection, so each path fully heals.
//!
//! This harness spawns the real edge between an in-process client and an
//! in-process fake upstream that idle-closes keep-alives:
//!
//!   [fake upstream] <-- http -- [zig-out/bin/edge] <-- http -- [client]
//!
//! then drives each forward path and confirms it fully recovers:
//!
//!   forward_raw   (passthrough, /forward)      -> evict + retry -> 10/10 ok
//!   pipe_stream   (dd logs, /api/v2/logs)      -> evict + retry -> 10/10 ok
//!   pipe_buffered (dd metrics, /api/v2/series) -> evict + retry -> 10/10 ok
//!
//! The retry replays without extra memory: pipe_buffered re-sends the body
//! already held in the request arena, and pipe_stream re-reads the buffered
//! inbound body and re-runs the transform through reused thread-local buffers
//! (CPU cost, not memory).
//!
//! Run: zig build upstream-pool-harness  (builds edge, then runs this)
//! Exit 0 = every path recovers (and forward_raw fully heals). Nonzero = some
//! path poisoned (stuck reusing one dead conn) or the fix regressed.

const std = @import("std");

const requests = 10;
const edge_bin = "zig-out/bin/edge";
const config_path = "zig-out/upstream_pool_harness.config.json";
const policies_path = "zig-out/upstream_pool_harness.policies.json";

/// Large 'x' filler for the passthrough path: big enough that reusing a
/// peer-closed conn fails while edge is *writing* the body upstream (the send
/// side std doesn't auto-evict), not while reading the response head.
const filler_body_len = 1 << 20; // 1 MiB

/// One forward path to exercise. `body_file` null => synthetic 1 MiB filler.
const Scenario = struct {
    name: []const u8,
    path: []const u8,
    content_type: []const u8,
    body_file: ?[]const u8,
    /// forward_raw retries within the request, so it should fully heal. The
    /// pipe paths only self-heal across requests (evict, no retry).
    expect_full_recovery: bool,
};

const scenarios = [_]Scenario{
    .{
        .name = "forward_raw   (passthrough)",
        .path = "/forward",
        .content_type = "text/plain",
        .body_file = null,
        .expect_full_recovery = true,
    },
    .{
        .name = "pipe_stream   (dd logs)",
        .path = "/api/v2/logs",
        .content_type = "application/json",
        .body_file = "bench/perf/payloads/datadog-1mb.json",
        .expect_full_recovery = true,
    },
    .{
        .name = "pipe_buffered (dd metrics)",
        .path = "/api/v2/series",
        .content_type = "application/json",
        .body_file = "bench/scaling/payloads/datadog-metrics.json",
        .expect_full_recovery = true,
    },
};

/// policies.json that activates both .log and .metric signals (keep-all), so the
/// pipe paths actually run instead of falling back to forward_raw.
const policies_json =
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

const Mock = struct {
    server: std.Io.net.Server,
    io: std.Io,
    /// Fresh TCP connections edge dialed. The discriminator: a poisoned pool
    /// keeps reusing one dead conn (stuck at 1 dial).
    accepted: std.atomic.Value(u32) = .init(0),

    /// Accept loop, spawned concurrently. Each connection gets exactly one
    /// response, then the socket is closed — an upstream that idle-closes a
    /// keep-alive after serving. Returns when accept is canceled at shutdown.
    fn serve(self: *Mock) void {
        const io = self.io;
        while (true) {
            var stream = self.server.accept(io) catch return; // error.Canceled on shutdown
            _ = self.accepted.fetchAdd(1, .monotonic);
            handleConn(io, stream);
            stream.close(io);
        }
    }

    fn handleConn(io: std.Io, stream: std.Io.net.Stream) void {
        var recv: [16 * 1024]u8 = undefined;
        var send: [4 * 1024]u8 = undefined;
        var nr = std.Io.net.Stream.Reader.init(stream, io, &recv);
        var nw = std.Io.net.Stream.Writer.init(stream, io, &send);
        var server = std.http.Server.init(&nr.interface, &nw.interface);

        if (server.reader.state != .ready) return;
        var req = server.receiveHead() catch return;

        // Drain the request body so the read side is clean before responding.
        var body_buf: [64 * 1024]u8 = undefined;
        const body_reader = req.readerExpectContinue(&body_buf) catch return;
        _ = body_reader.discardRemaining() catch return;

        req.respond("ok", .{ .keep_alive = true }) catch return;
    }
};

/// One POST through edge. Success = edge relayed the upstream's 200.
fn sendRequest(client: *std.http.Client, uri: std.Uri, content_type: []const u8, body: []const u8) bool {
    var req = client.request(.POST, uri, .{
        .extra_headers = &.{.{ .name = "content-type", .value = content_type }},
    }) catch return false;
    defer req.deinit();

    req.transfer_encoding = .{ .content_length = body.len };
    var send_buf: [16 * 1024]u8 = undefined;
    var body_writer = req.sendBodyUnflushed(&send_buf) catch return false;
    body_writer.writer.writeAll(body) catch return false;
    body_writer.end() catch return false;
    (req.connection orelse return false).flush() catch return false;

    var res = req.receiveHead(&.{}) catch return false;
    var res_buf: [4096]u8 = undefined;
    _ = res.reader(&res_buf).discardRemaining() catch return false;
    return res.head.status == .ok;
}

fn readFile(io: std.Io, gpa: std.mem.Allocator, path: []const u8) ![]u8 {
    const file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var fr = file.reader(io, &.{});
    return fr.interface.allocRemaining(gpa, .limited(8 * 1024 * 1024));
}

fn loadBody(io: std.Io, gpa: std.mem.Allocator, sc: Scenario) ![]u8 {
    if (sc.body_file) |path| return readFile(io, gpa, path);
    const b = try gpa.alloc(u8, filler_body_len);
    @memset(b, 'x');
    return b;
}

/// GET `path`; return its body (caller frees) or null on any failure.
fn get(client: *std.http.Client, gpa: std.mem.Allocator, uri: std.Uri) ?[]u8 {
    var req = client.request(.GET, uri, .{}) catch return null;
    defer req.deinit();
    req.sendBodiless() catch return null;
    var res = req.receiveHead(&.{}) catch return null;
    if (res.head.status != .ok) return null;
    var buf: [1024]u8 = undefined;
    return res.reader(&buf).allocRemaining(gpa, .limited(64 * 1024)) catch null;
}

/// Poll `path` until `probe` accepts the body or the deadline passes.
fn waitFor(
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
        io.sleep(.fromNanoseconds(50 * std.time.ns_per_ms), .awake) catch {};
    }
    return error.NotReady;
}

fn healthOk(body: []const u8) bool {
    return std.mem.indexOf(u8, body, "ok") != null;
}

fn policiesActive(body: []const u8) bool {
    // Both signals must show a loaded target, else the pipe paths fall back to
    // forward_raw (see exec.policiesActiveFor).
    return std.mem.indexOf(u8, body, "(log=1 metric=1") != null;
}

/// Bind a free loopback port, then release it so edge can claim it. TOCTOU race
/// is acceptable for a local harness; reuse_address keeps the rebind quick.
fn freePort(io: std.Io, start: u16) !u16 {
    var port = start;
    while (port < start + 200) : (port += 1) {
        const addr = std.Io.net.IpAddress.parse("127.0.0.1", port) catch continue;
        var server = addr.listen(io, .{ .reuse_address = true }) catch continue;
        server.deinit(io);
        return port;
    }
    return error.NoFreePort;
}

fn writeFile(io: std.Io, path: []const u8, contents: []const u8) !void {
    var file = try std.Io.Dir.cwd().createFile(io, path, .{});
    defer file.close(io);
    var buf: [256]u8 = undefined;
    var fw = file.writer(io, &buf);
    try fw.interface.writeAll(contents);
    try fw.interface.flush();
}

fn writeConfig(io: std.Io, edge_port: u16, mock_port: u16) !void {
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

const Result = struct { sc: Scenario, successes: u32, dials: u32 };

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;

    // Fake upstream: bind a loopback port and keep it; this is edge's upstream.
    var mock_port: u16 = 14000;
    const server = while (mock_port < 14200) : (mock_port += 1) {
        const addr = std.Io.net.IpAddress.parse("127.0.0.1", mock_port) catch continue;
        break addr.listen(io, .{ .reuse_address = true }) catch continue;
    } else {
        std.debug.print("could not bind a loopback port for the mock upstream\n", .{});
        return error.NoFreePort;
    };

    var mock: Mock = .{ .server = server, .io = io };
    defer mock.server.deinit(io);

    var group: std.Io.Group = .init;
    defer group.cancel(io); // stop accept before mock.server.deinit (LIFO)
    try group.concurrent(io, Mock.serve, .{&mock});

    // Spawn the real edge binary pointed at the fake upstream, with policies that
    // activate the .log and .metric signals so the pipe paths actually run.
    const edge_port = try freePort(io, 18080);
    try writeFile(io, policies_path, policies_json);
    defer std.Io.Dir.cwd().deleteFile(io, policies_path) catch {};
    try writeConfig(io, edge_port, mock_port);
    defer std.Io.Dir.cwd().deleteFile(io, config_path) catch {};

    var child = try std.process.spawn(io, .{
        .argv = &.{ edge_bin, config_path },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    defer child.kill(io); // idempotent: forcibly terminates and reaps

    try waitFor(io, gpa, edge_port, "/_health", healthOk);
    waitFor(io, gpa, edge_port, "/_edge/policies", policiesActive) catch {
        std.debug.print("policies never became active — pipe paths would fall back to forward_raw\n", .{});
        return error.PoliciesNotLoaded;
    };

    var client: std.http.Client = .{ .allocator = gpa, .io = io };
    defer client.deinit();

    var results: [scenarios.len]Result = undefined;
    for (scenarios, 0..) |sc, i| {
        const body = try loadBody(io, gpa, sc);
        defer gpa.free(body);

        var uri_buf: [96]u8 = undefined;
        const uri = try std.Uri.parse(try std.fmt.bufPrint(&uri_buf, "http://127.0.0.1:{d}{s}", .{ edge_port, sc.path }));

        const dials_before = mock.accepted.load(.monotonic);
        var successes: u32 = 0;
        for (0..requests) |_| {
            if (sendRequest(&client, uri, sc.content_type, body)) successes += 1;
            // Let the mock's FIN reach edge's pooled conn before the next reuse so
            // the failure is deterministic (loopback FIN is fast; this is insurance).
            io.sleep(.fromNanoseconds(5 * std.time.ns_per_ms), .awake) catch {};
        }
        results[i] = .{ .sc = sc, .successes = successes, .dials = mock.accepted.load(.monotonic) - dials_before };
    }

    std.debug.print(
        \\
        \\=== upstream connection-pool recovery harness (real edge) ===
        \\fake upstream: one response per connection, then close (idle-closing)
        \\{d} requests/path
        \\
        \\  path                          ok      dials   behavior
        \\
    , .{requests});

    var all_ok = true;
    for (results) |r| {
        // Recovery: the pool churned (>=2 dials) and most requests still landed,
        // i.e. it did NOT poison (stuck at 1 success / 1 dial). forward_raw must
        // additionally fully heal thanks to its in-request retry.
        const recovered = r.dials >= 2 and r.successes >= 2;
        const strict_ok = !r.sc.expect_full_recovery or r.successes >= requests - 1;
        const ok = recovered and strict_ok;
        if (!ok) all_ok = false;

        const behavior = if (!recovered)
            "POISONED (stuck)"
        else if (r.sc.expect_full_recovery)
            "full heal (evict+retry)"
        else
            "self-heals (evict only)";
        std.debug.print("  {s:<28}  {d:>2}/{d:<2}  {d:>3}     {s}\n", .{
            r.sc.name, r.successes, requests, r.dials, behavior,
        });
    }

    if (all_ok) {
        std.debug.print("\nPASS: every path recovers; forward_raw fully heals\n", .{});
        return;
    }
    std.debug.print("\nFAIL: a path poisoned or forward_raw did not fully heal\n", .{});
    return error.HarnessAssertionFailed;
}
