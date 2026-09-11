//! Real-binary stale keep-alive regression. Log intake clients never retry:
//! Edge must replay their prepared payload once on a fresh connection. Generic
//! POST and metric intake retain single-attempt semantics; those scenarios
//! separately verify that eviction permits sender-side recovery.
const std = @import("std");

const requests = 10;
const edge_bin = "zig-out/bin/edge";
const config_path = "zig-out/upstream_pool_harness.config.json";
const policies_path = "zig-out/upstream_pool_harness.policies.json";

/// Large 'x' filler for the passthrough path. Sized well past any loopback
/// Synthetic filler body for the passthrough path (no payload file needed).
const filler_body_len = 1 << 20; // 1 MiB

/// One forward path to exercise. `body_file` null => synthetic filler.
const Scenario = struct {
    name: []const u8,
    path: []const u8,
    content_type: []const u8,
    body_file: ?[]const u8,
    replayable: bool = false,
};

const scenarios = [_]Scenario{
    .{
        .name = "forward_raw   (passthrough)",
        .path = "/forward",
        .content_type = "text/plain",
        .body_file = null,
    },
    .{
        .name = "pipe_stream   (dd logs)",
        .replayable = true,
        .path = "/api/v2/logs",
        .content_type = "application/json",
        .body_file = "bench/perf/payloads/datadog-1mb.json",
    },
    .{
        .name = "pipe_buffered (dd metrics)",
        .path = "/api/v2/series",
        .content_type = "application/json",
        .body_file = "bench/scaling/payloads/datadog-metrics.json",
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

const Outcome = enum { first_try, recovered, failed };

/// Models a real sender: if a request fails (edge returned 502 after evicting the
/// dead upstream conn), retry it once. Because edge evicted, the retry must dial a
/// fresh upstream and succeed — that's the property under test. `.failed` means
/// two in a row failed, i.e. eviction did NOT heal the pool (poisoned).
fn sendWithRetry(client: *std.http.Client, uri: std.Uri, content_type: []const u8, body: []const u8) Outcome {
    if (sendRequest(client, uri, content_type, body)) return .first_try;
    if (sendRequest(client, uri, content_type, body)) return .recovered;
    return .failed;
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
        // ziglint-ignore: Z026 (best-effort poll pacing; a missed sleep is harmless)
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

const Result = struct { sc: Scenario, first_try: u32, recovered: u32, failed: u32, dials: u32 };

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
        const uri = try std.Uri.parse(
            try std.fmt.bufPrint(&uri_buf, "http://127.0.0.1:{d}{s}", .{ edge_port, sc.path }),
        );

        const dials_before = mock.accepted.load(.monotonic);
        var first_try: u32 = 0;
        var recovered: u32 = 0;
        var failed: u32 = 0;
        for (0..requests) |_| {
            const outcome: Outcome = if (sc.replayable)
                (if (sendRequest(&client, uri, sc.content_type, body)) .first_try else .failed)
            else
                sendWithRetry(&client, uri, sc.content_type, body);
            switch (outcome) {
                .first_try => first_try += 1,
                .recovered => recovered += 1,
                .failed => failed += 1,
            }
            // Let the mock's FIN reach edge's pooled conn before the next reuse so
            // the failure is deterministic (loopback FIN is fast; this is insurance).
            // ziglint-ignore: Z026 (best-effort pacing; a missed sleep is harmless)
            io.sleep(.fromNanoseconds(5 * std.time.ns_per_ms), .awake) catch {};
        }
        results[i] = .{
            .sc = sc,
            .first_try = first_try,
            .recovered = recovered,
            .failed = failed,
            .dials = mock.accepted.load(.monotonic) - dials_before,
        };
    }

    std.debug.print(
        \\
        \\=== upstream connection-pool recovery harness (real edge) ===
        \\fake upstream: one response per connection, then close (idle-closing)
        \\{d} requests/path; log clients never retry; other paths verify sender recovery
        \\
        \\  path                          ok/N   1st  retry  fail  dials
        \\
    , .{requests});

    var all_ok = true;
    for (results) |r| {
        // The property under test: edge evicts the dead conn on failure, so a
        // sender's immediate retry always lands. So NO request may fail twice in a
        // row (failed == 0), and the retry path must actually have been exercised
        // (recovered >= 1) — otherwise we never tested the self-heal.
        const ok = r.failed == 0 and (if (r.sc.replayable) r.first_try == requests else r.recovered >= 1);
        if (!ok) all_ok = false;

        const succeeded = r.first_try + r.recovered;
        std.debug.print("  {s:<28}  {d:>2}/{d:<2}  {d:>3}  {d:>4}  {d:>4}  {d:>4}\n", .{
            r.sc.name, succeeded, requests, r.first_try, r.recovered, r.failed, r.dials,
        });
    }

    if (all_ok) {
        std.debug.print(
            "\nPASS: log delivery succeeds without sender retries; other paths recover after eviction\n",
            .{},
        );
        return;
    }
    std.debug.print("\nFAIL: log delivery failed or single-attempt pool recovery regressed\n", .{});
    return error.HarnessAssertionFailed;
}
