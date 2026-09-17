//! End-to-end chunked-request harness for the stdio frontend. Spawns the real
//! `edge` binary (built with -Dfrontend=stdio) against a mock upstream that
//! records what each connection received, then sends chunked
//! (Transfer-Encoding: chunked) POSTs through edge and asserts:
//!
//!   * a chunked passthrough (`forward_raw`) body reaches the upstream as
//!     chunked, decoded byte-exact, with no Content-Length — the regression
//!     fixed by restoring the streaming path (pre-fix the body was
//!     arena-buffered and forwarded as content-length)
//!   * a chunked body over `max_body_size` is rejected (not 200) — the cap
//!     c33e387 added is preserved (sent mid-stream, no up-front length check)
//!   * a chunked body on the replayable logs path (`pipe_stream`) and the
//!     buffered metrics path (`pipe_buffered`) round-trip with policies active
//!
//! Mirrors src/bench/upstream_pool_harness.zig's process model (bind mock,
//! spawn edge, poll /_health) but adds a recording mock and chunked sending.
const std = @import("std");

const edge_bin = "zig-out/bin/edge";
const config_path = "zig-out/chunked_harness.config.json";
const policies_path = "zig-out/chunked_harness.policies.json";

/// keep-all policies so the .log and .metric signals actually run the pipeline
/// (otherwise they short-circuit to forward_raw); identical to the pool harness.
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

/// One connection's recorded view: which framing the upstream saw, body bytes.
const Recorded = struct {
    saw_chunked_te: bool = false,
    saw_content_length: bool = false,
    body_len: usize = 0,
    clean: bool = false, // head + full body drained, "ok" responded
};

const Mock = struct {
    server: std.Io.net.Server,
    io: std.Io,
    lock: std.Io.Mutex = .init,
    last: Recorded = .{},
    accepted: std.atomic.Value(u32) = .init(0),
    body_store: []u8,

    fn serve(self: *Mock) void {
        const io = self.io;
        while (true) {
            var stream = self.server.accept(io) catch return; // error.Canceled on shutdown
            _ = self.accepted.fetchAdd(1, .monotonic);
            self.handleConn(stream);
            stream.close(io);
        }
    }

    fn handleConn(self: *Mock, stream: std.Io.net.Stream) void {
        const io = self.io;
        var recv: [16 * 1024]u8 = undefined;
        var send: [4 * 1024]u8 = undefined;
        var nr = std.Io.net.Stream.Reader.init(stream, io, &recv);
        var nw = std.Io.net.Stream.Writer.init(stream, io, &send);
        var server = std.http.Server.init(&nr.interface, &nw.interface);
        if (server.reader.state != .ready) return;
        var req = server.receiveHead() catch return;

        // Inspect framing from the raw head BEFORE the body reader invalidates
        // the head strings (readerExpectNone invalidates them).
        var saw_chunked_te = false;
        var saw_content_length = false;
        var it = req.iterateHeaders();
        while (it.next()) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, "transfer-encoding")) saw_chunked_te = true;
            if (std.ascii.eqlIgnoreCase(h.name, "content-length")) saw_content_length = true;
        }

        var body_buf: [64 * 1024]u8 = undefined;
        const body_reader = req.readerExpectContinue(&body_buf) catch return;
        var total: usize = 0;
        const cap = self.body_store.len;
        while (total < cap) {
            const n = body_reader.readSliceShort(self.body_store[total..]) catch break;
            if (n == 0) break;
            total += n;
        }
        // ziglint-ignore: Z026 (best-effort drain of a possibly-truncated body)
        _ = body_reader.discardRemaining() catch {};
        req.respond("ok", .{ .keep_alive = true }) catch return;

        self.lock.lockUncancelable(io);
        defer self.lock.unlock(io);
        self.last = .{
            .saw_chunked_te = saw_chunked_te,
            .saw_content_length = saw_content_length,
            .body_len = total,
            .clean = true,
        };
    }
};

/// Send a chunked POST; return the HTTP status edge returned (0 on transport
/// failure). `transfer_encoding = .chunked` makes std.http.Client frame `body`
/// into chunks; the pump flushes through the 16 KiB send buffer.
fn sendChunked(client: *std.http.Client, uri: std.Uri, content_type: []const u8, body: []const u8) u16 {
    var req = client.request(.POST, uri, .{
        .extra_headers = &.{.{ .name = "content-type", .value = content_type }},
    }) catch return 0;
    defer req.deinit();
    req.transfer_encoding = .chunked;
    var send_buf: [16 * 1024]u8 = undefined;
    var bw = req.sendBodyUnflushed(&send_buf) catch return 0;
    // Edge may close the connection while we are still streaming an over-cap
    // body (it answers 413 and closes); tolerate the resulting write failure.
    bw.writer.writeAll(body) catch {
        // The response may already be waiting in our socket; try to read it.
        return readStatus(&req);
    };
    bw.end() catch return readStatus(&req);
    (req.connection orelse return 0).flush() catch return readStatus(&req);
    return readStatus(&req);
}

fn readStatus(req: *std.http.Client.Request) u16 {
    var res = req.receiveHead(&.{}) catch return 0;
    var res_buf: [4096]u8 = undefined;
    // ziglint-ignore: Z026 (response body drain; status already captured)
    _ = res.reader(&res_buf).discardRemaining() catch {};
    return @intFromEnum(res.head.status);
}

/// Send a chunked POST, retrying once on transport failure/non-200. The mock
/// upstream closes after one response, so a stale pooled connection can fail
/// the first send; edge evicts it and the retry dials fresh (mirrors the pool
/// harness's sendWithRetry). Over-cap bodies use `sendChunked` directly.
fn sendChunkedRetry(client: *std.http.Client, uri: std.Uri, content_type: []const u8, body: []const u8) u16 {
    const s1 = sendChunked(client, uri, content_type, body);
    if (s1 == 200) return s1;
    return sendChunked(client, uri, content_type, body);
}

fn readFile(io: std.Io, gpa: std.mem.Allocator, path: []const u8) ![]u8 {
    const file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var fr = file.reader(io, &.{});
    return fr.interface.allocRemaining(gpa, .limited(8 * 1024 * 1024));
}

fn get(client: *std.http.Client, gpa: std.mem.Allocator, uri: std.Uri) ?[]u8 {
    var req = client.request(.GET, uri, .{}) catch return null;
    defer req.deinit();
    req.sendBodiless() catch return null;
    var res = req.receiveHead(&.{}) catch return null;
    if (res.head.status != .ok) return null;
    var buf: [1024]u8 = undefined;
    return res.reader(&buf).allocRemaining(gpa, .limited(64 * 1024)) catch null;
}

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
    return std.mem.indexOf(u8, body, "(log=1 metric=1") != null;
}

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

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;

    var mock_port: u16 = 15000;
    const server = while (mock_port < 15200) : (mock_port += 1) {
        const addr = std.Io.net.IpAddress.parse("127.0.0.1", mock_port) catch continue;
        break addr.listen(io, .{ .reuse_address = true }) catch continue;
    } else {
        std.debug.print("could not bind a loopback port for the mock upstream\n", .{});
        return error.NoFreePort;
    };

    var body_store: [4 * 1024 * 1024]u8 = undefined; // 4 MiB recording buffer
    var mock: Mock = .{ .server = server, .io = io, .body_store = &body_store };
    defer mock.server.deinit(io);

    var group: std.Io.Group = .init;
    defer group.cancel(io);
    try group.concurrent(io, Mock.serve, .{&mock});

    const edge_port = try freePort(io, 19080);
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
    defer child.kill(io);

    try waitFor(io, gpa, edge_port, "/_health", healthOk);
    waitFor(io, gpa, edge_port, "/_edge/policies", policiesActive) catch {
        std.debug.print("policies never became active — pipe paths would fall back to forward_raw\n", .{});
        return error.PoliciesNotLoaded;
    };

    var client: std.http.Client = .{ .allocator = gpa, .io = io };
    defer client.deinit();

    var passes: u32 = 0;
    var fails: u32 = 0;
    var checks: u32 = 0;

    // --- Scenario 1: chunked passthrough reaches upstream chunked, byte-exact ---
    {
        const body = "the quick brown fox jumps over the lazy dog";
        var uri_buf: [96]u8 = undefined;
        const uri = try std.Uri.parse(
            try std.fmt.bufPrint(&uri_buf, "http://127.0.0.1:{d}/forward", .{edge_port}),
        );
        const accepted_before = mock.accepted.load(.monotonic);
        const status = sendChunkedRetry(&client, uri, "text/plain", body);
        // ziglint-ignore: Z026 (best-effort pacing; a missed sleep is harmless)
        io.sleep(.fromNanoseconds(20 * std.time.ns_per_ms), .awake) catch {};
        const accepted_after = mock.accepted.load(.monotonic);

        checks += 4;
        const ok_status = status == 200;
        const ok_dialed = accepted_after >= accepted_before + 1;
        const rec = mock.last;
        const ok_chunked = rec.saw_chunked_te and !rec.saw_content_length and rec.clean;
        const ok_body = rec.body_len == body.len and std.mem.eql(u8, mock.body_store[0..rec.body_len], body);
        if (ok_status) passes += 1 else fails += 1;
        if (ok_dialed) passes += 1 else fails += 1;
        if (ok_chunked) passes += 1 else fails += 1;
        if (ok_body) passes += 1 else fails += 1;
        std.debug.print(
            "  chunked passthrough /forward: status={d} dialed={s} upstream_tE={s} upstream_CL={s} body={s}" ++
                " (sent {d}B, upstream got {d}B)\n",
            .{
                status,
                if (ok_dialed) "yes" else "NO",
                if (rec.saw_chunked_te) "chunked" else "(none)",
                if (rec.saw_content_length) "present" else "absent",
                if (ok_body) "byte-exact" else "MISMATCH",
                body.len,
                rec.body_len,
            },
        );
    }

    // --- Scenario 2: chunked over-cap is rejected (not 200) ---
    {
        // 2.1 MiB > 2 MiB max_body_size. Edge must reject (413) and not return 200.
        const big = try gpa.alloc(u8, 2 * 1024 * 1024 + 64);
        defer gpa.free(big);
        @memset(big, 'z');
        var uri_buf: [96]u8 = undefined;
        const uri = try std.Uri.parse(
            try std.fmt.bufPrint(&uri_buf, "http://127.0.0.1:{d}/forward", .{edge_port}),
        );
        const status = sendChunked(&client, uri, "text/plain", big);

        checks += 1;
        // Acceptance: edge must NOT return 200. Either 413 or a transport
        // failure (0) after edge tore the connection down mid-stream both count
        // as "rejected" — the cap fired. A 200 would be the regression.
        const ok = status != 200;
        if (ok) passes += 1 else fails += 1;
        std.debug.print(
            "  chunked over-cap /forward (2M+64B): status={d} ({s})\n",
            .{ status, if (ok) "rejected" else "ACCEPTED (REGRESSION)" },
        );
    }

    // --- Scenario 3: chunked pipe_stream (replayable logs) round-trips ---
    {
        const body = try readFile(io, gpa, "bench/perf/payloads/datadog-1mb.json");
        defer gpa.free(body);
        var uri_buf: [96]u8 = undefined;
        const uri = try std.Uri.parse(
            try std.fmt.bufPrint(&uri_buf, "http://127.0.0.1:{d}/api/v2/logs", .{edge_port}),
        );
        const accepted_before = mock.accepted.load(.monotonic);
        const status = sendChunkedRetry(&client, uri, "application/json", body);
        // ziglint-ignore: Z026
        io.sleep(.fromNanoseconds(20 * std.time.ns_per_ms), .awake) catch {};
        const accepted_after = mock.accepted.load(.monotonic);

        checks += 2;
        const ok_status = status == 200;
        const ok_dialed = accepted_after >= accepted_before + 1;
        if (ok_status) passes += 1 else fails += 1;
        if (ok_dialed) passes += 1 else fails += 1;
        std.debug.print(
            "  chunked pipe_stream /api/v2/logs: status={d} dialed={s} ({d}B -> upstream {d}B)\n",
            .{ status, if (ok_dialed) "yes" else "NO", body.len, mock.last.body_len },
        );
    }

    // --- Scenario 4: chunked pipe_buffered (metrics) round-trips ---
    {
        const body = try readFile(io, gpa, "bench/scaling/payloads/datadog-metrics.json");
        defer gpa.free(body);
        var uri_buf: [96]u8 = undefined;
        const uri = try std.Uri.parse(
            try std.fmt.bufPrint(&uri_buf, "http://127.0.0.1:{d}/api/v2/series", .{edge_port}),
        );
        const accepted_before = mock.accepted.load(.monotonic);
        const status = sendChunkedRetry(&client, uri, "application/json", body);
        // ziglint-ignore: Z026
        io.sleep(.fromNanoseconds(20 * std.time.ns_per_ms), .awake) catch {};
        const accepted_after = mock.accepted.load(.monotonic);

        checks += 2;
        const ok_status = status == 200;
        const ok_dialed = accepted_after >= accepted_before + 1;
        if (ok_status) passes += 1 else fails += 1;
        if (ok_dialed) passes += 1 else fails += 1;
        std.debug.print(
            "  chunked pipe_buffered /api/v2/series: status={d} dialed={s} ({d}B -> upstream {d}B)\n",
            .{ status, if (ok_dialed) "yes" else "NO", body.len, mock.last.body_len },
        );
    }

    std.debug.print("\n=== chunked stdio harness: {d}/{d} checks passed ===\n", .{ passes, checks });
    if (fails == 0) {
        std.debug.print(
            "PASS: chunked forward_raw streams upstream chunked (byte-exact), over-cap rejected," ++
                " pipe paths round-trip\n",
            .{},
        );
        return;
    }
    std.debug.print("FAIL: {d} check(s) failed\n", .{fails});
    return error.ChunkedHarnessFailed;
}
