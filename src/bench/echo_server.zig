const std = @import("std");

const EndpointStats = struct {
    requests: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
};

const CapturedPayload = struct {
    path: []const u8,
    content_type: []const u8,
    data: []const u8,
};

/// Upstream faults the echo server can inject, so the matrix suite can drive
/// the edge's upstream leg through every failure it must survive. Armed over
/// HTTP (`POST /fault?mode=...`), applied to the echo path only, so /stats and
/// /fault stay reachable while a fault is armed.
pub const Fault = enum {
    /// Answer 202 as usual.
    none,
    /// Answer with `arg` as the status code.
    status,
    /// Read the body, then never answer. The client's watchdog must cut it.
    hang,
    /// Read part of the body, then close with no answer.
    close_early,
    /// Answer before reading the body, as a real intake does when it rejects
    /// a batch on its headers.
    reject_early,
    /// Close with RST and no answer.
    reset,
    /// Write bytes that are not HTTP.
    garbage,
    /// Declare a content-length larger than the body written, then close.
    truncate,
    /// Answer after `arg` milliseconds.
    slow,
    /// Answer with a body of `arg` bytes.
    oversize,
    /// Answer 202, then close at once, so the next pooled request finds a
    /// dead keep-alive connection.
    stale_keepalive,
};

pub const ServerContext = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    endpoint_stats: std.StringHashMap(EndpointStats),
    total_requests: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    total_bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    // Fault injection state
    fault_mutex: std.Io.Mutex = .init,
    fault: Fault = .none,
    /// Status code, milliseconds or byte count, by fault.
    fault_arg: u32 = 0,
    /// Requests left to fault. `null` means every request until it is cleared.
    fault_remaining: ?u32 = null,
    /// Faults applied since the last arm, so a test can assert it fired.
    fault_applied: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    // Capture mode state
    capture_mutex: std.Io.Mutex = .init,
    capture_enabled: bool = false,
    capture_name: ?[]const u8 = null,
    captured_payloads: std.ArrayListUnmanaged(CapturedPayload) = .empty,
    output_dir: []const u8 = ".",

    pub fn init(allocator: std.mem.Allocator, io: std.Io, output_dir: []const u8) ServerContext {
        return .{
            .allocator = allocator,
            .io = io,
            .endpoint_stats = std.StringHashMap(EndpointStats).init(allocator),
            .output_dir = output_dir,
        };
    }

    pub fn deinit(self: *ServerContext) void {
        var it = self.endpoint_stats.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.endpoint_stats.deinit();
        self.clearCaptures();
        if (self.capture_name) |name| {
            self.allocator.free(name);
        }
        self.* = undefined;
    }

    fn clearCaptures(self: *ServerContext) void {
        for (self.captured_payloads.items) |payload| {
            self.allocator.free(payload.path);
            self.allocator.free(payload.content_type);
            self.allocator.free(payload.data);
        }
        self.captured_payloads.clearRetainingCapacity();
    }

    pub fn startCapture(self: *ServerContext, name: []const u8) !void {
        self.capture_mutex.lockUncancelable(self.io);
        defer self.capture_mutex.unlock(self.io);

        self.clearCaptures();
        if (self.capture_name) |old_name| {
            self.allocator.free(old_name);
        }
        self.capture_name = try self.allocator.dupe(u8, name);
        self.capture_enabled = true;
    }

    pub fn stopCapture(self: *ServerContext) !usize {
        self.capture_mutex.lockUncancelable(self.io);
        defer self.capture_mutex.unlock(self.io);

        self.capture_enabled = false;
        const count = self.captured_payloads.items.len;

        // Save captures to file if we have a name
        if (self.capture_name) |name| {
            try self.saveCaptures(name);
        }

        return count;
    }

    fn saveCaptures(self: *ServerContext, name: []const u8) !void {
        // Create output file path
        var path_buf: [512]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buf, "{s}/{s}.jsonl", .{ self.output_dir, name });

        const file = try std.Io.Dir.cwd().createFile(self.io, path, .{});
        defer file.close(self.io);

        var buf: [4096]u8 = undefined;
        var file_writer = file.writer(self.io, &buf);
        const writer = &file_writer.interface;

        for (self.captured_payloads.items) |payload| {
            // Write as JSON lines: {"path": "...", "content_type": "...", "data_base64": "..."}
            try writer.writeAll("{\"path\":\"");
            try writer.writeAll(payload.path);
            try writer.writeAll("\",\"content_type\":\"");
            try writer.writeAll(payload.content_type);
            try writer.writeAll("\",\"data_base64\":\"");

            // Base64 encode the data
            const encoder = std.base64.standard.Encoder;
            const encoded_len = encoder.calcSize(payload.data.len);
            const encoded = try self.allocator.alloc(u8, encoded_len);
            defer self.allocator.free(encoded);
            _ = encoder.encode(encoded, payload.data);
            try writer.writeAll(encoded);

            try writer.writeAll("\"}\n");
        }

        try writer.flush();
    }

    pub fn capturePayload(self: *ServerContext, path: []const u8, content_type: []const u8, data: []const u8) void {
        self.capture_mutex.lockUncancelable(self.io);
        defer self.capture_mutex.unlock(self.io);

        if (!self.capture_enabled) return;

        const payload: CapturedPayload = .{
            .path = self.allocator.dupe(u8, path) catch return,
            .content_type = self.allocator.dupe(u8, content_type) catch return,
            .data = self.allocator.dupe(u8, data) catch return,
        };
        self.captured_payloads.append(self.allocator, payload) catch return;
    }

    pub fn recordRequest(self: *ServerContext, path: []const u8, body_len: usize) void {
        _ = self.total_requests.fetchAdd(1, .monotonic);
        _ = self.total_bytes.fetchAdd(body_len, .monotonic);

        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        if (self.endpoint_stats.getPtr(path)) |stats| {
            _ = stats.requests.fetchAdd(1, .monotonic);
            _ = stats.bytes.fetchAdd(body_len, .monotonic);
        } else {
            // New endpoint - need to allocate key
            const key = self.allocator.dupe(u8, path) catch return;
            self.endpoint_stats.put(key, .{}) catch {
                self.allocator.free(key);
                return;
            };
            if (self.endpoint_stats.getPtr(key)) |stats| {
                _ = stats.requests.fetchAdd(1, .monotonic);
                _ = stats.bytes.fetchAdd(body_len, .monotonic);
            }
        }
    }

    pub fn armFault(self: *ServerContext, fault: Fault, arg: u32, count: ?u32) void {
        self.fault_mutex.lockUncancelable(self.io);
        defer self.fault_mutex.unlock(self.io);
        self.fault = fault;
        self.fault_arg = arg;
        self.fault_remaining = count;
        self.fault_applied.store(0, .monotonic);
    }

    /// The fault for this request, with the counter spent.
    pub fn takeFault(self: *ServerContext) struct { Fault, u32 } {
        self.fault_mutex.lockUncancelable(self.io);
        defer self.fault_mutex.unlock(self.io);
        if (self.fault == .none) return .{ .none, 0 };
        if (self.fault_remaining) |left| {
            if (left == 0) return .{ .none, 0 };
            self.fault_remaining = left - 1;
        }
        _ = self.fault_applied.fetchAdd(1, .monotonic);
        return .{ self.fault, self.fault_arg };
    }

    pub fn clearFault(self: *ServerContext) void {
        self.armFault(.none, 0, null);
    }

    pub fn reset(self: *ServerContext) void {
        self.total_requests.store(0, .monotonic);
        self.total_bytes.store(0, .monotonic);

        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        var it = self.endpoint_stats.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.requests.store(0, .monotonic);
            entry.value_ptr.bytes.store(0, .monotonic);
        }

        self.clearFault();

        // Also clear captures
        self.capture_mutex.lockUncancelable(self.io);
        defer self.capture_mutex.unlock(self.io);
        self.clearCaptures();
        self.capture_enabled = false;
    }

    pub fn writeStats(self: *ServerContext, writer: anytype) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        try writer.writeAll("{\"endpoints\":{");

        var first = true;
        var it = self.endpoint_stats.iterator();
        while (it.next()) |entry| {
            if (!first) try writer.writeAll(",");
            first = false;

            try writer.print("\"{s}\":{{\"requests\":{d},\"bytes\":{d}}}", .{
                entry.key_ptr.*,
                entry.value_ptr.requests.load(.monotonic),
                entry.value_ptr.bytes.load(.monotonic),
            });
        }

        self.capture_mutex.lockUncancelable(self.io);
        defer self.capture_mutex.unlock(self.io);

        self.fault_mutex.lockUncancelable(self.io);
        defer self.fault_mutex.unlock(self.io);

        try writer.print("}},\"total_requests\":{d},\"total_bytes\":{d}," ++
            "\"capture_enabled\":{},\"captured_count\":{d}," ++
            "\"fault\":\"{s}\",\"fault_arg\":{d},\"fault_applied\":{d}}}", .{
            self.total_requests.load(.monotonic),
            self.total_bytes.load(.monotonic),
            self.capture_enabled,
            self.captured_payloads.items.len,
            @tagName(self.fault),
            self.fault_arg,
            self.fault_applied.load(.monotonic),
        });
    }
};

var server_context: ?*ServerContext = null;

fn shutdown(_: std.posix.SIG) callconv(.c) void {
    if (server_context) |ctx| {
        std.debug.print("\nReceived {d} requests, {d} bytes.\n", .{
            ctx.total_requests.load(.monotonic),
            ctx.total_bytes.load(.monotonic),
        });
    }
    std.process.exit(0);
}

/// `key=value` from a raw query string, or null.
fn queryValue(query: []const u8, key: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.findScalar(u8, pair, '=') orelse continue;
        if (std.mem.eql(u8, pair[0..eq], key)) return pair[eq + 1 ..];
    }
    return null;
}

/// Closes with RST rather than FIN, which is what a peer that crashed looks
/// like. Bench-only code, so std.posix here is fine.
fn resetConnection(stream: std.Io.net.Stream) void {
    const linger: std.posix.linger = .{ .onoff = 1, .linger = 0 };
    std.posix.setsockopt(
        stream.socket.handle,
        std.posix.SOL.SOCKET,
        std.posix.SO.LINGER,
        std.mem.asBytes(&linger),
    ) catch |err| {
        // The test that armed this fault expects an RST, so say when it
        // degrades to a normal close.
        std.debug.print("reset fault: SO_LINGER failed: {s}\n", .{@errorName(err)});
    };
}

/// Writes straight to the socket, past the HTTP state machine.
fn writeRaw(ctx: *ServerContext, stream: std.Io.net.Stream, bytes: []const u8) void {
    var buf: [512]u8 = undefined;
    var writer = std.Io.net.Stream.Writer.init(stream, ctx.io, &buf);
    writer.interface.writeAll(bytes) catch return;
    writer.interface.flush() catch return;
}

fn handleRequest(
    ctx: *ServerContext,
    request: *std.http.Server.Request,
    gpa: std.mem.Allocator,
    stream: std.Io.net.Stream,
) !void {
    const target = request.head.target;
    const query_start = std.mem.findScalar(u8, target, '?');
    const path = if (query_start) |i| target[0..i] else target;
    const query = if (query_start) |i| target[i + 1 ..] else "";

    const json_headers = [_]std.http.Header{
        .{ .name = "content-type", .value = "application/json" },
    };

    // A request with neither Content-Length nor Transfer-Encoding has an
    // empty body (RFC 9112 §6.3), but std.http frames it as read-until-close
    // for body-bearing methods, so any body read — including respond()'s
    // internal discard — blocks until the client hangs up. Skip body reads
    // and disable keep-alive so respond() never drains the socket.
    const unframed_body = request.head.method.requestHasBody() and
        request.head.transfer_encoding == .none and
        request.head.content_length == null;
    const keep_alive = !unframed_body;

    if (std.mem.eql(u8, path, "/stats")) {
        var buf: std.Io.Writer.Allocating = .init(gpa);
        defer buf.deinit();
        try ctx.writeStats(&buf.writer);
        try request.respond(buf.written(), .{ .keep_alive = keep_alive, .extra_headers = &json_headers });
        return;
    }

    if (std.mem.eql(u8, path, "/fault")) {
        const mode = queryValue(query, "mode") orelse "none";
        const fault = std.meta.stringToEnum(Fault, mode) orelse {
            try request.respond("{\"error\":\"unknown mode\"}", .{
                .keep_alive = keep_alive,
                .status = .bad_request,
                .extra_headers = &json_headers,
            });
            return;
        };
        const arg = if (queryValue(query, "arg")) |raw| std.fmt.parseInt(u32, raw, 10) catch 0 else 0;
        const count: ?u32 = if (queryValue(query, "count")) |raw|
            std.fmt.parseInt(u32, raw, 10) catch null
        else
            null;
        ctx.armFault(fault, arg, count);
        try request.respond("{\"status\":\"fault_armed\"}", .{
            .keep_alive = keep_alive,
            .extra_headers = &json_headers,
        });
        return;
    }

    if (std.mem.eql(u8, path, "/reset")) {
        ctx.reset();
        try request.respond("{\"status\":\"reset\"}", .{ .keep_alive = keep_alive, .extra_headers = &json_headers });
        return;
    }

    if (std.mem.eql(u8, path, "/capture/start")) {
        const capture_name = if (query.len == 0)
            "capture"
        else if (std.mem.find(u8, query, "name=")) |idx|
            query[idx + 5 ..]
        else
            query;
        ctx.startCapture(capture_name) catch |err| {
            try request.respond(@errorName(err), .{ .keep_alive = keep_alive, .status = .internal_server_error });
            return;
        };
        try request.respond("{\"status\":\"capture_started\"}", .{
            .keep_alive = keep_alive,
            .extra_headers = &json_headers,
        });
        return;
    }

    if (std.mem.eql(u8, path, "/capture/stop")) {
        const count = ctx.stopCapture() catch |err| {
            try request.respond(@errorName(err), .{ .keep_alive = keep_alive, .status = .internal_server_error });
            return;
        };
        var buf: [128]u8 = undefined;
        const json = std.fmt.bufPrint(&buf, "{{\"status\":\"capture_stopped\",\"count\":{d}}}", .{count}) catch
            "{\"status\":\"capture_stopped\"}";
        try request.respond(json, .{ .keep_alive = keep_alive, .extra_headers = &json_headers });
        return;
    }

    // All other requests: read body (5 MiB cap, matching the old config),
    // record stats, optionally capture, answer 202.
    // path and content_type point into the head buffer, which the body read
    // below reuses — copy them first or they get clobbered with body bytes.
    const fault, const fault_arg = ctx.takeFault();
    // These answer (or refuse to) before the body is read, which is what a
    // real intake does when it rejects a batch on its headers.
    switch (fault) {
        .reject_early => {
            try request.respond("{\"errors\":[\"invalid payload\"]}", .{
                .keep_alive = false,
                .status = .bad_request,
                .extra_headers = &json_headers,
            });
            return;
        },
        .reset => {
            resetConnection(stream);
            return error.FaultReset;
        },
        .garbage => {
            writeRaw(ctx, stream, "NOT-HTTP \x00\x01 garbage\r\n\r\n");
            return error.FaultGarbage;
        },
        .truncate => {
            writeRaw(
                ctx,
                stream,
                "HTTP/1.1 202 Accepted\r\ncontent-length: 4096\r\n\r\nshort",
            );
            return error.FaultTruncate;
        },
        else => {},
    }

    const path_copy = try gpa.dupe(u8, path);
    defer gpa.free(path_copy);
    const content_type_copy: ?[]const u8 = if (request.head.content_type) |ct|
        try gpa.dupe(u8, ct)
    else
        null;
    defer if (content_type_copy) |ct| gpa.free(ct);

    var body_buf: [16 * 1024]u8 = undefined;
    var captured: std.Io.Writer.Allocating = .init(gpa);
    defer captured.deinit();
    if (!unframed_body) {
        const body_reader = try request.readerExpectContinue(&body_buf);
        while (true) {
            const n = body_reader.stream(&captured.writer, .limited(5 * 1024 * 1024)) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return err,
            };
            if (n == 0) break;
        }
    }
    const body = captured.written();

    ctx.recordRequest(path_copy, body.len);
    if (body.len > 0) {
        ctx.capturePayload(path_copy, content_type_copy orelse "application/octet-stream", body);
    }
    // Stand in for a real intake round trip. A loopback echo answers in
    // microseconds, so every proxy under test looks thread-unbounded; against
    // a remote intake a handler owns its slot for the whole exchange and
    // throughput collapses to `handler_threads / round_trip`. Applied to the
    // echo path only, so /stats and /reset stay instant for the harness.
    if (latency_ms > 0) try ctx.io.sleep(.fromMilliseconds(latency_ms), .awake);

    switch (fault) {
        .hang => {
            // Long enough that every deadline under test fires first.
            try ctx.io.sleep(.fromMilliseconds(600_000), .awake);
            return;
        },
        .close_early => return error.FaultCloseEarly,
        .slow => try ctx.io.sleep(.fromMilliseconds(fault_arg), .awake),
        .status => {
            try request.respond("{\"faulted\":true}", .{
                .keep_alive = keep_alive,
                .status = @enumFromInt(fault_arg),
                .extra_headers = &json_headers,
            });
            return;
        },
        .oversize => {
            const filler = try gpa.alloc(u8, fault_arg);
            defer gpa.free(filler);
            @memset(filler, 'x');
            try request.respond(filler, .{ .keep_alive = keep_alive, .status = .accepted });
            return;
        },
        .stale_keepalive => {
            // Answer, then drop the connection the client just pooled.
            try request.respond("{}", .{ .keep_alive = true, .status = .accepted, .extra_headers = &json_headers });
            return error.FaultStaleKeepalive;
        },
        else => {},
    }
    try request.respond("{}", .{ .keep_alive = keep_alive, .status = .accepted, .extra_headers = &json_headers });
}

fn serveConnection(ctx: *ServerContext, gpa: std.mem.Allocator, stream: std.Io.net.Stream) std.Io.Cancelable!void {
    defer stream.close(ctx.io);

    var recv_buf: [32 * 1024]u8 = undefined;
    var send_buf: [32 * 1024]u8 = undefined;
    var net_reader = std.Io.net.Stream.Reader.init(stream, ctx.io, &recv_buf);
    var net_writer = std.Io.net.Stream.Writer.init(stream, ctx.io, &send_buf);
    var server = std.http.Server.init(&net_reader.interface, &net_writer.interface);

    while (server.reader.state == .ready) {
        var request = server.receiveHead() catch return;
        // A fault that closes the connection surfaces as an error, and the
        // defer above closes the stream.
        handleRequest(ctx, &request, gpa, stream) catch return;
    }
}

/// Simulated upstream round trip, from ECHO_LATENCY_MS. Read once at startup.
var latency_ms: i64 = 0;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    const args = try init.minimal.args.toSlice(init.arena.allocator());

    const port: u16 = if (args.len > 1)
        try std.fmt.parseInt(u16, args[1], 10)
    else
        9999;

    const output_dir: []const u8 = if (args.len > 2)
        args[2]
    else
        ".";

    if (init.environ_map.get("ECHO_LATENCY_MS")) |raw| {
        latency_ms = std.fmt.parseInt(i64, std.mem.trim(u8, raw, " \t\r\n"), 10) catch |err| {
            std.debug.print("invalid ECHO_LATENCY_MS '{s}': {s}\n", .{ raw, @errorName(err) });
            return err;
        };
    }

    // Own the io instance instead of inheriting it. std.Io.Threaded defaults
    // async_limit to cpu_count - 1, and the latency sleep below holds a slot
    // for its whole duration. Inherited, that caps the echo server at roughly
    // cpu_count / latency requests per second — 11 concurrent sleeps on a
    // 12-core box, which makes the upstream, not the proxy under test, the
    // bottleneck. The limit has to exceed target_rate x latency; sleeping
    // tasks are parked, so a high ceiling costs little.
    var threaded: std.Io.Threaded = .init(allocator, .{ .async_limit = .limited(2048) });
    defer threaded.deinit();
    const io = threaded.io();

    var ctx = ServerContext.init(allocator, io, output_dir);
    defer ctx.deinit();
    server_context = &ctx;

    std.posix.sigaction(std.posix.SIG.INT, &.{
        .handler = .{ .handler = shutdown },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    }, null);

    const address = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    var listener = try address.listen(io, .{ .reuse_address = true, .kernel_backlog = 1024 });
    defer listener.deinit(io);

    std.debug.print("Echo server listening on http://127.0.0.1:{d}\n", .{port});
    std.debug.print("Output directory: {s}\n", .{output_dir});
    std.debug.print("Simulated upstream latency: {d} ms\n", .{latency_ms});
    std.debug.print("Endpoints:\n", .{});
    std.debug.print("  POST /*           - Echo and record request\n", .{});
    std.debug.print("  GET  /stats       - Get statistics\n", .{});
    std.debug.print("  POST /reset       - Reset statistics\n", .{});
    std.debug.print("  GET  /capture/start?name=<name> - Start capturing payloads\n", .{});
    std.debug.print("  GET  /capture/stop - Stop capturing and save to file\n", .{});
    std.debug.print("  POST /fault?mode=<mode>&arg=<n>&count=<n> - Arm an upstream fault\n", .{});
    std.debug.print("Press Ctrl+C to stop\n", .{});

    var group: std.Io.Group = .init;
    defer group.cancel(io);
    while (true) {
        const stream = listener.accept(io) catch |err| switch (err) {
            error.Canceled => return,
            else => continue,
        };
        group.concurrent(io, serveConnection, .{ &ctx, allocator, stream }) catch {
            stream.close(io);
        };
    }
}
