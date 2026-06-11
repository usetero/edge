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

pub const ServerContext = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    endpoint_stats: std.StringHashMap(EndpointStats),
    total_requests: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    total_bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

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

        try writer.print("}},\"total_requests\":{d},\"total_bytes\":{d}," ++
            "\"capture_enabled\":{},\"captured_count\":{d}}}", .{
            self.total_requests.load(.monotonic),
            self.total_bytes.load(.monotonic),
            self.capture_enabled,
            self.captured_payloads.items.len,
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

fn handleRequest(ctx: *ServerContext, request: *std.http.Server.Request, gpa: std.mem.Allocator) !void {
    const target = request.head.target;
    const query_start = std.mem.findScalar(u8, target, '?');
    const path = if (query_start) |i| target[0..i] else target;
    const query = if (query_start) |i| target[i + 1 ..] else "";

    const json_headers = [_]std.http.Header{
        .{ .name = "content-type", .value = "application/json" },
    };

    if (std.mem.eql(u8, path, "/stats")) {
        var buf: std.Io.Writer.Allocating = .init(gpa);
        defer buf.deinit();
        try ctx.writeStats(&buf.writer);
        try request.respond(buf.written(), .{ .extra_headers = &json_headers });
        return;
    }

    if (std.mem.eql(u8, path, "/reset")) {
        ctx.reset();
        try request.respond("{\"status\":\"reset\"}", .{ .extra_headers = &json_headers });
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
            try request.respond(@errorName(err), .{ .status = .internal_server_error });
            return;
        };
        try request.respond("{\"status\":\"capture_started\"}", .{ .extra_headers = &json_headers });
        return;
    }

    if (std.mem.eql(u8, path, "/capture/stop")) {
        const count = ctx.stopCapture() catch |err| {
            try request.respond(@errorName(err), .{ .status = .internal_server_error });
            return;
        };
        var buf: [128]u8 = undefined;
        const json = std.fmt.bufPrint(&buf, "{{\"status\":\"capture_stopped\",\"count\":{d}}}", .{count}) catch
            "{\"status\":\"capture_stopped\"}";
        try request.respond(json, .{ .extra_headers = &json_headers });
        return;
    }

    // All other requests: read body (5 MiB cap, matching the old config),
    // record stats, optionally capture, answer 202.
    const content_type_copy: ?[]const u8 = if (request.head.content_type) |ct|
        try gpa.dupe(u8, ct)
    else
        null;
    defer if (content_type_copy) |ct| gpa.free(ct);

    var body_buf: [16 * 1024]u8 = undefined;
    const body_reader = try request.readerExpectContinue(&body_buf);
    var captured: std.Io.Writer.Allocating = .init(gpa);
    defer captured.deinit();
    while (true) {
        const n = body_reader.stream(&captured.writer, .limited(5 * 1024 * 1024)) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (n == 0) break;
    }
    const body = captured.written();

    ctx.recordRequest(path, body.len);
    if (body.len > 0) {
        ctx.capturePayload(path, content_type_copy orelse "application/octet-stream", body);
    }
    try request.respond("{}", .{ .status = .accepted, .extra_headers = &json_headers });
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
        handleRequest(ctx, &request, gpa) catch return;
    }
}

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

    var ctx = ServerContext.init(allocator, init.io, output_dir);
    defer ctx.deinit();
    server_context = &ctx;

    std.posix.sigaction(std.posix.SIG.INT, &.{
        .handler = .{ .handler = shutdown },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    }, null);

    const address = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    var listener = try address.listen(init.io, .{ .reuse_address = true, .kernel_backlog = 1024 });
    defer listener.deinit(init.io);

    std.debug.print("Echo server listening on http://127.0.0.1:{d}\n", .{port});
    std.debug.print("Output directory: {s}\n", .{output_dir});
    std.debug.print("Endpoints:\n", .{});
    std.debug.print("  POST /*           - Echo and record request\n", .{});
    std.debug.print("  GET  /stats       - Get statistics\n", .{});
    std.debug.print("  POST /reset       - Reset statistics\n", .{});
    std.debug.print("  GET  /capture/start?name=<name> - Start capturing payloads\n", .{});
    std.debug.print("  GET  /capture/stop - Stop capturing and save to file\n", .{});
    std.debug.print("Press Ctrl+C to stop\n", .{});

    var group: std.Io.Group = .init;
    defer group.cancel(init.io);
    while (true) {
        const stream = listener.accept(init.io) catch |err| switch (err) {
            error.Canceled => return,
            else => continue,
        };
        group.concurrent(init.io, serveConnection, .{ &ctx, allocator, stream }) catch {
            stream.close(init.io);
        };
    }
}
