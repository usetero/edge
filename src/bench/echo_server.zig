const std = @import("std");
const httpz = @import("httpz");

const EndpointStats = struct {
    requests: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
};

const CapturedPayload = struct {
    path: []const u8,
    content_type: []const u8,
    data: []const u8,
};

const ServerContext = struct {
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    endpoint_stats: std.StringHashMap(EndpointStats),
    total_requests: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    total_bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    // Capture mode state
    capture_mutex: std.Thread.Mutex = .{},
    capture_enabled: bool = false,
    capture_name: ?[]const u8 = null,
    captured_payloads: std.ArrayListUnmanaged(CapturedPayload) = .empty,
    output_dir: []const u8 = ".",

    pub fn init(allocator: std.mem.Allocator, output_dir: []const u8) ServerContext {
        return .{
            .allocator = allocator,
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
        self.capture_mutex.lock();
        defer self.capture_mutex.unlock();

        self.clearCaptures();
        if (self.capture_name) |old_name| {
            self.allocator.free(old_name);
        }
        self.capture_name = try self.allocator.dupe(u8, name);
        self.capture_enabled = true;
    }

    pub fn stopCapture(self: *ServerContext) !usize {
        self.capture_mutex.lock();
        defer self.capture_mutex.unlock();

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

        const file = try std.fs.cwd().createFile(path, .{});
        defer file.close();

        var buf: [4096]u8 = undefined;
        var file_writer = file.writer(&buf);
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
        self.capture_mutex.lock();
        defer self.capture_mutex.unlock();

        if (!self.capture_enabled) return;

        const payload = CapturedPayload{
            .path = self.allocator.dupe(u8, path) catch return,
            .content_type = self.allocator.dupe(u8, content_type) catch return,
            .data = self.allocator.dupe(u8, data) catch return,
        };
        self.captured_payloads.append(self.allocator, payload) catch return;
    }

    pub fn recordRequest(self: *ServerContext, path: []const u8, body_len: usize) void {
        _ = self.total_requests.fetchAdd(1, .monotonic);
        _ = self.total_bytes.fetchAdd(body_len, .monotonic);

        self.mutex.lock();
        defer self.mutex.unlock();

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

        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.endpoint_stats.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.requests.store(0, .monotonic);
            entry.value_ptr.bytes.store(0, .monotonic);
        }

        // Also clear captures
        self.capture_mutex.lock();
        defer self.capture_mutex.unlock();
        self.clearCaptures();
        self.capture_enabled = false;
    }

    pub fn writeStats(self: *ServerContext, writer: anytype) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

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

        self.capture_mutex.lock();
        defer self.capture_mutex.unlock();

        try writer.print("}},\"total_requests\":{d},\"total_bytes\":{d},\"capture_enabled\":{},\"captured_count\":{d}}}", .{
            self.total_requests.load(.monotonic),
            self.total_bytes.load(.monotonic),
            self.capture_enabled,
            self.captured_payloads.items.len,
        });
    }
};

var server_context: ?*ServerContext = null;

fn shutdown(_: c_int) callconv(.c) void {
    if (server_context) |ctx| {
        std.debug.print("\nReceived {d} requests, {d} bytes.\n", .{
            ctx.total_requests.load(.monotonic),
            ctx.total_bytes.load(.monotonic),
        });
    }
    std.process.exit(0);
}

fn handleRequest(ctx: *ServerContext, req: *httpz.Request, res: *httpz.Response) !void {
    const path = req.url.path;

    // Handle stats endpoint
    if (std.mem.eql(u8, path, "/stats")) {
        res.status = 200;
        res.content_type = .JSON;
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        try ctx.writeStats(buf.writer(ctx.allocator));
        res.body = try buf.toOwnedSlice(ctx.allocator);
        return;
    }

    // Handle reset endpoint
    if (std.mem.eql(u8, path, "/reset")) {
        ctx.reset();
        res.status = 200;
        res.body = "{\"status\":\"reset\"}";
        return;
    }

    // Handle capture start endpoint: /capture/start?name=<name>
    if (std.mem.eql(u8, path, "/capture/start")) {
        const query = req.url.query;
        // Parse name from query string (format: name=value or just value)
        const capture_name = if (query.len == 0)
            "capture"
        else if (std.mem.indexOf(u8, query, "name=")) |idx|
            query[idx + 5 ..]
        else
            query;

        ctx.startCapture(capture_name) catch |err| {
            res.status = 500;
            res.body = @errorName(err);
            return;
        };
        res.status = 200;
        res.content_type = .JSON;
        res.body = "{\"status\":\"capture_started\"}";
        return;
    }

    // Handle capture stop endpoint
    if (std.mem.eql(u8, path, "/capture/stop")) {
        const count = ctx.stopCapture() catch |err| {
            res.status = 500;
            res.body = @errorName(err);
            return;
        };
        res.status = 200;
        res.content_type = .JSON;

        var buf: [128]u8 = undefined;
        const json = std.fmt.bufPrint(&buf, "{{\"status\":\"capture_stopped\",\"count\":{d}}}", .{count}) catch {
            res.body = "{\"status\":\"capture_stopped\"}";
            return;
        };
        res.body = try ctx.allocator.dupe(u8, json);
        return;
    }

    // Record stats for all other requests
    const body = req.body();
    const body_len = if (body) |b| b.len else 0;
    ctx.recordRequest(path, body_len);

    // Capture payload if capture mode is enabled
    if (body) |b| {
        const content_type = req.header("content-type") orelse "application/octet-stream";
        ctx.capturePayload(path, content_type, b);
    }

    res.status = 202;
    res.body = "{}";
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const port: u16 = if (args.len > 1)
        try std.fmt.parseInt(u16, args[1], 10)
    else
        9999;

    const output_dir: []const u8 = if (args.len > 2)
        args[2]
    else
        ".";

    var ctx = ServerContext.init(allocator, output_dir);
    defer ctx.deinit();
    server_context = &ctx;

    std.posix.sigaction(std.posix.SIG.INT, &.{
        .handler = .{ .handler = shutdown },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    }, null);

    var server = try httpz.Server(*ServerContext).init(allocator, .{
        .port = port,
        .address = "127.0.0.1",
        .request = .{
            .max_body_size = 5194304,
        },
    }, &ctx);

    var router = try server.router(.{});
    router.get("/stats", handleRequest, .{});
    router.post("/reset", handleRequest, .{});
    router.get("/capture/start", handleRequest, .{});
    router.post("/capture/start", handleRequest, .{});
    router.get("/capture/stop", handleRequest, .{});
    router.post("/capture/stop", handleRequest, .{});
    router.post("/*", handleRequest, .{});

    std.debug.print("Echo server listening on http://127.0.0.1:{d}\n", .{port});
    std.debug.print("Output directory: {s}\n", .{output_dir});
    std.debug.print("Endpoints:\n", .{});
    std.debug.print("  POST /*           - Echo and record request\n", .{});
    std.debug.print("  GET  /stats       - Get statistics\n", .{});
    std.debug.print("  POST /reset       - Reset statistics\n", .{});
    std.debug.print("  GET  /capture/start?name=<name> - Start capturing payloads\n", .{});
    std.debug.print("  GET  /capture/stop - Stop capturing and save to file\n", .{});
    std.debug.print("Press Ctrl+C to stop\n", .{});

    try server.listen();
}
