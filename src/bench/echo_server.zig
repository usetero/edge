const std = @import("std");
const httpz = @import("httpz");

const EndpointStats = struct {
    requests: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
};

const ServerContext = struct {
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    endpoint_stats: std.StringHashMap(EndpointStats),
    total_requests: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    total_bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub fn init(allocator: std.mem.Allocator) ServerContext {
        return .{
            .allocator = allocator,
            .endpoint_stats = std.StringHashMap(EndpointStats).init(allocator),
        };
    }

    pub fn deinit(self: *ServerContext) void {
        var it = self.endpoint_stats.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.endpoint_stats.deinit();
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

        try writer.print("}},\"total_requests\":{d},\"total_bytes\":{d}}}", .{
            self.total_requests.load(.monotonic),
            self.total_bytes.load(.monotonic),
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

    // Record stats for all other requests
    const body_len = if (req.body()) |body| body.len else 0;
    ctx.recordRequest(path, body_len);

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

    var ctx = ServerContext.init(allocator);
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
    router.post("/*", handleRequest, .{});

    std.debug.print("Echo server listening on http://127.0.0.1:{d}\n", .{port});
    std.debug.print("Endpoints: POST /* (echo), GET /stats, POST /reset\n", .{});
    std.debug.print("Press Ctrl+C to stop\n", .{});

    try server.listen();
}
