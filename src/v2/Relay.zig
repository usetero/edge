//! Opt-in phase-one raw relay. One reactor owns clients; fixed workers own upstreams.
const Self = @This();

const std = @import("std");
const policy = @import("policy_zig");
const Processing = @import("Processing.zig");
const Routes = @import("Routes.zig");
const Admin = @import("Admin.zig");
const FileResponse = @import("FileResponse.zig");
const Poller = @import("os/Poller.zig");
const Origin = @import("Origin.zig");
const UpstreamLane = @import("UpstreamLane.zig");
const service = @import("../service/service.zig");
const PolicyStore = @import("PolicyStore.zig");
const Acceptor = @import("Acceptor.zig");
const AcceptChannel = @import("AcceptChannel.zig");
const Connections = @import("Connections.zig");
const HeadScanner = @import("HeadScanner.zig");
const RequestHead = @import("RequestHead.zig");
const RequestIngress = @import("RequestIngress.zig");
const RequestTable = @import("RequestTable.zig");
const RequestWire = @import("RequestWire.zig");
const Response = @import("Response.zig");
const ResponseHead = @import("ResponseHead.zig");
const ResponseIngress = @import("ResponseIngress.zig");
const ResponseWire = @import("ResponseWire.zig");
const UpstreamWatch = @import("UpstreamWatch.zig");
const WorkChannel = @import("WorkChannel.zig");
const http_field = @import("http_field.zig");

pub const HEAD_BYTES = 16 * 1024;
pub const TRAILER_BYTES = 4096;
pub const FIELDS = 64;
pub const TRAILERS = 16;
// Phase-0 gzip probes exceed 600 KiB; retain headroom for policy/codec frames.
pub const STACK_BYTES = 2 * 1024 * 1024;
const POLL_MS = 10;
const TURN_BYTES = 64 * 1024;
const CONTINUE = "HTTP/1.1 100 Continue\r\n\r\n";

pub const Config = struct {
    listen: std.Io.net.IpAddress,
    upstream: std.Io.net.IpAddress,
    authority: []const u8,
    connections: u32 = 64,
    requests: u32 = 16,
    workers: u16 = 4,
    body_bytes: u32 = 1024 * 1024,
    response_bytes: u32 = 1024 * 1024,
    timeout_ms: u32 = 5000,
    budget_bytes: u64 = 128 * 1024 * 1024,
    policy_store: ?*PolicyStore = null,
    extension_sink: ?policy.ExtensionSink = null,
    tap: ?*@import("../pipeline/tap.zig").TapState = null,
    processing: Processing.Limits = .{},
    distribution: Routes.Distribution = .edge,
    prometheus: Routes.Options = .{},
    default_origin: ?Origin = null,
    ca_bundle: ?*std.crypto.Certificate.Bundle = null,
    ca_lock: ?*std.Io.RwLock = null,
    tls_allocator: ?std.mem.Allocator = null,
    logs_upstream: ?Origin = null,
    metrics_upstream: ?Origin = null,

    fn origin(self: Config, choice: service.UpstreamChoice) Origin {
        const fallback = self.default_origin orelse Origin{ .address = self.upstream, .authority = self.authority };
        return switch (choice) {
            .default => fallback,
            .logs => self.logs_upstream orelse fallback,
            .metrics => self.metrics_upstream orelse fallback,
        };
    }

    fn connectionLimits(self: Config) Connections.Limits {
        return .{ .sockets = self.connections, .head_bytes = HEAD_BYTES, .events = 64 };
    }

    fn requestLimits(self: Config) RequestTable.Limits {
        return .{
            .requests = self.requests,
            .head_bytes = HEAD_BYTES,
            .body_bytes = self.body_bytes,
            .trailer_bytes = TRAILER_BYTES,
            .response_bytes = self.response_bytes,
            // Bounded informational heads precede the final head in this region.
            .response_head_bytes = 64 * 1024 + HEAD_BYTES + 18,
            .response_tail_bytes = TRAILER_BYTES + TRAILERS + 5,
        };
    }
};

const Client = struct {
    token: u64 = 0,
    scanner: HeadScanner = .{ .limit = HEAD_BYTES },
    buffered: usize = 0,
    parsed: ?RequestHead = null,
    ingress: ?RequestIngress = null,
    response: ?Response = null,
    local: bool = false,
    file_response: ?FileResponse.Complete = null,
    file_offset: u64 = 0,
    file_buffered: usize = 0,
    file_sent: usize = 0,
    file_tail: []const u8 = "",
    continue_offset: ?usize = null,
    deadline: std.Io.Timestamp = .{ .nanoseconds = 0 },
    fields: [FIELDS]RequestHead.Field = undefined,
    trailer_fields: [TRAILERS]RequestHead.Field = undefined,
    line: [1024]u8 = undefined,
};

config: Config,
connections: Connections,
requests: RequestTable,
channel: WorkChannel,
accepts: AcceptChannel,
acceptor: Acceptor,
watch: UpstreamWatch,
clients: []Client,
threads: []std.Thread,
workspaces: []Processing.Workspace,
evaluated: std.atomic.Value(u64) = .init(0),
policy_dropped: std.atomic.Value(u64) = .init(0),
processing_bypassed: std.atomic.Value(u64) = .init(0),
stopping: std.atomic.Value(bool) = .init(false),
accept_failed: std.atomic.Value(bool) = .init(false),
completed: u64 = 0,
failed: u64 = 0,
peak_requests: u32 = 0,

/// Validated application reservations, including explicit native thread stacks.
/// The main stack allowance is conservative; kernel/allocator/backend overhead is separate.
pub fn requiredBytes(config: Config) !u64 {
    if (config.workers == 0 or config.workers > 64 or config.requests < config.workers or
        config.connections < config.requests or config.timeout_ms < 50 or config.timeout_ms > 300000 or
        config.body_bytes > 64 * 1024 * 1024 or config.response_bytes > 64 * 1024 * 1024 or
        config.upstream.getPort() == 0)
    {
        return error.InvalidConfig;
    }
    try RequestHead.validateAuthority(config.authority, false);
    var total: u64 = @sizeOf(Self) + 8 * 1024 * 1024;
    total = try std.math.add(
        u64,
        total,
        try Connections.requiredBytes(config.connectionLimits()) - @sizeOf(Connections),
    );
    total = try std.math.add(
        u64,
        total,
        try RequestTable.requiredBytes(config.requestLimits()) - @sizeOf(RequestTable),
    );
    total = try std.math.add(
        u64,
        total,
        try WorkChannel.requiredBytes(.{ .capacity = config.requests }) - @sizeOf(WorkChannel),
    );
    total = try std.math.add(
        u64,
        total,
        try AcceptChannel.requiredBytes(.{ .capacity = config.connections }) - @sizeOf(AcceptChannel),
    );
    total = try std.math.add(
        u64,
        total,
        @as(u64, config.connections) * @sizeOf(Client),
    );
    total = try std.math.add(
        u64,
        total,
        @as(u64, config.workers) * (@sizeOf(UpstreamWatch.Slot) + @sizeOf(std.Thread)),
    );
    if (config.policy_store != null) {
        const workspace_bytes = try Processing.Workspace.requiredBytes(config.processing);
        total = try std.math.add(u64, total, try std.math.mul(u64, config.workers, workspace_bytes));
    }
    return std.math.add(u64, total, (@as(u64, config.workers) + 2) * STACK_BYTES);
}

/// Keep the returned owner stable before run; all application backing stores allocate here.
pub fn init(allocator: std.mem.Allocator, io: std.Io, config: Config) !Self {
    if (try requiredBytes(config) > config.budget_bytes) return error.MemoryBudgetExceeded;
    // Clients, accepted-but-undrained sockets, upstream lanes and a fixed margin
    // for pollers/stdio/backend descriptors must fit the existing process limit.
    const descriptors = @as(u64, config.connections) * 2 + @as(u64, config.workers) * 3 + config.requests + 64;
    if (descriptors > (try std.posix.getrlimit(.NOFILE)).cur) return error.DescriptorBudgetExceeded;
    var connections: Connections = try .init(allocator, config.connectionLimits());
    errdefer connections.deinit(allocator);
    var requests: RequestTable = try .init(allocator, config.requestLimits());
    errdefer requests.deinit(allocator);
    var channel: WorkChannel = try .init(allocator, .{ .capacity = config.requests });
    errdefer channel.deinit(allocator);
    var accepts: AcceptChannel = try .init(allocator, .{ .capacity = config.connections });
    errdefer accepts.deinit(allocator, io);
    var watch: UpstreamWatch = try .init(allocator, config.workers);
    errdefer watch.deinit(allocator);
    const clients = try allocator.alloc(Client, config.connections);
    errdefer allocator.free(clients);
    @memset(clients, .{});
    const threads = try allocator.alloc(std.Thread, config.workers);
    errdefer allocator.free(threads);
    const workspace_count = if (config.policy_store != null) config.workers else 0;
    const workspaces = try allocator.alloc(Processing.Workspace, workspace_count);
    errdefer allocator.free(workspaces);
    var initialized: usize = 0;
    errdefer for (workspaces[0..initialized]) |*workspace| workspace.deinit(allocator);
    for (workspaces) |*workspace| {
        workspace.* = try .init(allocator, config.processing);
        workspace.tap = config.tap;
        initialized += 1;
    }
    return .{
        .config = config,
        .connections = connections,
        .requests = requests,
        .channel = channel,
        .accepts = accepts,
        .watch = watch,
        .clients = clients,
        .threads = threads,
        .workspaces = workspaces,
        .acceptor = try .init(io, config.listen, .{}),
    };
}

/// run joins every producer before returning, including error exits.
pub fn deinit(self: *Self, allocator: std.mem.Allocator, io: std.Io) void {
    self.acceptor.deinit(io);
    self.accepts.deinit(allocator, io);
    self.watch.deinit(allocator);
    self.channel.deinit(allocator);
    self.requests.deinit(allocator);
    self.connections.deinit(allocator);
    allocator.free(self.clients);
    allocator.free(self.threads);
    for (self.workspaces) |*workspace| workspace.deinit(allocator);
    allocator.free(self.workspaces);
    self.* = undefined;
}

/// External shutdown is an atomic flag; finite waits also survive failed wake hints.
pub fn run(self: *Self, io: std.Io, stop: *const std.atomic.Value(bool)) !void {
    var started: usize = 0;
    var accepting: ?std.Thread = null;
    defer self.shutdown(io, started, accepting);
    for (self.threads, 0..) |*thread, index| {
        thread.* = try std.Thread.spawn(.{ .stack_size = STACK_BYTES }, worker, .{ self, io, index });
        started += 1;
    }
    accepting = try std.Thread.spawn(.{ .stack_size = STACK_BYTES }, acceptLoop, .{ self, io });
    while (!stop.load(.acquire)) {
        if (self.accept_failed.load(.acquire)) return error.AcceptorFailed;
        const pending = self.turn(io);
        const events = try self.connections.readiness.wait(io, after(io, if (pending) 0 else POLL_MS));
        for (events) |event| {
            const fd = self.connections.readiness.descriptor(event.token) orelse continue;
            const client = self.lookupClient(event.token);
            if (event.failed) {
                self.close(client);
                continue;
            }
            self.handle(io, client, fd, event.readable, event.writable) catch self.close(client);
        }
    }
}

fn shutdown(self: *Self, io: std.Io, started: usize, accepting: ?std.Thread) void {
    self.stopping.store(true, .release);
    self.acceptor.wake() catch |err| {
        std.log.warn("shutdown wake: {t}; finite wait remains active", .{err});
    };
    if (accepting) |thread| thread.join();
    for (self.clients) |*client| self.close(client);
    self.channel.close(io);
    while (self.channel.outstanding != 0) {
        _ = self.watch.expire(io, .{ .nanoseconds = std.math.maxInt(i96) });
        self.completions(io);
        io.sleep(.fromMilliseconds(POLL_MS), .awake) catch |err| {
            std.log.warn("shutdown wait: {t}", .{err});
        };
    }
    for (self.threads[0..started]) |thread| thread.join();
}

fn acceptLoop(self: *Self, io: std.Io) void {
    defer self.acceptor.stop(io);
    const targets = [_]Acceptor.Target{.{ .channel = &self.accepts, .wake = &self.connections.readiness }};
    while (!self.stopping.load(.acquire)) {
        const report = self.acceptor.turn(io, &targets, 32) catch {
            self.accept_failed.store(true, .release);
            return;
        };
        if (report.control_error != null) {
            self.accept_failed.store(true, .release);
            return;
        }
        if (report.failure) |err| std.log.warn("accept backoff: {t}", .{err});
        if (report.wake_failures != 0) std.log.warn("accept wake failed; timed drain remains active", .{});
        if (report.stop == .budget) continue;
        self.acceptor.wait(io, after(io, POLL_MS)) catch {
            self.accept_failed.store(true, .release);
            return;
        };
    }
}

fn turn(self: *Self, io: std.Io) bool {
    _ = self.watch.expire(io, .now(io, .awake));
    self.completions(io);
    var accepted: usize = 0;
    while (accepted < 32) : (accepted += 1) {
        const fd = self.accepts.receive(io) orelse break;
        const token = self.connections.adopt(fd) catch continue;
        self.lookupClient(token).* = .{ .token = token, .deadline = after(io, self.config.timeout_ms) };
    }
    const now = std.Io.Timestamp.now(io, .awake).nanoseconds;
    for (self.clients) |*client| {
        if (client.token == 0) continue;
        const state = self.connections.state(client.token) catch {
            client.token = 0;
            continue;
        };
        // The worker owns the same absolute deadline and returns a framed 504.
        if (state != .processing and now >= client.deadline.nanoseconds) self.close(client);
    }
    var admitted_count: usize = 0;
    while (admitted_count < 32) : (admitted_count += 1) {
        const admission = self.connections.admitNext(&self.requests, &self.channel) catch break orelse break;
        const client = self.lookupClient(admission.connection);
        self.admitted(io, client, admission.request) catch self.close(client);
    }
    self.peak_requests = @max(self.peak_requests, self.requests.live);
    // A coalesced wake may already be gone while work remains after a turn cap.
    return accepted == 32 or admitted_count == 32;
}

fn admitted(self: *Self, io: std.Io, client: *Client, request: RequestTable.Id) !void {
    const buffer = try self.connections.head(client.token);
    const head_len = client.parsed.?.head_len;
    client.ingress = try .init(&self.requests, request, buffer[0..head_len], .{
        .head_fields = &client.fields,
        .line = &client.line,
        .trailer_fields = &client.trailer_fields,
    }, .{ .head = .{}, .body = .{ .body_bytes = self.config.body_bytes } });
    self.consume(client, buffer, head_len);
    if (try client.ingress.?.continueAction(client.buffered != 0) == .send_continue) {
        client.continue_offset = 0;
        try self.connections.setInterest(&self.requests, &self.channel, client.token, .{ .write = true });
    } else try self.body(io, client);
}

fn handle(self: *Self, io: std.Io, client: *Client, fd: std.posix.fd_t, readable: bool, writable: bool) !void {
    if (client.response != null) {
        if (writable) try self.writeResponse(io, client, fd);
        return;
    }
    if (client.continue_offset) |offset| {
        if (!writable) return;
        const count = try send(fd, CONTINUE[offset..]);
        client.continue_offset = offset + count;
        if (client.continue_offset.? == CONTINUE.len) {
            client.continue_offset = null;
            try self.connections.setInterest(&self.requests, &self.channel, client.token, .{ .read = true });
            try self.body(io, client);
        }
        return;
    }
    const state = try self.connections.state(client.token);
    if (!readable or (state != .reading_head and state != .reading_body)) return;
    const buffer = try self.connections.head(client.token);
    const result = std.c.recv(fd, buffer[client.buffered..].ptr, buffer.len - client.buffered, 0);
    if (result == 0) return error.EndOfStream;
    if (result < 0) return switch (std.posix.errno(result)) {
        .AGAIN, .INTR => {},
        else => error.ReadFailed,
    };
    client.buffered += @intCast(result);
    if (state == .reading_head) try self.head(client) else try self.body(io, client);
}

fn head(self: *Self, client: *Client) !void {
    const buffer = try self.connections.head(client.token);
    const scanned = client.scanner.feed(buffer[client.scanner.length..client.buffered]) catch {
        return self.local(client, "431 Request Header Fields Too Large", "");
    };
    const length = scanned.head_len orelse return;
    const parsed = RequestHead.parse(buffer[0..length], &client.fields, .{}) catch {
        return self.local(client, "400 Bad Request", "");
    };
    if (parsed.expectation == .unsupported) return self.local(client, "417 Expectation Failed", "");
    if (parsed.target_form == .authority) return self.local(client, "405 Method Not Allowed", "");
    if (parsed.framing == .content_length and parsed.framing.content_length > self.config.body_bytes) {
        return self.local(client, "413 Content Too Large", "");
    }
    const method = parsed.method.slice(buffer);
    if (std.mem.eql(u8, parsed.path_query.slice(buffer), "/health") and std.mem.eql(u8, method, "GET")) {
        return self.local(client, "200 OK", "ok\n");
    }
    const path_query = parsed.path_query.slice(buffer);
    const path_end = std.mem.indexOfScalar(u8, path_query, '?') orelse path_query.len;
    if (std.mem.eql(u8, path_query[0..path_end], "/_health") and std.mem.eql(u8, method, "GET")) {
        return self.local(client, "200 OK", "{\"status\":\"ok\"}");
    }
    if (Routes.method(method) == .OTHER) return self.local(client, "404 Not Found", "");
    client.parsed = parsed;
    try self.connections.enqueue(client.token);
}

fn body(self: *Self, io: std.Io, client: *Client) !void {
    const buffer = try self.connections.head(client.token);
    const result = client.ingress.?.feed(buffer[0..client.buffered]) catch |err| {
        // Retain the unpublished reservation until local output closes its client.
        if (err == error.BodyTooLarge) return self.local(client, "413 Content Too Large", "");
        return self.local(client, "400 Bad Request", "");
    };
    self.consume(client, buffer, result.consumed);
    if (result.status != .done) return;
    const input = try client.ingress.?.input(client.deadline);
    try self.connections.dispatch(io, &self.requests, &self.channel, client.token, input);
    client.ingress = null;
}

fn consume(_: *Self, client: *Client, buffer: []u8, count: usize) void {
    @memmove(buffer[0 .. client.buffered - count], buffer[count..client.buffered]);
    client.buffered -= count;
}

fn local(self: *Self, client: *Client, comptime status: []const u8, comptime body_bytes: []const u8) !void {
    const wire = "HTTP/1.1 " ++ status ++ "\r\nConnection: close\r\nContent-Length: " ++
        std.fmt.comptimePrint("{d}", .{body_bytes.len}) ++ "\r\n\r\n" ++ body_bytes;
    client.response = .{ .parts = .{ wire, "", "" }, .close = true };
    client.local = true;
    try self.connections.setInterest(&self.requests, &self.channel, client.token, .{ .write = true });
}

fn completions(self: *Self, io: std.Io) void {
    for (0..self.config.requests) |_| {
        const completion = self.channel.receive(io) orelse break;
        const token = self.connections.complete(&self.requests, &self.channel, completion) catch unreachable orelse {
            if (completion.outcome == .file_response) completion.outcome.file_response.file.close(io);
            continue;
        };
        const client = self.lookupClient(token);
        client.deadline = after(io, self.config.timeout_ms);
        self.completed += 1;
        switch (completion.outcome) {
            .framed_response => |lengths| {
                client.response = self.requests.responseView(completion.request, lengths) catch unreachable;
                self.connections.responseReady(&self.requests, &self.channel, token) catch {
                    self.close(client);
                };
            },
            .file_response => |response| {
                const spans = self.requests.responseView(completion.request, .{
                    .head = response.head,
                    .body = 0,
                    .tail = response.tail,
                    .close = true,
                }) catch unreachable;
                client.response = .{ .parts = .{ spans.parts[0], "", "" }, .close = true };
                client.file_response = response;
                client.file_tail = spans.parts[2];
                self.connections.responseReady(&self.requests, &self.channel, token) catch self.close(client);
            },
            .failed => |err| {
                self.failed += 1;
                if (err == error.Timeout) {
                    self.local(client, "504 Gateway Timeout", "") catch self.close(client);
                } else self.local(client, "502 Bad Gateway", "") catch self.close(client);
            },
            .response => unreachable,
        }
    }
}

fn writeResponse(self: *Self, io: std.Io, client: *Client, fd: std.posix.fd_t) !void {
    var remaining: usize = TURN_BYTES;
    while (remaining != 0) {
        const bytes = client.response.?.pending();
        if (bytes.len == 0) {
            if (client.file_response != null) {
                if (!try self.writeFile(io, client, fd, &remaining)) return;
                continue;
            }
            if (client.response.?.close or client.local) return self.close(client);
            client.response = null;
            try self.connections.finishResponse(&self.requests, &self.channel, client.token);
            client.scanner.reset();
            client.parsed = null;
            client.deadline = after(io, self.config.timeout_ms);
            if (client.buffered != 0) try self.head(client);
            return;
        }
        const count = try send(fd, bytes[0..@min(bytes.len, remaining)]);
        if (count == 0) return;
        try client.response.?.advance(count);
        remaining -= count;
    }
}

fn writeFile(self: *Self, io: std.Io, client: *Client, fd: std.posix.fd_t, remaining: *usize) !bool {
    const response = client.file_response.?;
    if (client.file_sent == client.file_buffered) {
        if (client.file_offset == response.length) {
            response.file.close(io);
            client.file_response = null;
            client.response = .{ .parts = .{ client.file_tail, "", "" }, .close = true };
            return true;
        }
        const buffer = try self.connections.head(client.token);
        const count: usize = @intCast(@min(buffer.len, response.length - client.file_offset));
        const read = try response.file.readPositionalAll(io, buffer[0..count], client.file_offset);
        if (read != count) return error.TruncatedResponseFile;
        client.file_buffered = read;
        client.file_sent = 0;
        client.file_offset += read;
    }
    const buffer = try self.connections.head(client.token);
    const bytes = buffer[client.file_sent..client.file_buffered];
    const sent = try send(fd, bytes[0..@min(bytes.len, remaining.*)]);
    client.file_sent += sent;
    remaining.* -= sent;
    return sent != 0;
}

fn close(self: *Self, client: *Client) void {
    if (client.token == 0) return;
    if (client.file_response) |response| Poller.closeFd(response.file.handle);
    self.connections.close(&self.requests, &self.channel, client.token) catch |err| {
        // An interest failure already closes and detaches the same incarnation.
        std.debug.assert(err == error.StaleConnection);
    };
    client.* = .{};
}

fn lookupClient(self: *Self, token: u64) *Client {
    return &self.clients[(token - 1) % self.clients.len];
}

fn worker(self: *Self, io: std.Io, index: usize) void {
    var lane: UpstreamLane = .{};
    defer lane.close(io);
    while (self.channel.take(io) catch null) |job| {
        const outcome: WorkChannel.Outcome = if (self.stopping.load(.acquire))
            .{ .failed = error.ShuttingDown }
        else if (self.exchange(io, index, job, &lane)) |outcome|
            outcome
        else |err|
            .{ .failed = if (std.Io.Timestamp.now(io, .awake).nanoseconds >= job.deadline.nanoseconds)
                error.Timeout
            else
                err };
        self.channel.publish(io, job, outcome);
        self.connections.readiness.wake() catch |err| {
            std.log.warn("completion wake: {t}; finite drain remains active", .{err});
        };
    }
}

fn exchange(self: *Self, io: std.Io, index: usize, job: WorkChannel.Job, lane: *UpstreamLane) !WorkChannel.Outcome {
    if (std.Io.Timestamp.now(io, .awake).nanoseconds >= job.deadline.nanoseconds) return error.Timeout;
    var fields: [FIELDS]RequestHead.Field = undefined;
    var trailer_fields: [TRAILERS]RequestHead.Field = undefined;
    var head_buffer: [HEAD_BYTES + 18]u8 = undefined;
    var tail_buffer: [TRAILER_BYTES + TRAILERS + 5]u8 = undefined;
    const request = try RequestHead.parse(job.head, &fields, .{});
    if (try self.admin(io, job, request)) |reply| return .{ .framed_response = reply };
    const headers = headersFor(job.head, fields[0..request.header_count]);
    const outcome = Routes.plan(self.config.distribution, .{
        .method = Routes.method(request.method.slice(job.head)),
        .path = request.path_query.slice(job.head),
        .content_type = headers.content_type,
        .content_encoding = headers.codec,
    }, self.config.prometheus) orelse return error.RouteNotFound;
    const origin = self.config.origin(switch (outcome) {
        .respond => .default,
        inline else => |value| value.upstream,
    });
    const processed = self.process(io, index, job, outcome, headers);
    if (processed.all_dropped and outcome == .pipe_buffered)
        return .{ .framed_response = try localJob(job, request, "{}") };
    const storage: RequestWire.Storage = .{
        .head = &head_buffer,
        .tail = &tail_buffer,
        .fields = &fields,
        .trailer_fields = &trailer_fields,
    };
    var wire = RequestWire.init(.{
        .head = job.head,
        .body = processed.body,
        .trailers = job.trailers,
        .source_body_len = if (processed.changed) job.body.len else null,
    }, .{ .authority = origin.authority }, storage, .{}) catch |err| fallback: {
        if (!processed.changed) return err;
        _ = self.processing_bypassed.fetchAdd(1, .monotonic);
        break :fallback try RequestWire.init(.{
            .head = job.head,
            .body = job.body,
            .trailers = job.trailers,
        }, .{ .authority = origin.authority }, storage, .{});
    };
    const fresh = try lane.acquire(io, origin, job.deadline, &self.stopping);
    errdefer lane.close(io);
    self.watch.arm(io, index, lane.stream.?, job.deadline);
    var armed = true;
    defer if (armed) {
        _ = self.watch.disarm(io, index);
    };
    if (fresh) try lane.handshake(io, if (self.config.ca_bundle) |bundle| .{
        .allocator = self.config.tls_allocator.?,
        .bundle = bundle,
        .lock = self.config.ca_lock.?,
    } else null);
    const output = lane.output();
    while (wire.pending().len != 0) {
        const bytes = wire.pending();
        output.writeAll(bytes) catch return error.TimeoutOrWriteFailed;
        try wire.advance(bytes.len);
    }
    try lane.flush();
    if (outcome == .fetch_filtered and (outcome.fetch_filtered.max_input_bytes == 0 or
        outcome.fetch_filtered.max_output_bytes == 0))
    {
        const response = try FileResponse.receive(io, lane.input(), job.responseBuffers(), request.version, if (self.config.policy_store) |store| .{
            .store = store,
            .workspace = &self.workspaces[index],
            .input_cap = outcome.fetch_filtered.max_input_bytes,
            .output_cap = outcome.fetch_filtered.max_output_bytes,
            .deadline = job.deadline,
            .stopped = &self.stopping,
        } else null);
        errdefer response.file.close(io);
        const expired = self.watch.disarm(io, index);
        armed = false;
        lane.close(io);
        if (expired) return error.Timeout;
        return .{ .file_response = response };
    }
    var reusable = false;
    const lengths = self.receive(io, index, lane.input(), job, request, outcome, &reusable) catch |err| {
        const expired = self.watch.disarm(io, index);
        armed = false;
        return if (expired or std.Io.Timestamp.now(io, .awake).nanoseconds >= job.deadline.nanoseconds)
            error.Timeout
        else
            err;
    };
    const expired = self.watch.disarm(io, index);
    armed = false;
    if (expired or std.Io.Timestamp.now(io, .awake).nanoseconds >= job.deadline.nanoseconds) return error.Timeout;
    lane.release(io, reusable);
    return .{ .framed_response = lengths };
}

fn admin(self: *Self, io: std.Io, job: WorkChannel.Job, request: RequestHead) !?Response.Lengths {
    if (!std.mem.eql(u8, request.method.slice(job.head), "GET")) return null;
    const query = request.path_query.slice(job.head);
    const end = std.mem.findScalar(u8, query, '?') orelse query.len;
    const path = query[0..end];
    var writer: std.Io.Writer = .fixed(job.response);
    var status: []const u8 = "200 OK";
    var content_type: []const u8 = "text/plain";
    if (std.mem.eql(u8, path, "/_edge/policies")) {
        const json = std.mem.indexOf(u8, query[end..], "format=json") != null;
        if (json) content_type = "application/json";
        Admin.policies(io, self.config.policy_store, &writer, json) catch {
            writer.end = 0;
            status = "503 Service Unavailable";
        };
    } else if (std.mem.eql(u8, path, "/_edge/metrics")) {
        try writer.print("tero_v2_evaluated_total {d}\ntero_v2_policy_dropped_total {d}\n" ++
            "tero_v2_processing_bypassed_total {d}\n", .{
            self.evaluated.load(.monotonic),           self.policy_dropped.load(.monotonic),
            self.processing_bypassed.load(.monotonic),
        });
    } else if (std.mem.eql(u8, path, "/_edge/tap/pre") or std.mem.eql(u8, path, "/_edge/tap/post")) {
        const claimed = Admin.tap(io, self.config.tap, query, &writer, job.deadline, &self.stopping) catch |err| {
            if (err != error.TapDisabled) return err;
            status = "404 Not Found";
            return try finishLocal(job, request, status, content_type, 0);
        };
        if (!claimed) status = "409 Conflict";
    } else return null;
    return try finishLocal(job, request, status, content_type, writer.buffered().len);
}

fn finishLocal(job: WorkChannel.Job, request: RequestHead, status: []const u8, content_type: []const u8, length: usize) !Response.Lengths {
    const connection: []const u8 = if (request.keep_alive) "" else "Connection: close\r\n";
    const head_bytes = try std.fmt.bufPrint(job.response_head, "{s} {s}\r\nContent-Type: {s}\r\nContent-Length: {d}\r\n{s}\r\n", .{ @tagName(request.version), status, content_type, length, connection });
    return .{ .head = @intCast(head_bytes.len), .body = @intCast(length), .tail = 0, .close = !request.keep_alive };
}

const Headers = struct { content_type: []const u8 = "", codec: []const u8 = "", partial: bool = false };

fn headersFor(head_bytes: []const u8, fields: []const RequestHead.Field) Headers {
    var result: Headers = .{};
    for (fields) |field| {
        const name = field.name.slice(head_bytes);
        const value = field.value.slice(head_bytes);
        if (std.ascii.eqlIgnoreCase(name, "content-range")) result.partial = true;
        if (std.ascii.eqlIgnoreCase(name, "content-encoding")) result.codec = value;
        if (std.ascii.eqlIgnoreCase(name, "content-type")) result.content_type = value;
    }
    return result;
}

fn process(
    self: *Self,
    io: std.Io,
    index: usize,
    job: WorkChannel.Job,
    outcome: Routes.Outcome,
    headers: Headers,
) Processing.Result {
    const store = self.config.policy_store orelse return .{ .body = job.body };
    if (headers.partial) return .{ .body = job.body };
    const workspace = &self.workspaces[index];
    const result = switch (outcome) {
        .pipe_stream => |pipe| if (pipe.format == .json_array)
            Processing.logs(io, store, workspace, job.body, headers.codec, self.config.extension_sink)
        else
            Processing.nested(
                io,
                store,
                workspace,
                job.body,
                headers.codec,
                headers.content_type,
                switch (pipe.signal) {
                    .log => .otlp_logs,
                    .metric => .otlp_metrics,
                    .trace => .otlp_traces,
                },
            ),
        .pipe_buffered => |pipe| Processing.nested(
            io,
            store,
            workspace,
            job.body,
            headers.codec,
            headers.content_type,
            switch (pipe.kind) {
                .datadog_metrics_json => .datadog_metrics,
                .otlp_logs_json => .otlp_logs,
                .otlp_metrics_json => .otlp_metrics,
                .otlp_traces_json => .otlp_traces,
            },
        ),
        else => return .{ .body = job.body },
    };
    _ = self.evaluated.fetchAdd(result.evaluated, .monotonic);
    _ = self.policy_dropped.fetchAdd(result.dropped, .monotonic);
    if (result.reason != .none) _ = self.processing_bypassed.fetchAdd(1, .monotonic);
    return result;
}

fn localJob(job: WorkChannel.Job, request: RequestHead, body_bytes: []const u8) !Response.Lengths {
    if (body_bytes.len > job.response.len) return error.OutputTooSmall;
    @memcpy(job.response[0..body_bytes.len], body_bytes);
    return finishLocal(job, request, "200 OK", "application/json", body_bytes.len);
}

fn receive(
    self: *Self,
    io: std.Io,
    index: usize,
    input: *std.Io.Reader,
    job: WorkChannel.Job,
    request: RequestHead,
    outcome: Routes.Outcome,
    reusable: *bool,
) !Response.Lengths {
    var head_buffer: [HEAD_BYTES]u8 = undefined;
    var trailers: [TRAILER_BYTES]u8 = undefined;
    var line: [1024]u8 = undefined;
    var fields: [FIELDS]RequestHead.Field = undefined;
    var trailer_fields: [TRAILERS]RequestHead.Field = undefined;
    const is_head = std.mem.eql(u8, request.method.slice(job.head), "HEAD");
    const method: ResponseHead.Method = if (is_head) .head else .ordinary;
    var ingress: ResponseIngress = try .init(.{
        .head = &head_buffer,
        .body = job.response,
        .fields = &fields,
        .line = &line,
        .trailers = &trailers,
        .trailer_fields = &trailer_fields,
    }, method, .{ .body_bytes = self.config.response_bytes });

    var interim: usize = 0;
    while (ingress.state != .done) {
        const bytes = input.peekGreedy(1) catch |err| {
            if (err != error.EndOfStream) return err;
            // exchange checks/disarms the watchdog before this can be published.
            try ingress.finish(.clean_eof);
            break;
        };
        const result = try ingress.feed(bytes);
        input.toss(result.consumed);
        if (result.status == .informational) {
            const view = try ingress.informational();
            if (request.version == .@"HTTP/1.1" and view.metadata.status != 100) {
                interim += try writeInterim(view, job.response_head[interim..][0..@min(
                    HEAD_BYTES,
                    64 * 1024 - interim,
                    job.response_head.len - interim,
                )]);
            }
        }
    }
    reusable.* = (try ingress.message()).reusable;
    var changed = false;
    if (outcome == .fetch_filtered and ingress.head.status == 200) {
        if (self.config.policy_store) |store| {
            const view = try ingress.message();
            const headers = headersFor(view.head.bytes, view.head.fields);
            if (!headers.partial and (std.mem.startsWith(u8, headers.content_type, "text/plain") or
                std.mem.startsWith(u8, headers.content_type, "application/openmetrics-text")))
            {
                const processed = Processing.prometheus(
                    io,
                    store,
                    &self.workspaces[index],
                    view.body,
                    headers.codec,
                    outcome.fetch_filtered.max_input_bytes,
                    outcome.fetch_filtered.max_output_bytes,
                );
                _ = self.evaluated.fetchAdd(processed.evaluated, .monotonic);
                _ = self.policy_dropped.fetchAdd(processed.dropped, .monotonic);
                if (processed.changed and processed.body.len <= job.response.len) {
                    @memcpy(job.response[0..processed.body.len], processed.body);
                    ingress.body_len = processed.body.len;
                    changed = true;
                } else if (processed.reason != .none or processed.changed) {
                    _ = self.processing_bypassed.fetchAdd(1, .monotonic);
                }
            }
        }
    }
    var buffers = job.responseBuffers();
    buffers.head = buffers.head[interim..];
    var lengths = try ResponseWire.prepare(&ingress, buffers, .{
        .version = request.version,
        .keep_alive = request.keep_alive,
        .changed = changed,
    }, .{});
    lengths.head += @intCast(interim);
    return lengths;
}

fn writeInterim(view: ResponseIngress.HeadView, buffer: []u8) !usize {
    var writer: std.Io.Writer = .fixed(buffer);
    try writer.print("HTTP/1.1 {d} {s}\r\n", .{ view.metadata.status, view.metadata.reason.slice(view.bytes) });
    var count: usize = 1; // Via is generated too.
    for (view.fields) |field| {
        const name = field.name.slice(view.bytes);
        if (ResponseWire.transportField(name) or http_field.nominated(name, view.bytes, view.fields)) continue;
        if (count == FIELDS) return error.TooManyHeaders;
        count += 1;
        try writer.print("{s}: {s}\r\n", .{ name, field.value.slice(view.bytes) });
    }
    try writer.writeAll("Via: 1.1 tero-edge\r\n\r\n");
    return writer.buffered().len;
}

fn send(fd: std.posix.fd_t, bytes: []const u8) !usize {
    const count = std.c.send(fd, bytes.ptr, bytes.len, std.posix.MSG.NOSIGNAL);
    if (count >= 0) return @intCast(count);
    return switch (std.posix.errno(count)) {
        .AGAIN, .INTR => 0,
        else => error.WriteFailed,
    };
}

fn after(io: std.Io, ms: u32) std.Io.Timestamp {
    return std.Io.Timestamp.now(io, .awake).addDuration(.fromMilliseconds(ms));
}

fn testConfig() !Config {
    return .{
        .listen = try .parseLiteral("127.0.0.1:0"),
        .upstream = try .parseLiteral("127.0.0.1:1"),
        .authority = "origin",
        .workers = 1,
        .requests = 1,
        .connections = 2,
        .body_bytes = 64,
        .response_bytes = 64,
    };
}

test "v2 relay aggregate reservation rejects before allocation and accepts equality" {
    var config = try testConfig();
    const bytes = try requiredBytes(config);
    config.budget_bytes = bytes - 1;
    try std.testing.expectError(
        error.MemoryBudgetExceeded,
        init(std.testing.failing_allocator, std.testing.io, config),
    );
    config.budget_bytes = bytes;
    var relay = try init(std.testing.allocator, std.testing.io, config);
    defer relay.deinit(std.testing.allocator, std.testing.io);
    try std.testing.expectEqual(bytes, try requiredBytes(config));
    config.workers = 2;
    try std.testing.expectError(error.InvalidConfig, requiredBytes(config));
    config = try testConfig();
    config.upstream.setPort(0);
    try std.testing.expectError(error.InvalidConfig, requiredBytes(config));
}

fn testStartup(allocator: std.mem.Allocator) !void {
    var relay = try init(allocator, std.testing.io, try testConfig());
    defer relay.deinit(allocator, std.testing.io);
}

test "v2 relay startup unwinds all application allocation failures" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, testStartup, .{});
}
