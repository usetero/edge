//! Reactor-owned request slots. A work/completion lease pins storage after disconnect.
const Self = @This();

const std = @import("std");
const Budget = @import("Budget.zig");
const Response = @import("Response.zig");

slots: []Slot,
storage: []u8,
capacity: Limits,
stride: usize,
free_head: u32,
live: u32 = 0,
retired: u32 = 0,

const NONE = std.math.maxInt(u32);

pub const Id = struct { index: u32, generation: u64 };

pub const Limits = struct {
    requests: u32,
    head_bytes: u32,
    body_bytes: u32,
    trailer_bytes: u32 = 0,
    response_bytes: u32,
    response_head_bytes: u32 = 0,
    response_tail_bytes: u32 = 0,
    ceiling_bytes: u64 = std.math.maxInt(u64),
};

const Slot = struct {
    generation: u64 = 1,
    connection_token: u64 = 0,
    next_free: u32 = NONE,
    state: enum { free, reading, forwarding, responding, detached, retired } = .free,
    lease: enum { none, reserved, work, completion } = .none,
    client_attached: bool = false,
};

pub const Buffers = struct {
    head: []u8,
    body: []u8,
    trailers: []u8,
    response: []u8,
    response_head: []u8,
    response_tail: []u8,

    /// Group the independently reserved response regions without copying bytes.
    pub fn responseBuffers(self: Buffers) Response.Buffers {
        return .{ .head = self.response_head, .body = self.response, .tail = self.response_tail };
    }
};

/// Allocate only for admitted request capacity, independently of idle connections.
/// All methods after init run on the owning reactor and allocate nothing.
pub fn init(allocator: std.mem.Allocator, capacity: Limits) !Self {
    const required = try requiredBytes(capacity);
    if (required > capacity.ceiling_bytes) return error.MemoryBudgetExceeded;
    const stride = std.math.cast(usize, try bufferBytes(capacity)) orelse return error.Overflow;
    const storage_len = try std.math.mul(usize, capacity.requests, stride);
    const slots = try allocator.alloc(Slot, capacity.requests);
    errdefer allocator.free(slots);
    const storage = try allocator.alloc(u8, storage_len);
    for (slots, 0..) |*slot, index| slot.* = .{
        .next_free = if (index + 1 < slots.len) @intCast(index + 1) else NONE,
    };
    return .{
        .slots = slots,
        .storage = storage,
        .capacity = capacity,
        .stride = stride,
        .free_head = 0,
    };
}

/// Drain work/completions and detach clients before destroying their backing bytes.
pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
    std.debug.assert(self.live == 0);
    allocator.free(self.storage);
    allocator.free(self.slots);
    self.* = undefined;
}

/// Requested bytes including real metadata layouts; allocator overhead is separate.
pub fn requiredBytes(capacity: Limits) !u64 {
    if (capacity.requests == 0 or capacity.requests == NONE or capacity.head_bytes == 0) {
        return error.InvalidCapacity;
    }
    const terms = try Budget.core(.{
        .connections = 0,
        .head_bytes = 0,
        .inflight_requests = capacity.requests,
        .max_body_bytes = capacity.body_bytes,
        .max_output_bytes = 0,
        .max_response_bytes = capacity.response_bytes,
        .request_overhead_bytes = @sizeOf(Slot) + @as(u64, capacity.head_bytes) + capacity.trailer_bytes +
            capacity.response_head_bytes + capacity.response_tail_bytes,
        .processing_workers = 0,
        .processing_workspace_bytes = 0,
        .forwarders = 0,
        .lane_bytes = 0,
        .forwarder_stack_bytes = 0,
        .control_bytes = @sizeOf(Self),
        .ceiling_bytes = std.math.maxInt(u64),
    });
    return terms.total;
}

/// Reserve head/input/trailer/response capacity before admitting a request body.
pub fn acquire(self: *Self) ?Id {
    if (self.free_head == NONE) return null;
    const index = self.free_head;
    const slot = &self.slots[index];
    std.debug.assert(slot.state == .free);
    self.free_head = slot.next_free;
    slot.next_free = NONE;
    slot.state = .reading;
    slot.client_attached = true;
    self.live += 1;
    return .{ .index = index, .generation = slot.generation };
}

/// Capacities contain uninitialized bytes. Consumers track initialized lengths.
/// Borrowed spans remain pinned through work and completion; do not call table
/// methods from a worker or access spans concurrently with that worker's writes.
pub fn buffers(self: *Self, id: Id) !Buffers {
    _ = try self.lookup(id);
    const start = @as(usize, id.index) * self.stride;
    const head_end = start + self.capacity.head_bytes;
    const body_end = head_end + self.capacity.body_bytes;
    const trailer_end = body_end + self.capacity.trailer_bytes;
    const response_head_end = trailer_end + self.capacity.response_head_bytes;
    const response_end = response_head_end + self.capacity.response_bytes;
    return .{
        .head = self.storage[start..head_end],
        .body = self.storage[head_end..body_end],
        .trailers = self.storage[body_end..trailer_end],
        .response_head = self.storage[trailer_end..response_head_end],
        .response = self.storage[response_head_end..response_end],
        .response_tail = self.storage[response_end .. start + self.stride],
    };
}

/// Reactor-only ingress access ends when admission is canceled or transferred.
/// Generation alone is insufficient: worker leases deliberately keep slots live.
pub fn ingressBuffers(self: *Self, id: Id) !Buffers {
    const slot = try self.lookup(id);
    if (slot.state != .reading or slot.lease != .reserved or !slot.client_attached) {
        return error.InvalidTransition;
    }
    return self.buffers(id);
}

/// Reactor-only, after acknowledging a live completion. Worker leases still own
/// their mutable output before then. Drop this view before disconnect or release.
pub fn responseView(self: *Self, id: Id, lengths: Response.Lengths) !Response {
    const slot = try self.lookup(id);
    if (slot.state != .responding or slot.lease != .none or !slot.client_attached) return error.InvalidTransition;
    return .init((try self.buffers(id)).responseBuffers(), lengths);
}

/// Bind once before dispatch. Zero is reserved for an unbound request. Retain
/// the original token after disconnect so late completion can reject socket reuse.
pub fn bindConnection(self: *Self, id: Id, token: u64) !void {
    const slot = try self.lookup(id);
    if (token == 0) return error.InvalidConnection;
    if (slot.state != .reading or slot.connection_token != 0) return error.InvalidTransition;
    slot.connection_token = token;
}

/// Read before acknowledging a detached completion, which may recycle the slot.
pub fn connectionToken(self: *Self, id: Id) !u64 {
    return (try self.lookup(id)).connection_token;
}

/// Pair with a channel credit before admitting body bytes. A disconnected
/// reservation stays pinned until the channel returns its credit explicitly.
pub fn reserve(self: *Self, id: Id) !void {
    const slot = try self.lookup(id);
    if (slot.state != .reading or slot.lease != .none) return error.InvalidTransition;
    slot.lease = .reserved;
}

/// Cancel admission before publication. Once dispatched, only completion can
/// release the work lease, even if the client has disappeared.
pub fn cancelReservation(self: *Self, id: Id) !void {
    const slot = try self.lookup(id);
    if (slot.lease != .reserved) return error.InvalidTransition;
    slot.lease = .none;
    if (!slot.client_attached) self.recycle(id.index);
}

/// Transfer an admission reservation to a job. The work lease follows the job
/// through its queue and worker until complete is applied.
pub fn dispatch(self: *Self, id: Id) !void {
    const slot = try self.lookup(id);
    if (slot.state != .reading or slot.lease != .reserved) return error.InvalidTransition;
    std.debug.assert(slot.client_attached);
    slot.state = .forwarding;
    slot.lease = .work;
}

/// Apply a worker completion on the reactor. Disconnect does not cancel ownership.
pub fn complete(self: *Self, id: Id) !void {
    const slot = try self.lookup(id);
    if (slot.lease != .work) return error.InvalidTransition;
    slot.lease = .completion;
    if (slot.client_attached) slot.state = .responding;
}

/// Release completion ownership after consuming all spans it refers to.
pub fn consumeCompletion(self: *Self, id: Id) !void {
    const slot = try self.lookup(id);
    if (slot.lease != .completion) return error.InvalidTransition;
    slot.lease = .none;
    if (!slot.client_attached) self.recycle(id.index);
}

/// Losing the client releases its reference, never a worker's borrowed storage.
pub fn disconnect(self: *Self, id: Id) !void {
    const slot = try self.lookup(id);
    if (!slot.client_attached) return error.InvalidTransition;
    slot.client_attached = false;
    if (slot.lease == .none) self.recycle(id.index) else slot.state = .detached;
}

/// Release a response only after the client write and completion consumption end.
pub fn finishResponse(self: *Self, id: Id) !void {
    const slot = try self.lookup(id);
    if (slot.state != .responding or slot.lease != .none) return error.InvalidTransition;
    slot.client_attached = false;
    self.recycle(id.index);
}

fn lookup(self: *Self, id: Id) !*Slot {
    if (id.index >= self.slots.len) return error.StaleRequest;
    const slot = &self.slots[id.index];
    if (slot.generation != id.generation or slot.state == .free or slot.state == .retired) {
        return error.StaleRequest;
    }
    return slot;
}

fn recycle(self: *Self, index: u32) void {
    const slot = &self.slots[index];
    std.debug.assert(!slot.client_attached);
    std.debug.assert(slot.lease == .none);
    std.debug.assert(self.live > 0);
    self.live -= 1;
    slot.connection_token = 0;
    if (slot.generation == std.math.maxInt(u64)) {
        slot.state = .retired;
        self.retired += 1;
        return;
    }
    slot.generation += 1;
    slot.state = .free;
    slot.next_free = self.free_head;
    self.free_head = index;
}

fn bufferBytes(capacity: Limits) !u64 {
    const input_bytes = try std.math.add(u64, capacity.head_bytes, capacity.body_bytes);
    const tail_bytes = try std.math.add(u64, capacity.trailer_bytes, capacity.response_bytes);
    const metadata_bytes = try std.math.add(u64, capacity.response_head_bytes, capacity.response_tail_bytes);
    return std.math.add(u64, try std.math.add(u64, input_bytes, tail_bytes), metadata_bytes);
}

const testing = std.testing;
const limits: Limits = .{
    .requests = 2,
    .head_bytes = 128,
    .body_bytes = 256,
    .trailer_bytes = 64,
    .response_bytes = 512,
    .response_head_bytes = 128,
    .response_tail_bytes = 64,
};

test "v2 request table bounds admission and rejects handles from a reused slot" {
    var table: Self = try .init(testing.allocator, limits);
    defer table.deinit(testing.allocator);
    const first = table.acquire().?;
    const second = table.acquire().?;
    try testing.expect(table.acquire() == null);
    try table.disconnect(first);
    const reused = table.acquire().?;
    try testing.expectEqual(first.index, reused.index);
    try testing.expect(reused.generation != first.generation);
    try testing.expectError(error.StaleRequest, table.dispatch(first));
    try table.disconnect(second);
    try table.disconnect(reused);
    try testing.expectEqual(@as(u32, 0), table.live);
}

test "v2 request storage survives disconnect until its completion is consumed" {
    var table: Self = try .init(testing.allocator, limits);
    defer table.deinit(testing.allocator);
    const id = table.acquire().?;
    const spans = try table.buffers(id);
    @memcpy(spans.body[0..4], "body");
    try table.reserve(id);
    try table.dispatch(id);
    try table.disconnect(id);
    try testing.expectEqual(@as(u32, 1), table.live);
    try testing.expectEqualStrings("body", (try table.buffers(id)).body[0..4]);
    try table.complete(id);
    try testing.expectError(error.InvalidTransition, table.complete(id));
    try testing.expectEqual(@as(u32, 1), table.live);
    try table.consumeCompletion(id);
    try testing.expectEqual(@as(u32, 0), table.live);
    try testing.expectError(error.StaleRequest, table.buffers(id));
}

test "v2 request response remains pinned after consuming a live completion" {
    var table: Self = try .init(testing.allocator, limits);
    defer table.deinit(testing.allocator);
    const id = table.acquire().?;
    try table.reserve(id);
    try table.dispatch(id);
    try table.complete(id);
    try testing.expectError(error.InvalidTransition, table.finishResponse(id));
    try table.consumeCompletion(id);
    try testing.expectEqual(@as(u32, 1), table.live);
    try table.finishResponse(id);
    try testing.expectEqual(@as(u32, 0), table.live);
}

test "v2 request disconnect after completion returns credit exactly once" {
    var table: Self = try .init(testing.allocator, limits);
    defer table.deinit(testing.allocator);
    const id = table.acquire().?;
    try table.reserve(id);
    try table.dispatch(id);
    try table.complete(id);
    try table.disconnect(id);
    try testing.expectError(error.InvalidTransition, table.disconnect(id));
    try table.consumeCompletion(id);
    try testing.expectError(error.StaleRequest, table.consumeCompletion(id));
}

test "v2 request table retires a generation before it wraps" {
    var table: Self = try .init(testing.allocator, .{
        .requests = 1,
        .head_bytes = 16,
        .body_bytes = 16,
        .response_bytes = 16,
    });
    defer table.deinit(testing.allocator);
    table.slots[0].generation = std.math.maxInt(u64);
    const id = table.acquire().?;
    try table.disconnect(id);
    try testing.expect(table.acquire() == null);
    try testing.expectEqual(@as(u32, 1), table.retired);
}

test "v2 request table checks capacity before allocation and unwinds startup failures" {
    var too_small = limits;
    too_small.ceiling_bytes = (try requiredBytes(limits)) - 1;
    try testing.expectError(error.MemoryBudgetExceeded, Self.init(testing.allocator, too_small));
    try testing.checkAllAllocationFailures(testing.allocator, testAllocation, .{});
}

test "v2 request table budget accounts for all backing storage at the exact ceiling" {
    var capacity = limits;
    capacity.ceiling_bytes = try requiredBytes(capacity);
    var table: Self = try .init(testing.allocator, capacity);
    defer table.deinit(testing.allocator);
    const actual = @sizeOf(Self) + table.slots.len * @sizeOf(Slot) + table.storage.len;
    try testing.expectEqual(capacity.ceiling_bytes, actual);
    try testing.expectError(error.Overflow, requiredBytes(.{
        .requests = std.math.maxInt(u32) - 1,
        .head_bytes = 1,
        .body_bytes = std.math.maxInt(u32),
        .response_bytes = std.math.maxInt(u32),
    }));
    capacity.requests = 0;
    try testing.expectError(error.InvalidCapacity, requiredBytes(capacity));
}

fn testAllocation(allocator: std.mem.Allocator) !void {
    var table: Self = try .init(allocator, limits);
    defer table.deinit(allocator);
    const first = table.acquire().?;
    const second = table.acquire().?;
    const a = try table.buffers(first);
    const b = try table.buffers(second);
    @memset(a.body, 1);
    @memset(a.trailers, 4);
    @memset(a.response, 2);
    @memset(a.response_head, 5);
    @memset(a.response_tail, 6);
    @memset(b.head, 3);
    try testing.expectEqual(@as(u8, 1), a.body[0]);
    try testing.expectEqual(@as(u8, 2), a.response[0]);
    try testing.expectEqual(@as(u8, 3), b.head[0]);
    try testing.expectEqual(@as(u8, 4), a.trailers[0]);
    try testing.expectEqual(@as(u8, 5), a.response_head[0]);
    try testing.expectEqual(@as(u8, 6), a.response_tail[0]);
    try table.disconnect(first);
    try table.disconnect(second);
}

test "v2 request connection binding persists until release and resets on reuse" {
    var table: Self = try .init(testing.allocator, limits);
    defer table.deinit(testing.allocator);
    const id = table.acquire().?;
    try testing.expectEqual(@as(u64, 0), try table.connectionToken(id));
    try testing.expectError(error.InvalidConnection, table.bindConnection(id, 0));
    try table.bindConnection(id, 123);
    try testing.expectError(error.InvalidTransition, table.bindConnection(id, 456));
    try table.reserve(id);
    try table.dispatch(id);
    try table.disconnect(id);
    try testing.expectEqual(@as(u64, 123), try table.connectionToken(id));
    try table.complete(id);
    try table.consumeCompletion(id);
    try testing.expectError(error.StaleRequest, table.connectionToken(id));
    const next = table.acquire().?;
    try testing.expectEqual(id.index, next.index);
    try testing.expectEqual(@as(u64, 0), try table.connectionToken(next));
    try table.disconnect(next);
}
