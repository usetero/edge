const std = @import("std");
const config_types = @import("../config/types.zig");

pub const ConnectionFds = struct {
    client: std.posix.socket_t,
    upstream: std.posix.socket_t,
};

pub const ConnectionQueue = struct {
    items: std.ArrayList(ConnectionFds),
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex,
    condvar: std.Thread.Condition,

    pub fn init(allocator: std.mem.Allocator, capacity: usize) !ConnectionQueue {
        const items = try std.ArrayList(ConnectionFds).initCapacity(allocator, capacity);
        return .{
            .items = items,
            .allocator = allocator,
            .mutex = .{},
            .condvar = .{},
        };
    }

    pub fn deinit(self: *ConnectionQueue) void {
        self.items.deinit(self.allocator);
    }

    pub fn push(self: *ConnectionQueue, fds: ConnectionFds) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        try self.items.append(self.allocator, fds);
        self.condvar.signal();
    }

    pub fn pop(self: *ConnectionQueue) ?ConnectionFds {
        self.mutex.lock();
        defer self.mutex.unlock();

        while (self.items.items.len == 0) {
            self.condvar.wait(&self.mutex);
        }

        return self.items.orderedRemove(0);
    }

    pub fn tryPop(self: *ConnectionQueue) ?ConnectionFds {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.items.items.len == 0) return null;
        return self.items.orderedRemove(0);
    }
};

pub const ThreadPool = struct {
    threads: []std.Thread,
    queue: ConnectionQueue,
    config: *const std.atomic.Value(*const config_types.ProxyConfig),
    shutdown: std.atomic.Value(bool),
    allocator: std.mem.Allocator,

    pub fn init(
        allocator: std.mem.Allocator,
        config: *const std.atomic.Value(*const config_types.ProxyConfig),
        thread_count: u16,
    ) !ThreadPool {
        const threads = try allocator.alloc(std.Thread, thread_count);
        errdefer allocator.free(threads);

        var queue = try ConnectionQueue.init(allocator, 1024);
        errdefer queue.deinit();

        var pool = ThreadPool{
            .threads = threads,
            .queue = queue,
            .config = config,
            .shutdown = std.atomic.Value(bool).init(false),
            .allocator = allocator,
        };

        // Spawn worker threads
        for (threads, 0..) |*thread, i| {
            thread.* = try std.Thread.spawn(.{}, workerMain, .{ &pool, i });
        }

        return pool;
    }

    pub fn deinit(self: *ThreadPool) void {
        self.shutdown.store(true, .release);

        // Signal all threads to wake up
        for (0..self.threads.len) |_| {
            self.queue.condvar.signal();
        }

        // Wait for all threads to finish
        for (self.threads) |thread| {
            thread.join();
        }

        self.queue.deinit();
        self.allocator.free(self.threads);
    }

    pub fn submit(self: *ThreadPool, fds: ConnectionFds) !void {
        try self.queue.push(fds);
    }

    fn workerMain(pool: *ThreadPool, thread_id: usize) void {
        // Per-thread GPA to reduce contention
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();

        std.log.info("Worker thread {} started", .{thread_id});

        while (!pool.shutdown.load(.acquire)) {
            const fds = pool.queue.pop() orelse continue;

            const current_config = pool.config.load(.acquire);

            // Import worker module for connection handling
            const worker = @import("worker.zig");
            worker.handleConnection(
                gpa.allocator(),
                fds.client,
                fds.upstream,
                current_config,
            ) catch |err| {
                std.log.err("Thread {}: connection error: {}", .{ thread_id, err });
            };
        }

        std.log.info("Worker thread {} shutting down", .{thread_id});
    }
};
