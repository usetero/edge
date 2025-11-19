const std = @import("std");
const config_types = @import("../config/types.zig");

pub const ConnectionFds = struct {
    client: std.posix.socket_t,
    upstream: std.posix.socket_t,
};

pub const ThreadPool = struct {
    threads: []std.Thread,
    queue: std.ArrayList(ConnectionFds),
    mutex: std.Thread.Mutex,
    config: *const std.atomic.Value(*const config_types.ProxyConfig),
    shutdown: std.atomic.Value(bool),
    allocator: std.mem.Allocator,

    pub fn init(
        allocator: std.mem.Allocator,
        config: *const std.atomic.Value(*const config_types.ProxyConfig),
        thread_count: u16,
    ) !*ThreadPool {
        std.log.info("ThreadPool.init: allocating pool on heap", .{});
        const pool = try allocator.create(ThreadPool);
        errdefer allocator.destroy(pool);

        std.log.info("ThreadPool.init: allocating {} threads", .{thread_count});
        const threads = try allocator.alloc(std.Thread, thread_count);
        errdefer allocator.free(threads);

        std.log.info("ThreadPool.init: initializing pool structure", .{});
        pool.* = ThreadPool{
            .threads = threads,
            .queue = .empty,
            .mutex = .{},
            .config = config,
            .shutdown = std.atomic.Value(bool).init(false),
            .allocator = allocator,
        };

        std.log.info("ThreadPool.init: spawning worker threads", .{});
        // Spawn worker threads
        for (threads, 0..) |*thread, i| {
            std.log.info("ThreadPool.init: spawning thread {}", .{i});
            thread.* = try std.Thread.spawn(.{}, workerMain, .{ pool, i });
            // Small delay to let thread initialize
            std.Thread.sleep(10 * std.time.ns_per_ms);
        }

        std.log.info("ThreadPool.init: complete", .{});
        return pool;
    }

    pub fn deinit(self: *ThreadPool, allocator: std.mem.Allocator) void {
        std.log.info("ThreadPool.deinit: setting shutdown flag", .{});
        // Set shutdown flag
        self.shutdown.store(true, .seq_cst);

        std.log.info("ThreadPool.deinit: waiting for {} threads to finish", .{self.threads.len});
        // Wait for all threads to finish
        for (self.threads, 0..) |thread, i| {
            std.log.info("ThreadPool.deinit: joining thread {}", .{i});
            thread.join();
        }

        std.log.info("ThreadPool.deinit: cleaning up queue", .{});
        // Clean up remaining connections in queue
        self.mutex.lock();
        for (self.queue.items) |fds| {
            std.posix.close(fds.client);
            std.posix.close(fds.upstream);
        }
        self.queue.deinit(self.allocator);
        self.mutex.unlock();

        std.log.info("ThreadPool.deinit: freeing thread memory", .{});
        self.allocator.free(self.threads);
        std.log.info("ThreadPool.deinit: destroying pool", .{});
        allocator.destroy(self);
        std.log.info("ThreadPool.deinit: complete", .{});
    }

    pub fn submit(self: *ThreadPool, fds: ConnectionFds) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.shutdown.load(.seq_cst)) {
            // Pool is shutting down, reject new work
            std.posix.close(fds.client);
            std.posix.close(fds.upstream);
            return error.ShuttingDown;
        }

        try self.queue.append(self.allocator, fds);
    }

    fn workerMain(pool: *ThreadPool, thread_id: usize) void {
        std.log.info("Worker thread {}: initializing GPA", .{thread_id});
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();

        std.log.info("Worker thread {}: started, entering main loop", .{thread_id});

        var iterations: usize = 0;
        while (true) {
            iterations += 1;

            // Check shutdown first
            const is_shutdown = pool.shutdown.load(.seq_cst);
            if (iterations % 1000 == 0) {
                std.log.info("Worker thread {}: iteration {}, shutdown={}", .{ thread_id, iterations, is_shutdown });
            }
            if (is_shutdown) {
                std.log.info("Worker thread {}: shutdown flag detected, breaking", .{thread_id});
                break;
            }

            // Try to get work (non-blocking)
            pool.mutex.lock();
            const maybe_fds = if (pool.queue.items.len > 0)
                pool.queue.orderedRemove(0)
            else
                null;
            pool.mutex.unlock();

            if (maybe_fds) |fds| {
                std.log.info("Worker thread {}: processing connection", .{thread_id});
                const current_config = pool.config.load(.acquire);

                const worker = @import("worker.zig");
                worker.handleConnection(
                    gpa.allocator(),
                    fds.client,
                    fds.upstream,
                    current_config,
                ) catch |err| {
                    std.log.err("Thread {}: connection error: {}", .{ thread_id, err });
                };
            } else {
                // No work available, sleep briefly to avoid spinning
                std.Thread.sleep(1 * std.time.ns_per_ms);
            }
        }

        std.log.info("Worker thread {}: exited main loop, shutting down", .{thread_id});
    }
};
