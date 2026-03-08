const std = @import("std");
const framer_mod = @import("../framer.zig");
const watch_mod = @import("../watch.zig");
const common = @import("common.zig");

const fixed_slot_count: usize = 256;

const Op = struct {
    event: watch_mod.Event,
    buf_off: usize,
    submitted_len: usize,
    result: i32 = 0,
};

pub const Scheduler = struct {
    allocator: std.mem.Allocator,
    ring: std.os.linux.IoUring,
    ops: std.ArrayList(Op) = .{},
    scratch: std.ArrayList(u8) = .{},
    cqes: std.ArrayList(std.os.linux.io_uring_cqe) = .{},
    fixed_iovecs: std.ArrayList(std.posix.iovec) = .{},
    fixed_fds: std.ArrayList(std.posix.fd_t) = .{},
    fixed_buffers_registered: bool = false,
    fixed_files_registered: bool = false,
    fixed_enabled: bool = true,
    fixed_buf_size: usize = 0,

    pub fn init(allocator: std.mem.Allocator) !Scheduler {
        return .{
            .allocator = allocator,
            .ring = try std.os.linux.IoUring.init(256, 0),
        };
    }

    pub fn deinit(self: *Scheduler) void {
        if (self.fixed_buffers_registered) {
            self.ring.unregister_buffers() catch {};
            self.fixed_buffers_registered = false;
        }
        if (self.fixed_files_registered) {
            self.ring.unregister_files() catch {};
            self.fixed_files_registered = false;
        }
        self.ring.deinit();
        self.ops.deinit(self.allocator);
        self.scratch.deinit(self.allocator);
        self.cqes.deinit(self.allocator);
        self.fixed_iovecs.deinit(self.allocator);
        self.fixed_fds.deinit(self.allocator);
    }

    pub fn processBatch(
        self: *Scheduler,
        framer: *framer_mod.LineFramer,
        writer: *std.Io.Writer,
        events: []const watch_mod.Event,
        filter_ctx: *anyopaque,
        filter_fn: *const framer_mod.LineFramer.LineFilterFn,
    ) !usize {
        if (events.len == 0) return 0;

        self.ops.clearRetainingCapacity();
        self.cqes.clearRetainingCapacity();

        try self.ops.ensureTotalCapacity(self.allocator, events.len);
        try self.cqes.ensureTotalCapacity(self.allocator, events.len);
        try self.prepareFixedResources(framer.read_buf.len);
        const use_fixed = self.fixed_enabled and self.fixed_buffers_registered and self.fixed_files_registered;
        if (!use_fixed) self.scratch.clearRetainingCapacity();

        var op_idx: usize = 0;
        for (events) |evt| {
            if (evt.end_offset <= evt.start_offset) continue;
            if (op_idx >= fixed_slot_count) break;

            const max_bytes: u64 = evt.end_offset - evt.start_offset;
            const to_read: usize = @intCast(@min(max_bytes, framer.read_buf.len));
            if (to_read == 0) continue;

            const user_data: u64 = @intCast(self.ops.items.len + 1);
            var buf_off: usize = 0;
            if (use_fixed) {
                buf_off = op_idx * self.fixed_buf_size;
                self.fixed_iovecs.items[op_idx].len = to_read;
                self.fixed_fds.items[op_idx] = evt.file.handle;
                const sqe = self.ring.read_fixed(
                    user_data,
                    @intCast(op_idx),
                    &self.fixed_iovecs.items[op_idx],
                    evt.start_offset,
                    @intCast(op_idx),
                ) catch {
                    self.fixed_enabled = false;
                    return common.processBatchScalar(framer, writer, events, filter_ctx, filter_fn);
                };
                sqe.flags |= std.os.linux.IOSQE_FIXED_FILE;
            } else {
                const off = self.scratch.items.len;
                try self.scratch.resize(self.allocator, off + to_read);
                const slot = self.scratch.items[off .. off + to_read];
                _ = self.ring.read(user_data, evt.file.handle, .{ .buffer = slot }, evt.start_offset) catch {
                    return common.processBatchScalar(framer, writer, events, filter_ctx, filter_fn);
                };
                buf_off = off;
            }

            self.ops.appendAssumeCapacity(.{
                .event = evt,
                .buf_off = buf_off,
                .submitted_len = to_read,
            });
            op_idx += 1;
        }

        if (self.ops.items.len == 0) return 0;
        if (use_fixed) {
            self.ring.register_files_update(0, self.fixed_fds.items[0..self.ops.items.len]) catch {
                self.fixed_enabled = false;
                return common.processBatchScalar(framer, writer, events, filter_ctx, filter_fn);
            };
        }

        _ = self.ring.submit_and_wait(@intCast(self.ops.items.len)) catch {
            return common.processBatchScalar(framer, writer, events, filter_ctx, filter_fn);
        };

        try self.cqes.resize(self.allocator, self.ops.items.len);
        var got: usize = 0;
        while (got < self.ops.items.len) {
            const n = try self.ring.copy_cqes(
                self.cqes.items[got..self.ops.items.len],
                @intCast(self.ops.items.len - got),
            );
            got += n;
        }

        for (self.cqes.items[0..got]) |cqe| {
            const idx: usize = @intCast(cqe.user_data - 1);
            if (idx < self.ops.items.len) {
                self.ops.items[idx].result = cqe.res;
            }
        }

        var processed: usize = 0;
        for (self.ops.items) |op| {
            if (op.result < 0) {
                try framer.readRange(
                    op.event.file,
                    op.event.start_offset,
                    op.event.end_offset,
                    writer,
                    filter_ctx,
                    filter_fn,
                );
                processed += 1;
                continue;
            }
            if (op.result == 0) continue;

            const n: usize = @intCast(@min(@as(usize, @intCast(op.result)), op.submitted_len));
            const buf = self.scratch.items[op.buf_off .. op.buf_off + n];
            try framer.ingestChunk(buf, writer, filter_ctx, filter_fn);

            const next_off: u64 = op.event.start_offset + n;
            if (next_off < op.event.end_offset) {
                try common.readTailScalar(
                    framer,
                    op.event.file,
                    next_off,
                    op.event.end_offset,
                    writer,
                    filter_ctx,
                    filter_fn,
                );
            }
            processed += 1;
        }

        return processed;
    }

    fn prepareFixedResources(self: *Scheduler, read_buf_size: usize) !void {
        if (!self.fixed_enabled) return;

        if (!self.fixed_files_registered) {
            self.ring.register_files_sparse(fixed_slot_count) catch {
                self.fixed_enabled = false;
                return;
            };
            self.fixed_files_registered = true;
            try self.fixed_fds.resize(self.allocator, fixed_slot_count);
            for (self.fixed_fds.items) |*fd| fd.* = -1;
        }

        if (self.fixed_buffers_registered and self.fixed_buf_size == read_buf_size) return;

        if (self.fixed_buffers_registered) {
            self.ring.unregister_buffers() catch {};
            self.fixed_buffers_registered = false;
        }
        self.fixed_buf_size = read_buf_size;
        try self.scratch.resize(self.allocator, fixed_slot_count * read_buf_size);
        try self.fixed_iovecs.resize(self.allocator, fixed_slot_count);
        var i: usize = 0;
        while (i < fixed_slot_count) : (i += 1) {
            const off = i * read_buf_size;
            self.fixed_iovecs.items[i] = .{
                .base = self.scratch.items[off .. off + read_buf_size].ptr,
                .len = read_buf_size,
            };
        }
        self.ring.register_buffers(self.fixed_iovecs.items) catch {
            self.fixed_enabled = false;
            return;
        };
        self.fixed_buffers_registered = true;
    }
};
