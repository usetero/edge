//! Unlimited response entities backed by private unlinked OS files, never heap growth.
const std = @import("std");
const HeadScanner = @import("HeadScanner.zig");
const ResponseHead = @import("ResponseHead.zig");
const ResponseIngress = @import("ResponseIngress.zig");
const ResponseWire = @import("ResponseWire.zig");
const BodyFramer = @import("BodyFramer.zig");
const Response = @import("Response.zig");
const Processing = @import("Processing.zig");
const PolicyStore = @import("PolicyStore.zig");
const Prometheus = @import("Prometheus.zig");
const encoding = @import("../pipeline/encoding.zig");
const Field = @import("http_field.zig").Field;

pub const Complete = struct { file: std.Io.File, length: u64, head: u32, tail: u32 };
pub const Filter = struct {
    store: *PolicyStore,
    workspace: *Processing.Workspace,
    input_cap: usize,
    output_cap: usize,
    deadline: std.Io.Timestamp,
    stopped: *const std.atomic.Value(bool),
};

/// A successful return transfers the sole file owner. Unlink immediately so
/// crashes cannot accumulate scratch telemetry or expose it through a pathname.
pub fn temporary(io: std.Io) !std.Io.File {
    var nonce: [16]u8 = undefined;
    io.random(&nonce);
    var path_buffer: [80]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buffer, "/tmp/tero-edge-{x}.tmp", .{nonce});
    const file = try std.Io.Dir.cwd().createFile(io, path, .{
        .read = true,
        .exclusive = true,
        .permissions = .fromMode(0o600),
    });
    errdefer file.close(io);
    try std.Io.Dir.cwd().deleteFile(io, path);
    return file;
}

/// Receives one complete final response before publishing headers. The caller's
/// socket watchdog bounds network waits. Disk exhaustion fails without a prefix.
pub fn receive(io: std.Io, input: *std.Io.Reader, buffers: Response.Buffers, version: std.http.Version, filter: ?Filter) !Complete {
    var head_bytes: [16384]u8 = undefined;
    var fields: [64]Field = undefined;
    var head: ResponseHead = undefined;
    var informational: usize = 0;
    var total_head_bytes: usize = 0;
    while (true) {
        var scanner: HeadScanner = try .init(head_bytes.len);
        var used: usize = 0;
        while (true) {
            const chunk = try input.peekGreedy(1);
            const scanned = try scanner.feed(chunk);
            @memcpy(head_bytes[used..][0..scanned.consumed], chunk[0..scanned.consumed]);
            input.toss(scanned.consumed);
            used += scanned.consumed;
            if (scanned.head_len != null) break;
        }
        total_head_bytes += used;
        if (total_head_bytes > 65536) return error.HeadersTooLarge;
        head = try .parse(head_bytes[0..used], &fields, .ordinary, .{});
        if (head.status >= 200) break;
        informational += 1;
        if (informational > 8) return error.TooManyInformationalResponses;
        if (head.status == 101) return error.UnsupportedUpgrade;
    }
    var line: [1024]u8 = undefined;
    var trailer_bytes: [4096]u8 = undefined;
    var trailer_fields: [16]Field = undefined;
    var framer: ?BodyFramer = if (head.framing == .close_delimited) null else try .init(switch (head.framing) {
        .none => .none,
        .content_length => |length| .{ .content_length = length },
        .chunked => .chunked,
        .close_delimited => unreachable,
    }, .{ .line = &line, .trailers = &trailer_bytes, .fields = &trailer_fields }, .{ .body_bytes = std.math.maxInt(u64), .metadata_bytes = std.math.maxInt(u32) });
    var file = try temporary(io);
    errdefer file.close(io);
    var offset: u64 = 0;
    var body: [16384]u8 = undefined;
    while (true) {
        if (framer) |*framing| if (framing.state == .done) break;
        const chunk = input.peekGreedy(1) catch |err| {
            if (err != error.EndOfStream) return err;
            if (framer) |*framing| try framing.finish();
            break;
        };
        const consumed, const written = if (framer) |*framing| blk: {
            const result = try framing.feed(chunk, &body);
            break :blk .{ result.consumed, result.written };
        } else blk: {
            const count = @min(chunk.len, body.len);
            @memcpy(body[0..count], chunk[0..count]);
            break :blk .{ count, count };
        };
        if (head.status == 205 and written != 0) return error.ForbiddenBody;
        try file.writePositionalAll(io, body[0..written], offset);
        offset = try std.math.add(u64, offset, written);
        input.toss(consumed);
    }
    var changed = false;
    if (filter) |options| {
        if (head.status == 200) {
            var content_type: []const u8 = "";
            var codec: []const u8 = "";
            var partial = false;
            for (fields[0..head.header_count]) |field| {
                const name = field.name.slice(&head_bytes);
                const value = field.value.slice(&head_bytes);
                if (std.ascii.eqlIgnoreCase(name, "content-type")) content_type = value;
                if (std.ascii.eqlIgnoreCase(name, "content-encoding")) codec = value;
                if (std.ascii.eqlIgnoreCase(name, "content-range")) partial = true;
            }
            if (!partial and (std.mem.startsWith(u8, content_type, "text/plain") or
                std.mem.startsWith(u8, content_type, "application/openmetrics-text")))
            {
                if (encoding.ContentEncoding.fromHeader(codec)) |selected| {
                    if (filterFile(io, file, selected, options) catch null) |candidate| {
                        file.close(io);
                        file = candidate.file;
                        offset = candidate.length;
                        changed = true;
                    }
                }
            }
        }
    }
    const message: ResponseIngress.Message = .{
        .changed = changed,
        .head = .{ .bytes = head_bytes[0..head.head_len], .fields = fields[0..head.header_count], .metadata = head },
        .body = "",
        .external_body_len = offset,
        .trailers = if (framer) |*framing| framing.trailers() else .{ .bytes = "", .fields = &.{} },
        .reusable = false,
    };
    const lengths = try ResponseWire.prepareFile(message, buffers, .{ .version = version, .keep_alive = false });
    return .{ .file = file, .length = offset, .head = lengths.head, .tail = lengths.tail };
}

fn filterFile(io: std.Io, original: std.Io.File, codec: encoding.ContentEncoding, options: Filter) !?Complete {
    const candidate = try temporary(io);
    var retained = false;
    defer if (!retained) candidate.close(io);
    var read_buffer: [16384]u8 = undefined;
    var write_buffer: [16384]u8 = undefined;
    var reader = original.reader(io, &read_buffer);
    var output = candidate.writer(io, &write_buffer);
    var decoder: encoding.Decoder = .init(codec, &reader.interface, options.workspace.decoder, options.workspace.limits.zstd_window_bytes);
    var encoder: encoding.Encoder = try .init(codec, &output.interface, options.workspace.encoder);
    defer encoder.deinit();
    var state: Prometheus.State = .{
        .store = options.store,
        .scratch = &options.workspace.scratch,
        .io = io,
    };
    const line = options.workspace.record;
    var used: usize = 0;
    var oversized = false;
    var input_bytes: u64 = 0;
    var chunk: [16384]u8 = undefined;
    while (true) {
        if (options.stopped.load(.acquire) or std.Io.Timestamp.now(io, .awake).nanoseconds >=
            options.deadline.nanoseconds) return error.Timeout;
        const count = try decoder.reader().readSliceShort(&chunk);
        if (count == 0) break;
        input_bytes = try std.math.add(u64, input_bytes, count);
        if (options.input_cap != 0 and input_bytes > options.input_cap) return error.InputTooLarge;
        for (chunk[0..count]) |byte| {
            if (byte == '\n') {
                if (oversized) {
                    try encoder.writer().writeAll("\n");
                } else if (try state.onRecord(line[0..used]) != .drop) {
                    try encoder.writer().writeAll(line[0..used]);
                    try encoder.writer().writeAll("\n");
                }
                used = 0;
                oversized = false;
            } else if (oversized) {
                try encoder.writer().writeByte(byte);
            } else if (used == line.len) {
                state.clearMetadata();
                state.counts.skipped += 1;
                try encoder.writer().writeAll(line);
                try encoder.writer().writeByte(byte);
                used = 0;
                oversized = true;
            } else {
                line[used] = byte;
                used += 1;
            }
        }
        if (options.output_cap != 0 and output.logicalPos() > options.output_cap) return error.OutputTooLarge;
    }
    if (!oversized and used > 0 and try state.onRecord(line[0..used]) != .drop)
        try encoder.writer().writeAll(line[0..used]);
    try encoder.finish();
    try output.interface.flush();
    const length = try candidate.length(io);
    if (options.output_cap != 0 and length > options.output_cap) return error.OutputTooLarge;
    if (state.counts.dropped == 0) return null;
    retained = true;
    return .{ .file = candidate, .length = length, .head = 0, .tail = 0 };
}

test "v2 private response file is positional and remains readable after unlink" {
    const file = try temporary(std.testing.io);
    defer file.close(std.testing.io);
    try file.writePositionalAll(std.testing.io, "abc", 0);
    var bytes: [3]u8 = undefined;
    try std.testing.expectEqual(3, try file.readPositionalAll(std.testing.io, &bytes, 0));
    try std.testing.expectEqualStrings("abc", &bytes);
}
