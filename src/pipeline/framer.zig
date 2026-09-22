//! Record framing for the streaming pipeline (PLAN.md §6.3).
//!
//! A framer slices a byte stream into records, hands each record to a sink,
//! and re-emits wire syntax for the records the sink keeps. Sinks are
//! comptime duck-typed (`anytype`) with one required method:
//!
//!     fn onRecord(self: *S, bytes: []const u8) !Decision
//!
//! so record dispatch costs nothing at runtime and no vtable exists. The
//! framer owns ALL wire syntax (newlines, array brackets and commas, protobuf
//! tag/length prefixes): a keep-everything sink reproduces a semantically
//! identical stream.
//!
//! Failure semantics (PLAN.md §6.5): records larger than the fixed scratch
//! buffer are copied through verbatim without evaluation (fail-open);
//! structurally malformed input flips the framer into copy-through mode for
//! the remainder of the stream (desync). Bytes are never dropped by the
//! framer itself — only a sink's explicit `.drop` removes data.
const std = @import("std");

pub const frame_ndjson = @import("frame_ndjson.zig");
pub const frame_json_array = @import("frame_json_array.zig");
pub const frame_protobuf = @import("frame_protobuf.zig");

pub const WireFormat = enum {
    /// Newline-delimited records (NDJSON, plain log lines).
    ndjson,
    /// Top-level JSON array; each element is a record (Datadog logs bodies).
    json_array,
    /// Length-delimited top-level protobuf fields; each LEN payload is a
    /// record (OTLP ResourceLogs / ResourceSpans / ResourceMetrics).
    otlp_protobuf,
    /// Line-oriented Prometheus text exposition; framing is identical to
    /// ndjson, the sink supplies the metric semantics.
    prom_text,
};

/// Sink verdict for one record. `replace` bytes are sink-owned and must stay
/// valid until the next onRecord call (the transform scratch in practice).
pub const Decision = union(enum) {
    keep,
    drop,
    replace: []const u8,
};

pub const Stats = struct {
    records: u64 = 0,
    kept: u64 = 0,
    dropped: u64 = 0,
    replaced: u64 = 0,
    /// Oversized or unparseable records copied through without evaluation.
    failed_open: u64 = 0,
    /// Structural desync: the rest of the stream was copied verbatim.
    desynced: bool = false,
};

pub const Framer = union(WireFormat) {
    ndjson: frame_ndjson.NdjsonFramer,
    json_array: frame_json_array.JsonArrayFramer,
    otlp_protobuf: frame_protobuf.ProtobufFramer,
    prom_text: frame_ndjson.NdjsonFramer,

    /// `scratch` bounds the largest record that can be evaluated; larger
    /// records fail open. The slice is borrowed for the framer's lifetime
    /// (the connection's record-scratch slab region in production).
    pub fn init(format: WireFormat, scratch: []u8) Framer {
        return switch (format) {
            .ndjson => .{ .ndjson = .init(scratch) },
            .json_array => .{ .json_array = .init(scratch) },
            .otlp_protobuf => .{ .otlp_protobuf = .init(scratch) },
            .prom_text => .{ .prom_text = .init(scratch) },
        };
    }

    pub fn ingest(self: *Framer, chunk: []const u8, out: *std.Io.Writer, sink: anytype) !void {
        switch (self.*) {
            inline else => |*f| try f.ingest(chunk, out, sink),
        }
    }

    /// Flush trailing state at end of stream. Must be called exactly once.
    pub fn finish(self: *Framer, out: *std.Io.Writer, sink: anytype) !void {
        switch (self.*) {
            inline else => |*f| try f.finish(out, sink),
        }
    }

    pub fn stats(self: *const Framer) Stats {
        return switch (self.*) {
            inline else => |*f| f.stats,
        };
    }
};

test {
    _ = frame_ndjson;
    _ = frame_json_array;
    _ = frame_protobuf;
}
