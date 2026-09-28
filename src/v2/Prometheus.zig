//! Sample filtering over borrowed lines; metadata and oversized lines stay intact.
const std = @import("std");
const policy = @import("policy_zig");
const PolicyStore = @import("PolicyStore.zig");
const Scratch = @import("Scratch.zig");
const parser = @import("../signals/prometheus/line_parser.zig");
const accessor = @import("../signals/prometheus/field_accessor.zig");
const Decision = @import("../pipeline/framer.zig").Decision;

pub const Counts = struct { evaluated: u64 = 0, dropped: u64 = 0, skipped: u64 = 0 };

pub const State = struct {
    store: *PolicyStore,
    scratch: *Scratch,
    /// Non-null for file streaming: pin only during evaluation, release before IO.
    io: ?std.Io = null,
    counts: Counts = .{},
    name: [256]u8 = undefined,
    name_len: usize = 0,
    description: [4096]u8 = undefined,
    description_len: usize = 0,
    metric_type: ?[]const u8 = null,

    pub fn onRecord(self: *State, bytes: []const u8) !Decision {
        if (self.io) |io| {
            var guard = switch (self.store.tryRead(io)) {
                .ready => |guard| guard,
                else => {
                    self.counts.skipped += 1;
                    return .keep;
                },
            };
            defer guard.deinit(io);
            return self.evaluate(bytes);
        }
        return self.evaluate(bytes);
    }

    pub fn clearMetadata(self: *State) void {
        self.name_len = 0;
        self.description_len = 0;
        self.metric_type = null;
    }

    fn setName(self: *State, name: []const u8) bool {
        if (name.len > self.name.len) {
            self.clearMetadata();
            return false;
        }
        if (!std.mem.eql(u8, self.name[0..self.name_len], name)) self.clearMetadata();
        @memcpy(self.name[0..name.len], name);
        self.name_len = name.len;
        return true;
    }

    fn evaluate(self: *State, line: []const u8) !Decision {
        const parsed = parser.parseLine(line);
        switch (parsed) {
            .help => |value| {
                if (self.setName(value.metric_name)) {
                    if (value.description.len <= self.description.len) {
                        @memcpy(self.description[0..value.description.len], value.description);
                        self.description_len = value.description.len;
                    } else self.description_len = 0;
                }
            },
            .type_info => |value| {
                if (self.setName(value.metric_name)) self.metric_type = @tagName(value.metric_type);
            },
            .sample => |sample| {
                self.scratch.reset();
                const same_family = familyMatches(self.name[0..self.name_len], sample.metric_name);
                var context: accessor.PrometheusFieldContext = .{
                    .parsed = parsed,
                    .line_buffer = line,
                    .description = if (same_family and self.description_len > 0)
                        self.description[0..self.description_len]
                    else
                        null,
                    .metric_type = if (same_family) self.metric_type else null,
                    .labels_cache = try accessor.buildLabelsCache(self.scratch.allocator(), parsed),
                };
                var matches: [policy.max_matches_per_scan][]const u8 = undefined;
                const engine = policy.PolicyEngine.init(self.store.registry.bus, &self.store.registry);
                const result = engine.evaluate(.metric, &accessor.metric_accessor, &context, &matches, .{
                    .scratch = self.scratch.allocator(),
                    .io = self.store.registry.bus.io,
                });
                self.counts.evaluated += 1;
                if (self.scratch.denied) return error.OutOfMemory;
                if (!result.decision.shouldContinue()) {
                    self.counts.dropped += 1;
                    return .drop;
                }
            },
            else => {},
        }
        return .keep;
    }
};

/// The caller holds the snapshot guard. Retain comments and HELP/TYPE verbatim,
/// including metadata for families whose samples are all removed.
pub fn filter(
    store: *PolicyStore,
    scratch: *Scratch,
    original: []const u8,
    writer: *std.Io.Writer,
    line_limit: usize,
) !Counts {
    var state: State = .{ .store = store, .scratch = scratch };
    var offset: usize = 0;
    while (offset < original.len) {
        const end = std.mem.indexOfScalarPos(u8, original, offset, '\n') orelse original.len;
        const next = if (end < original.len) end + 1 else end;
        const line = original[offset..end];
        const wire = original[offset..next];
        offset = next;
        if (line.len > line_limit) {
            state.counts.skipped += 1;
            state.clearMetadata();
        } else if (try state.onRecord(line) == .drop) continue;
        try writer.writeAll(wire);
    }
    return state.counts;
}

fn familyMatches(base: []const u8, name: []const u8) bool {
    if (base.len == 0 or !std.mem.startsWith(u8, name, base)) return false;
    const suffix = name[base.len..];
    return suffix.len == 0 or std.mem.eql(u8, suffix, "_bucket") or
        std.mem.eql(u8, suffix, "_sum") or std.mem.eql(u8, suffix, "_count");
}

test "v2 prometheus family metadata does not leak into unrelated name prefixes" {
    try std.testing.expect(familyMatches("http", "http_bucket"));
    try std.testing.expect(!familyMatches("http", "http_other"));
    try std.testing.expect(!familyMatches("", "http"));
}
