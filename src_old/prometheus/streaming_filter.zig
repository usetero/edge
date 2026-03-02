//! Streaming Prometheus Filter
//!
//! Processes Prometheus exposition format data line-by-line in a streaming fashion.
//! Designed for bounded memory usage regardless of input size.
//!
//! This module provides:
//! - Line-by-line streaming with configurable buffer sizes
//! - Data volume limiting (max bytes per scrape)
//! - Statistics tracking for observability
//! - Policy-based metric filtering (via PolicyStreamingFilter)
//!

const std = @import("std");
const proto = @import("proto");
const line_parser = @import("line_parser.zig");
const field_accessor = @import("field_accessor.zig");
const policy = @import("policy_zig");
const o11y = @import("o11y");

const AttributePath = proto.policy.AttributePath;

const PolicyEngine = policy.PolicyEngine;
const PolicyRegistry = policy.Registry;
const EventBus = o11y.EventBus;
const PrometheusFieldContext = field_accessor.PrometheusFieldContext;
const prometheusFieldAccessor = field_accessor.prometheusFieldAccessor;

/// Result of processing a chunk of data
pub const ProcessResult = struct {
    /// Number of bytes consumed from the input
    consumed: usize,
    /// Whether the filter should stop processing (data limit reached)
    should_stop: bool,
};

/// Statistics from the filtering operation
pub const FilterStats = struct {
    /// Total bytes read from upstream
    bytes_processed: usize,
    /// Total bytes forwarded to client
    bytes_forwarded: usize,
    /// Number of complete lines processed
    lines_processed: usize,
    /// Number of lines dropped by policy (Phase 4)
    lines_dropped: usize,
    /// Number of lines kept/forwarded
    lines_kept: usize,
    /// Whether processing was truncated due to data limit
    scrape_truncated: bool,
};

/// Streaming filter for Prometheus exposition format.
/// Processes data line-by-line, forwarding to an output writer.
/// Internal implementation - use PolicyStreamingFilter for public API.
const StreamingPrometheusFilter = struct {
    // Configuration
    max_input_bytes: usize,
    max_output_bytes: usize,

    // Buffers (caller-provided)
    line_buffer: []u8,
    line_len: usize,

    // Metadata buffers for HELP/TYPE lines (Phase 4)
    metadata_buffer: []u8,

    // Statistics
    bytes_processed: usize,
    bytes_forwarded: usize,
    lines_processed: usize,
    lines_dropped: usize,
    lines_kept: usize,
    scrape_truncated: bool,
    truncation_reason: TruncationReason,

    // State
    stopped: bool,

    pub const TruncationReason = enum {
        none,
        input_limit,
        output_limit,
    };

    pub const Config = struct {
        line_buffer: []u8,
        metadata_buffer: []u8,
        max_input_bytes: usize,
        max_output_bytes: usize = std.math.maxInt(usize),
    };

    pub fn init(config: Config) StreamingPrometheusFilter {
        return .{
            .max_input_bytes = config.max_input_bytes,
            .max_output_bytes = config.max_output_bytes,
            .line_buffer = config.line_buffer,
            .line_len = 0,
            .metadata_buffer = config.metadata_buffer,
            .bytes_processed = 0,
            .bytes_forwarded = 0,
            .lines_processed = 0,
            .lines_dropped = 0,
            .lines_kept = 0,
            .scrape_truncated = false,
            .truncation_reason = .none,
            .stopped = false,
        };
    }

    /// Check if the filter should stop processing
    pub fn shouldStop(self: *const StreamingPrometheusFilter) bool {
        return self.stopped;
    }

    /// Process a chunk of input data, writing filtered output to the writer.
    /// Returns the number of bytes consumed and whether to stop.
    pub fn processChunk(
        self: *StreamingPrometheusFilter,
        chunk: []const u8,
        writer: *std.Io.Writer,
    ) !ProcessResult {
        // Check input limit before processing
        const remaining_input = self.max_input_bytes -| self.bytes_processed;
        if (remaining_input == 0) {
            self.scrape_truncated = true;
            self.truncation_reason = .input_limit;
            self.stopped = true;
            return .{ .consumed = 0, .should_stop = true };
        }

        // Check output limit
        if (self.bytes_forwarded >= self.max_output_bytes) {
            self.scrape_truncated = true;
            self.truncation_reason = .output_limit;
            self.stopped = true;
            return .{ .consumed = 0, .should_stop = true };
        }

        // Only process up to remaining input budget
        const to_process = @min(chunk.len, remaining_input);
        var consumed: usize = 0;

        for (chunk[0..to_process]) |byte| {
            consumed += 1;
            self.bytes_processed += 1;

            if (byte == '\n') {
                // Process the complete line
                try self.processLine(writer);
                self.line_len = 0;

                // Check output limit after each line
                if (self.bytes_forwarded >= self.max_output_bytes) {
                    self.scrape_truncated = true;
                    self.truncation_reason = .output_limit;
                    self.stopped = true;
                    break;
                }
            } else if (self.line_len < self.line_buffer.len) {
                // Accumulate byte into line buffer
                self.line_buffer[self.line_len] = byte;
                self.line_len += 1;
            }
            // If line exceeds buffer, we truncate (bytes are dropped until newline)
        }

        // Check if we've hit the input limit after processing
        if (self.bytes_processed >= self.max_input_bytes) {
            self.scrape_truncated = true;
            self.truncation_reason = .input_limit;
            self.stopped = true;
        }

        return .{ .consumed = consumed, .should_stop = self.stopped };
    }

    /// Process a complete line (without the trailing newline)
    fn processLine(self: *StreamingPrometheusFilter, writer: *std.Io.Writer) !void {
        const line = self.line_buffer[0..self.line_len];
        self.lines_processed += 1;

        // Phase 2: Passthrough mode - forward all lines
        // Phase 4 will add policy evaluation here
        try self.writeLine(line, writer);
        self.lines_kept += 1;
    }

    /// Write a line to the output (with newline)
    fn writeLine(self: *StreamingPrometheusFilter, line: []const u8, writer: *std.Io.Writer) !void {
        try writer.writeAll(line);
        try writer.writeAll("\n");
        self.bytes_forwarded += line.len + 1;
    }

    /// Finish processing - flush any remaining partial line and return stats.
    pub fn finish(self: *StreamingPrometheusFilter, writer: *std.Io.Writer) !FilterStats {
        // Only write remaining partial line if we didn't truncate.
        // If truncated, discard the partial line to avoid broken metric output.
        if (self.line_len > 0 and !self.scrape_truncated) {
            try self.processLine(writer);
            self.line_len = 0;
        }

        // Flush the writer
        try writer.flush();

        return self.getStats();
    }

    /// Get current statistics
    pub fn getStats(self: *const StreamingPrometheusFilter) FilterStats {
        return .{
            .bytes_processed = self.bytes_processed,
            .bytes_forwarded = self.bytes_forwarded,
            .lines_processed = self.lines_processed,
            .lines_dropped = self.lines_dropped,
            .lines_kept = self.lines_kept,
            .scrape_truncated = self.scrape_truncated,
        };
    }
};

// =============================================================================
// Policy-based Streaming Filter
// =============================================================================

/// Maximum number of policies that can match a single metric
const MAX_POLICY_MATCHES = 16;

/// Streaming filter with policy-based metric filtering.
/// Evaluates each metric sample against the policy engine and only forwards
/// metrics that pass the policy evaluation.
///
/// HELP and TYPE metadata lines are tracked and forwarded only when at least
/// one sample for that metric is kept.
pub const PolicyStreamingFilter = struct {
    // Base filter (handles streaming mechanics)
    base: StreamingPrometheusFilter,

    // Policy registry and event bus for creating engine on demand
    registry: *PolicyRegistry,
    bus: *EventBus,

    // Allocator for labels cache
    allocator: std.mem.Allocator,

    // Metadata tracking: stores HELP/TYPE lines keyed by metric name
    // We use a simple approach: store the most recent HELP and TYPE for each metric
    // When we see a sample that passes policy, we output its metadata first
    current_metric_name: []const u8,
    current_help_line: []const u8,
    current_type_line: []const u8,
    // Parsed metadata values for policy evaluation
    current_description: []const u8,
    current_type_str: []const u8,
    metadata_written: bool,

    // Policy ID buffer for evaluate()
    policy_id_buf: [MAX_POLICY_MATCHES][]const u8,

    pub const Config = struct {
        line_buffer: []u8,
        metadata_buffer: []u8,
        max_input_bytes: usize,
        max_output_bytes: usize = std.math.maxInt(usize),
        registry: *PolicyRegistry,
        bus: *EventBus,
        allocator: std.mem.Allocator,
    };

    pub fn init(config: Config) PolicyStreamingFilter {
        return .{
            .base = StreamingPrometheusFilter.init(.{
                .line_buffer = config.line_buffer,
                .metadata_buffer = config.metadata_buffer,
                .max_input_bytes = config.max_input_bytes,
                .max_output_bytes = config.max_output_bytes,
            }),
            .registry = config.registry,
            .bus = config.bus,
            .allocator = config.allocator,
            .current_metric_name = "",
            .current_help_line = "",
            .current_type_line = "",
            .current_description = "",
            .current_type_str = "",
            .metadata_written = false,
            .policy_id_buf = undefined,
        };
    }

    /// Process a chunk of input data with policy filtering.
    pub fn processChunk(
        self: *PolicyStreamingFilter,
        chunk: []const u8,
        writer: *std.Io.Writer,
    ) !ProcessResult {
        // Check input limit before processing
        const remaining_input = self.base.max_input_bytes -| self.base.bytes_processed;
        if (remaining_input == 0) {
            self.base.scrape_truncated = true;
            self.base.truncation_reason = .input_limit;
            self.base.stopped = true;
            return .{ .consumed = 0, .should_stop = true };
        }

        // Check output limit
        if (self.base.bytes_forwarded >= self.base.max_output_bytes) {
            self.base.scrape_truncated = true;
            self.base.truncation_reason = .output_limit;
            self.base.stopped = true;
            return .{ .consumed = 0, .should_stop = true };
        }

        // Only process up to remaining input budget
        const to_process = @min(chunk.len, remaining_input);
        var consumed: usize = 0;

        for (chunk[0..to_process]) |byte| {
            consumed += 1;
            self.base.bytes_processed += 1;

            if (byte == '\n') {
                // Process the complete line with policy evaluation
                try self.processLineWithPolicy(writer);
                self.base.line_len = 0;

                // Check output limit after each line
                if (self.base.bytes_forwarded >= self.base.max_output_bytes) {
                    self.base.scrape_truncated = true;
                    self.base.truncation_reason = .output_limit;
                    self.base.stopped = true;
                    break;
                }
            } else if (self.base.line_len < self.base.line_buffer.len) {
                self.base.line_buffer[self.base.line_len] = byte;
                self.base.line_len += 1;
            }
        }

        if (self.base.bytes_processed >= self.base.max_input_bytes) {
            self.base.scrape_truncated = true;
            self.base.truncation_reason = .input_limit;
            self.base.stopped = true;
        }

        return .{ .consumed = consumed, .should_stop = self.base.stopped };
    }

    /// Process a complete line with policy evaluation
    fn processLineWithPolicy(self: *PolicyStreamingFilter, writer: *std.Io.Writer) !void {
        const line = self.base.line_buffer[0..self.base.line_len];
        self.base.lines_processed += 1;

        const parsed = line_parser.parseLine(line);

        switch (parsed) {
            .empty => {
                // Forward empty lines
                try self.writeLine(line, writer);
                self.base.lines_kept += 1;
            },
            .comment => {
                // Forward comments (non HELP/TYPE)
                try self.writeLine(line, writer);
                self.base.lines_kept += 1;
            },
            .help => |h| {
                // Store HELP metadata for potential later output
                self.updateMetadata(h.metric_name, .{
                    .line = line,
                    .description = h.description,
                }, null);
            },
            .type_info => |t| {
                // Store TYPE metadata for potential later output
                self.updateMetadata(t.metric_name, null, .{
                    .line = line,
                    .type_str = @tagName(t.metric_type),
                });
            },
            .sample => |s| {
                // Evaluate sample against policy engine
                if (self.shouldKeepMetric(s, line)) {
                    // Output metadata if this is first sample for this metric
                    try self.maybeWriteMetadata(s.metric_name, writer);
                    // Output the sample
                    try self.writeLine(line, writer);
                    self.base.lines_kept += 1;
                } else {
                    self.base.lines_dropped += 1;
                }
            },
            .parse_error => {
                // Forward unparseable lines (be conservative)
                try self.writeLine(line, writer);
                self.base.lines_kept += 1;
            },
        }
    }

    // Metadata buffer layout:
    // [0..256): metric name
    // [256..640): HELP line (384 bytes)
    // [640..1024): TYPE line (384 bytes)
    // [1024..1280): description text (256 bytes)
    // [1280..1296): type string (16 bytes - e.g., "counter", "histogram")
    const METRIC_NAME_OFFSET: usize = 0;
    const METRIC_NAME_SIZE: usize = 256;
    const HELP_LINE_OFFSET: usize = 256;
    const HELP_LINE_SIZE: usize = 384;
    const TYPE_LINE_OFFSET: usize = 640;
    const TYPE_LINE_SIZE: usize = 384;
    const DESCRIPTION_OFFSET: usize = 1024;
    const DESCRIPTION_SIZE: usize = 256;
    const TYPE_STR_OFFSET: usize = 1280;
    const TYPE_STR_SIZE: usize = 16;

    const HelpMetadata = struct {
        line: []const u8,
        description: []const u8,
    };

    const TypeMetadata = struct {
        line: []const u8,
        type_str: []const u8,
    };

    /// Update stored metadata for a metric
    fn updateMetadata(self: *PolicyStreamingFilter, metric_name: []const u8, help: ?HelpMetadata, type_meta: ?TypeMetadata) void {
        // Check if this is a new metric (compare against stored name in buffer)
        if (!std.mem.eql(u8, self.current_metric_name, metric_name)) {
            // New metric - copy name to stable buffer and reset state
            const name_len = @min(metric_name.len, METRIC_NAME_SIZE);
            @memcpy(self.base.metadata_buffer[METRIC_NAME_OFFSET..][0..name_len], metric_name[0..name_len]);
            self.current_metric_name = self.base.metadata_buffer[METRIC_NAME_OFFSET..][0..name_len];
            self.current_help_line = "";
            self.current_type_line = "";
            self.current_description = "";
            self.current_type_str = "";
            self.metadata_written = false;
        }

        // Store HELP line and description in metadata buffer
        if (help) |h| {
            const line_len = @min(h.line.len, HELP_LINE_SIZE);
            @memcpy(self.base.metadata_buffer[HELP_LINE_OFFSET..][0..line_len], h.line[0..line_len]);
            self.current_help_line = self.base.metadata_buffer[HELP_LINE_OFFSET..][0..line_len];

            const desc_len = @min(h.description.len, DESCRIPTION_SIZE);
            @memcpy(self.base.metadata_buffer[DESCRIPTION_OFFSET..][0..desc_len], h.description[0..desc_len]);
            self.current_description = self.base.metadata_buffer[DESCRIPTION_OFFSET..][0..desc_len];
        }

        // Store TYPE line and type string in metadata buffer
        if (type_meta) |t| {
            const line_len = @min(t.line.len, TYPE_LINE_SIZE);
            @memcpy(self.base.metadata_buffer[TYPE_LINE_OFFSET..][0..line_len], t.line[0..line_len]);
            self.current_type_line = self.base.metadata_buffer[TYPE_LINE_OFFSET..][0..line_len];

            const type_len = @min(t.type_str.len, TYPE_STR_SIZE);
            @memcpy(self.base.metadata_buffer[TYPE_STR_OFFSET..][0..type_len], t.type_str[0..type_len]);
            self.current_type_str = self.base.metadata_buffer[TYPE_STR_OFFSET..][0..type_len];
        }
    }

    /// Write metadata lines if not already written for current metric
    fn maybeWriteMetadata(self: *PolicyStreamingFilter, metric_name: []const u8, writer: *std.Io.Writer) !void {
        // Only write metadata if it matches the current metric and hasn't been written
        // For histograms/summaries, sample names have suffixes like _bucket, _sum, _count
        // so we check if sample name starts with the metadata metric name
        const matches = self.current_metric_name.len > 0 and
            std.mem.startsWith(u8, metric_name, self.current_metric_name);

        if (matches and !self.metadata_written) {
            if (self.current_help_line.len > 0) {
                try self.writeLine(self.current_help_line, writer);
                self.base.lines_kept += 1;
            }
            if (self.current_type_line.len > 0) {
                try self.writeLine(self.current_type_line, writer);
                self.base.lines_kept += 1;
            }
            self.metadata_written = true;
        }
    }

    /// Sample type from ParsedLine union
    const Sample = std.meta.TagPayload(line_parser.ParsedLine, .sample);

    /// Evaluate whether to keep a metric sample based on policy
    fn shouldKeepMetric(self: *PolicyStreamingFilter, sample: Sample, line: []const u8) bool {
        // Build the field context with metadata from HELP/TYPE lines
        var ctx = PrometheusFieldContext{
            .parsed = .{ .sample = sample },
            .line_buffer = line,
            .labels_cache = null,
            .description = if (self.current_description.len > 0) self.current_description else null,
            .metric_type = if (self.current_type_str.len > 0) self.current_type_str else null,
        };

        // Build labels cache for pattern matching (if needed)
        const labels_cache = field_accessor.buildLabelsCache(self.allocator, .{ .sample = sample }) catch null;
        defer if (labels_cache) |lc| self.allocator.free(lc);
        ctx.labels_cache = labels_cache;

        // Create engine on demand (same pattern as other modules)
        const engine = PolicyEngine.init(self.bus, self.registry);

        // Evaluate against policy engine
        // Note: We pass null for mutator since Prometheus metrics are immutable in exposition format
        const result = engine.evaluate(
            .metric,
            @ptrCast(&ctx),
            prometheusFieldAccessor,
            null, // No mutation support for Prometheus
            &self.policy_id_buf,
        );

        // Continue means keep, drop means filter out
        return result.decision.shouldContinue();
    }

    /// Write a line to output
    fn writeLine(self: *PolicyStreamingFilter, line: []const u8, writer: *std.Io.Writer) !void {
        try writer.writeAll(line);
        try writer.writeAll("\n");
        self.base.bytes_forwarded += line.len + 1;
    }

    /// Finish processing and return stats
    pub fn finish(self: *PolicyStreamingFilter, writer: *std.Io.Writer) !FilterStats {
        // Only write remaining line if we didn't truncate.
        // If truncated, discard the partial line to avoid broken output.
        if (self.base.line_len > 0 and !self.base.scrape_truncated) {
            try self.processLineWithPolicy(writer);
            self.base.line_len = 0;
        }
        try writer.flush();
        return self.base.getStats();
    }

    /// Get current statistics
    pub fn getStats(self: *const PolicyStreamingFilter) FilterStats {
        return self.base.getStats();
    }
};

// =============================================================================
// FilteringWriter - std.Io.Writer wrapper for PolicyStreamingFilter
// =============================================================================

/// A writer that filters Prometheus metrics through PolicyStreamingFilter.
/// Implements std.Io.Writer interface so it can be used with reader.stream().
///
/// Usage with server's streaming pattern:
/// ```
/// var filtering_writer = FilteringWriter.init(filter, response_writer, &buffer);
/// const writer = filtering_writer.writer();
/// _ = try upstream_reader.stream(writer, .until_end);
/// const stats = try filtering_writer.finish();
/// ```
pub const FilteringWriter = struct {
    /// Embedded Writer interface - MUST be first field for @fieldParentPtr
    interface: std.Io.Writer,

    /// The filter that processes incoming data
    filter: *PolicyStreamingFilter,

    /// The downstream writer where filtered output goes
    inner: *std.Io.Writer,

    const vtable: std.Io.Writer.VTable = .{
        .drain = drain,
        .flush = flush,
    };

    pub const Config = struct {
        filter: *PolicyStreamingFilter,
        inner: *std.Io.Writer,
        buffer: []u8,
    };

    pub fn init(config: Config) FilteringWriter {
        return .{
            .interface = .{
                .vtable = &vtable,
                .buffer = config.buffer,
                .end = 0,
            },
            .filter = config.filter,
            .inner = config.inner,
        };
    }

    /// Returns a pointer to the Writer interface for use with reader.stream().
    /// IMPORTANT: Never copy the returned Writer - always use it via pointer.
    pub fn writer(self: *FilteringWriter) *std.Io.Writer {
        return &self.interface;
    }

    /// Finish filtering and return stats.
    /// This flushes any remaining buffered data through the filter.
    pub fn finish(self: *FilteringWriter) !FilterStats {
        // Process any remaining data in our buffer
        const buffered = self.interface.buffer[0..self.interface.end];
        if (buffered.len > 0) {
            _ = try self.filter.processChunk(buffered, self.inner);
            self.interface.end = 0;
        }
        // Finish the filter (processes any partial line)
        return try self.filter.finish(self.inner);
    }

    /// Get current stats without finishing
    pub fn getStats(self: *const FilteringWriter) FilterStats {
        return self.filter.getStats();
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *FilteringWriter = @fieldParentPtr("interface", w);

        // Process buffered data first
        const buffered = w.buffer[0..w.end];
        if (buffered.len > 0) {
            const result = self.filter.processChunk(buffered, self.inner) catch |err| {
                return mapFilterError(err);
            };
            _ = result; // We don't stop early on should_stop during drain
        }
        w.end = 0;

        // Process the data slices through the filter
        const slice = data[0..data.len -| 1];
        const pattern: []const u8 = if (data.len > 0) data[data.len - 1] else "";

        for (slice) |s| {
            const result = self.filter.processChunk(s, self.inner) catch |err| {
                return mapFilterError(err);
            };
            _ = result;
        }

        // Process the pattern repeated splat times
        for (0..splat) |_| {
            const result = self.filter.processChunk(pattern, self.inner) catch |err| {
                return mapFilterError(err);
            };
            _ = result;
        }

        // Return total bytes we accepted
        var total: usize = pattern.len * splat;
        for (slice) |s| {
            total += s.len;
        }
        return total;
    }

    fn flush(w: *std.Io.Writer) std.Io.Writer.Error!void {
        const self: *FilteringWriter = @fieldParentPtr("interface", w);

        // Process any remaining buffered data
        const buffered = w.buffer[0..w.end];
        if (buffered.len > 0) {
            _ = self.filter.processChunk(buffered, self.inner) catch |err| {
                return mapFilterError(err);
            };
            w.end = 0;
        }

        // Don't flush inner here - finish() will do that
    }

    fn mapFilterError(_: anyerror) std.Io.Writer.Error {
        // Map any filter error to Unexpected since std.Io.Writer.Error
        // only has WriteFailed
        return error.WriteFailed;
    }
};

// =============================================================================
// Tests
// =============================================================================

/// Helper function to create an AttributePath from a simple key for tests
fn testMakeAttrPath(allocator: std.mem.Allocator, key: []const u8) !AttributePath {
    var attr_path = AttributePath{};
    try attr_path.path.append(allocator, try allocator.dupe(u8, key));
    return attr_path;
}

test "StreamingPrometheusFilter - passthrough simple input" {
    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [512]u8 = undefined;
    var output_buf: [4096]u8 = undefined;

    var filter = StreamingPrometheusFilter.init(.{
        .line_buffer = &line_buf,
        .metadata_buffer = &metadata_buf,
        .max_input_bytes = 1024 * 1024,
    });

    var output_writer = std.Io.Writer.fixed(&output_buf);

    const input = "metric_a 1\nmetric_b 2\nmetric_c 3\n";
    const result = try filter.processChunk(input, &output_writer);

    try std.testing.expectEqual(input.len, result.consumed);
    try std.testing.expect(!result.should_stop);

    const stats = try filter.finish(&output_writer);
    try std.testing.expectEqual(@as(usize, 3), stats.lines_processed);
    try std.testing.expectEqual(@as(usize, 3), stats.lines_kept);
    try std.testing.expectEqual(@as(usize, 0), stats.lines_dropped);
    try std.testing.expectEqual(input.len, stats.bytes_processed);
    try std.testing.expectEqual(input.len, stats.bytes_forwarded);
    try std.testing.expect(!stats.scrape_truncated);

    // Verify output
    const written = output_writer.buffered();
    try std.testing.expectEqualStrings(input, written);
}

test "StreamingPrometheusFilter - chunked input" {
    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [512]u8 = undefined;
    var output_buf: [4096]u8 = undefined;

    var filter = StreamingPrometheusFilter.init(.{
        .line_buffer = &line_buf,
        .metadata_buffer = &metadata_buf,
        .max_input_bytes = 1024 * 1024,
    });

    var output_writer = std.Io.Writer.fixed(&output_buf);

    // Send data in small chunks
    const input = "metric_name{label=\"value\"} 123\n";
    var total_consumed: usize = 0;

    // Process byte by byte
    for (input) |byte| {
        const chunk = input[total_consumed .. total_consumed + 1];
        const result = try filter.processChunk(chunk, &output_writer);
        total_consumed += result.consumed;
        _ = byte;
    }

    try std.testing.expectEqual(input.len, total_consumed);

    const stats = try filter.finish(&output_writer);
    try std.testing.expectEqual(@as(usize, 1), stats.lines_processed);

    const written = output_writer.buffered();
    try std.testing.expectEqualStrings(input, written);
}

test "StreamingPrometheusFilter - data limit enforcement" {
    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [512]u8 = undefined;
    var output_buf: [4096]u8 = undefined;

    var filter = StreamingPrometheusFilter.init(.{
        .line_buffer = &line_buf,
        .metadata_buffer = &metadata_buf,
        .max_input_bytes = 20, // Very small limit
    });

    var output_writer = std.Io.Writer.fixed(&output_buf);

    const input = "metric_a 1\nmetric_b 2\nmetric_c 3\n";
    const result = try filter.processChunk(input, &output_writer);

    // Should only consume up to the limit
    try std.testing.expectEqual(@as(usize, 20), result.consumed);
    try std.testing.expect(result.should_stop);

    const stats = try filter.finish(&output_writer);
    try std.testing.expect(stats.scrape_truncated);
    try std.testing.expectEqual(@as(usize, 20), stats.bytes_processed);
}

test "StreamingPrometheusFilter - empty input" {
    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [512]u8 = undefined;
    var output_buf: [4096]u8 = undefined;

    var filter = StreamingPrometheusFilter.init(.{
        .line_buffer = &line_buf,
        .metadata_buffer = &metadata_buf,
        .max_input_bytes = 1024 * 1024,
    });

    var output_writer = std.Io.Writer.fixed(&output_buf);

    const result = try filter.processChunk("", &output_writer);
    try std.testing.expectEqual(@as(usize, 0), result.consumed);
    try std.testing.expect(!result.should_stop);

    const stats = try filter.finish(&output_writer);
    try std.testing.expectEqual(@as(usize, 0), stats.lines_processed);
    try std.testing.expectEqual(@as(usize, 0), stats.bytes_processed);
}

test "StreamingPrometheusFilter - partial line at end" {
    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [512]u8 = undefined;
    var output_buf: [4096]u8 = undefined;

    var filter = StreamingPrometheusFilter.init(.{
        .line_buffer = &line_buf,
        .metadata_buffer = &metadata_buf,
        .max_input_bytes = 1024 * 1024,
    });

    var output_writer = std.Io.Writer.fixed(&output_buf);

    // Input without trailing newline
    const input = "metric_a 1\nmetric_b 2";
    _ = try filter.processChunk(input, &output_writer);

    const stats = try filter.finish(&output_writer);

    // Should process both lines (finish() handles partial line)
    try std.testing.expectEqual(@as(usize, 2), stats.lines_processed);
    try std.testing.expectEqual(@as(usize, 2), stats.lines_kept);

    // Output should have newlines added
    const written = output_writer.buffered();
    try std.testing.expectEqualStrings("metric_a 1\nmetric_b 2\n", written);
}

test "StreamingPrometheusFilter - line longer than buffer" {
    var line_buf: [10]u8 = undefined; // Very small buffer
    var metadata_buf: [512]u8 = undefined;
    var output_buf: [4096]u8 = undefined;

    var filter = StreamingPrometheusFilter.init(.{
        .line_buffer = &line_buf,
        .metadata_buffer = &metadata_buf,
        .max_input_bytes = 1024 * 1024,
    });

    var output_writer = std.Io.Writer.fixed(&output_buf);

    // Line longer than buffer - will be truncated
    const input = "very_long_metric_name 123\nshort 1\n";
    _ = try filter.processChunk(input, &output_writer);

    const stats = try filter.finish(&output_writer);
    try std.testing.expectEqual(@as(usize, 2), stats.lines_processed);

    // First line truncated to buffer size, second line intact
    const written = output_writer.buffered();
    try std.testing.expect(std.mem.startsWith(u8, written, "very_long_"));
    try std.testing.expect(std.mem.endsWith(u8, written, "short 1\n"));
}

test "StreamingPrometheusFilter - HELP and TYPE lines passthrough" {
    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [512]u8 = undefined;
    var output_buf: [4096]u8 = undefined;

    var filter = StreamingPrometheusFilter.init(.{
        .line_buffer = &line_buf,
        .metadata_buffer = &metadata_buf,
        .max_input_bytes = 1024 * 1024,
    });

    var output_writer = std.Io.Writer.fixed(&output_buf);

    const input =
        \\# HELP http_requests_total Total requests
        \\# TYPE http_requests_total counter
        \\http_requests_total{method="get"} 100
        \\http_requests_total{method="post"} 50
        \\
    ;

    _ = try filter.processChunk(input, &output_writer);
    const stats = try filter.finish(&output_writer);

    try std.testing.expectEqual(@as(usize, 4), stats.lines_processed);
    try std.testing.expectEqual(@as(usize, 4), stats.lines_kept);

    const written = output_writer.buffered();
    try std.testing.expectEqualStrings(input, written);
}

test "StreamingPrometheusFilter - newline split across chunks" {
    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [512]u8 = undefined;
    var output_buf: [4096]u8 = undefined;

    var filter = StreamingPrometheusFilter.init(.{
        .line_buffer = &line_buf,
        .metadata_buffer = &metadata_buf,
        .max_input_bytes = 1024 * 1024,
    });

    var output_writer = std.Io.Writer.fixed(&output_buf);

    // First chunk ends mid-line
    _ = try filter.processChunk("metric_a 1\nmetric_b", &output_writer);
    // Second chunk completes the line
    _ = try filter.processChunk(" 2\nmetric_c 3\n", &output_writer);

    const stats = try filter.finish(&output_writer);
    try std.testing.expectEqual(@as(usize, 3), stats.lines_processed);

    const written = output_writer.buffered();
    try std.testing.expectEqualStrings("metric_a 1\nmetric_b 2\nmetric_c 3\n", written);
}

test "StreamingPrometheusFilter - exact buffer boundary" {
    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [512]u8 = undefined;
    var output_buf: [4096]u8 = undefined;

    var filter = StreamingPrometheusFilter.init(.{
        .line_buffer = &line_buf,
        .metadata_buffer = &metadata_buf,
        .max_input_bytes = 11, // Exactly "metric_a 1\n".len
    });

    var output_writer = std.Io.Writer.fixed(&output_buf);

    const input = "metric_a 1\nmetric_b 2\n";
    const result = try filter.processChunk(input, &output_writer);

    // Should process exactly up to the limit
    try std.testing.expectEqual(@as(usize, 11), result.consumed);
    try std.testing.expect(result.should_stop);

    const stats = try filter.finish(&output_writer);
    try std.testing.expectEqual(@as(usize, 1), stats.lines_processed);
    try std.testing.expect(stats.scrape_truncated);
}

// =============================================================================
// Reader/Writer Streaming Integration Tests
// =============================================================================
// These tests simulate the full flow: reading from an upstream source (simulated
// by a FixedBufferStream) and writing to a client (simulated by a fixed writer).
// This validates the streaming approach works correctly with std.Io interfaces.

/// Helper to create a mock "upstream" reader from a string
fn createMockReader(data: []const u8, read_buf: []u8) std.io.FixedBufferStream([]const u8) {
    _ = read_buf;
    return std.io.fixedBufferStream(data);
}

/// Simulates streaming from reader -> filter -> writer
/// Returns the filter stats after processing
fn streamThroughFilter(
    input_data: []const u8,
    line_buf: []u8,
    metadata_buf: []u8,
    output_buf: []u8,
    max_input_bytes: usize,
    chunk_size: usize,
) !struct { stats: FilterStats, output: []const u8 } {
    var filter = StreamingPrometheusFilter.init(.{
        .line_buffer = line_buf,
        .metadata_buffer = metadata_buf,
        .max_input_bytes = max_input_bytes,
    });

    var output_writer = std.Io.Writer.fixed(output_buf);

    // Process in chunks (simulating network reads)
    var pos: usize = 0;
    while (pos < input_data.len) {
        const end = @min(pos + chunk_size, input_data.len);
        const chunk = input_data[pos..end];

        const result = try filter.processChunk(chunk, &output_writer);
        pos += result.consumed;

        if (result.should_stop) break;
    }

    const stats = try filter.finish(&output_writer);
    return .{ .stats = stats, .output = output_writer.buffered() };
}

test "Reader/Writer streaming - basic passthrough" {
    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [4096]u8 = undefined;

    const input =
        \\# HELP http_requests_total The total number of HTTP requests.
        \\# TYPE http_requests_total counter
        \\http_requests_total{method="post",code="200"} 1027
        \\http_requests_total{method="post",code="400"} 3
        \\# HELP process_cpu_seconds_total Total CPU time spent.
        \\# TYPE process_cpu_seconds_total counter
        \\process_cpu_seconds_total 12345.67
        \\
    ;

    const result = try streamThroughFilter(
        input,
        &line_buf,
        &metadata_buf,
        &output_buf,
        1024 * 1024,
        64, // Small chunks to test reassembly
    );

    try std.testing.expectEqualStrings(input, result.output);
    try std.testing.expectEqual(@as(usize, 7), result.stats.lines_processed);
    try std.testing.expectEqual(@as(usize, 7), result.stats.lines_kept);
    try std.testing.expect(!result.stats.scrape_truncated);
}

test "Reader/Writer streaming - single byte chunks" {
    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [4096]u8 = undefined;

    const input = "metric_a 1\nmetric_b 2\nmetric_c 3\n";

    const result = try streamThroughFilter(
        input,
        &line_buf,
        &metadata_buf,
        &output_buf,
        1024 * 1024,
        1, // One byte at a time - extreme case
    );

    try std.testing.expectEqualStrings(input, result.output);
    try std.testing.expectEqual(@as(usize, 3), result.stats.lines_processed);
}

test "Reader/Writer streaming - large chunk (entire input)" {
    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [4096]u8 = undefined;

    const input = "metric_a 1\nmetric_b 2\nmetric_c 3\n";

    const result = try streamThroughFilter(
        input,
        &line_buf,
        &metadata_buf,
        &output_buf,
        1024 * 1024,
        4096, // Larger than input
    );

    try std.testing.expectEqualStrings(input, result.output);
    try std.testing.expectEqual(@as(usize, 3), result.stats.lines_processed);
}

test "Reader/Writer streaming - chunk boundary on newline" {
    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [4096]u8 = undefined;

    // "metric_a 1\n" is exactly 11 bytes
    const input = "metric_a 1\nmetric_b 2\nmetric_c 3\n";

    const result = try streamThroughFilter(
        input,
        &line_buf,
        &metadata_buf,
        &output_buf,
        1024 * 1024,
        11, // Chunk size exactly matches first line
    );

    try std.testing.expectEqualStrings(input, result.output);
    try std.testing.expectEqual(@as(usize, 3), result.stats.lines_processed);
}

test "Reader/Writer streaming - chunk boundary mid-line" {
    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [4096]u8 = undefined;

    const input = "metric_a 1\nmetric_b 2\nmetric_c 3\n";

    const result = try streamThroughFilter(
        input,
        &line_buf,
        &metadata_buf,
        &output_buf,
        1024 * 1024,
        7, // Splits "metric_a" from " 1\n"
    );

    try std.testing.expectEqualStrings(input, result.output);
    try std.testing.expectEqual(@as(usize, 3), result.stats.lines_processed);
}

test "Reader/Writer streaming - max_input_bytes truncation" {
    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [4096]u8 = undefined;

    const input = "metric_a 1\nmetric_b 2\nmetric_c 3\nmetric_d 4\n";

    const result = try streamThroughFilter(
        input,
        &line_buf,
        &metadata_buf,
        &output_buf,
        22, // Only enough for first two lines
        64,
    );

    try std.testing.expect(result.stats.scrape_truncated);
    try std.testing.expectEqual(@as(usize, 22), result.stats.bytes_processed);
    // Should have processed 2 complete lines (11 bytes each)
    try std.testing.expectEqual(@as(usize, 2), result.stats.lines_processed);
}

test "Reader/Writer streaming - histogram with buckets" {
    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [8192]u8 = undefined;

    const input =
        \\# HELP http_request_duration_seconds Request duration histogram.
        \\# TYPE http_request_duration_seconds histogram
        \\http_request_duration_seconds_bucket{le="0.005"} 24054
        \\http_request_duration_seconds_bucket{le="0.01"} 33444
        \\http_request_duration_seconds_bucket{le="0.025"} 100392
        \\http_request_duration_seconds_bucket{le="0.05"} 129389
        \\http_request_duration_seconds_bucket{le="0.1"} 133988
        \\http_request_duration_seconds_bucket{le="+Inf"} 144320
        \\http_request_duration_seconds_sum 53423
        \\http_request_duration_seconds_count 144320
        \\
    ;

    const result = try streamThroughFilter(
        input,
        &line_buf,
        &metadata_buf,
        &output_buf,
        1024 * 1024,
        128,
    );

    try std.testing.expectEqualStrings(input, result.output);
    try std.testing.expectEqual(@as(usize, 10), result.stats.lines_processed);
}

test "Reader/Writer streaming - summary with quantiles" {
    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [4096]u8 = undefined;

    const input =
        \\# HELP rpc_duration_seconds RPC latency distributions.
        \\# TYPE rpc_duration_seconds summary
        \\rpc_duration_seconds{quantile="0.5"} 0.000473
        \\rpc_duration_seconds{quantile="0.9"} 0.00102
        \\rpc_duration_seconds{quantile="0.99"} 0.00367
        \\rpc_duration_seconds_sum 17560473
        \\rpc_duration_seconds_count 2693
        \\
    ;

    const result = try streamThroughFilter(
        input,
        &line_buf,
        &metadata_buf,
        &output_buf,
        1024 * 1024,
        50,
    );

    try std.testing.expectEqualStrings(input, result.output);
    try std.testing.expectEqual(@as(usize, 7), result.stats.lines_processed);
}

test "Reader/Writer streaming - multiple metric families" {
    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [8192]u8 = undefined;

    const input =
        \\# HELP go_gc_duration_seconds GC invocation duration.
        \\# TYPE go_gc_duration_seconds summary
        \\go_gc_duration_seconds{quantile="0"} 0.000012
        \\go_gc_duration_seconds{quantile="1"} 0.000234
        \\go_gc_duration_seconds_sum 1.234
        \\go_gc_duration_seconds_count 100
        \\# HELP go_goroutines Number of goroutines.
        \\# TYPE go_goroutines gauge
        \\go_goroutines 42
        \\# HELP go_memstats_alloc_bytes Allocated bytes.
        \\# TYPE go_memstats_alloc_bytes gauge
        \\go_memstats_alloc_bytes 1.234e+07
        \\
    ;

    const result = try streamThroughFilter(
        input,
        &line_buf,
        &metadata_buf,
        &output_buf,
        1024 * 1024,
        100,
    );

    try std.testing.expectEqualStrings(input, result.output);
    try std.testing.expectEqual(@as(usize, 12), result.stats.lines_processed);
}

test "Reader/Writer streaming - empty lines preserved" {
    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [4096]u8 = undefined;

    const input = "metric_a 1\n\nmetric_b 2\n\n\nmetric_c 3\n";

    const result = try streamThroughFilter(
        input,
        &line_buf,
        &metadata_buf,
        &output_buf,
        1024 * 1024,
        10,
    );

    try std.testing.expectEqualStrings(input, result.output);
    // 3 metrics + 3 empty lines = 6 lines
    try std.testing.expectEqual(@as(usize, 6), result.stats.lines_processed);
}

test "Reader/Writer streaming - comments preserved" {
    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [4096]u8 = undefined;

    const input =
        \\# This is a comment
        \\# Another comment
        \\metric_a 1
        \\# Inline comment
        \\metric_b 2
        \\
    ;

    const result = try streamThroughFilter(
        input,
        &line_buf,
        &metadata_buf,
        &output_buf,
        1024 * 1024,
        20,
    );

    try std.testing.expectEqualStrings(input, result.output);
    try std.testing.expectEqual(@as(usize, 5), result.stats.lines_processed);
}

test "Reader/Writer streaming - special float values" {
    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [4096]u8 = undefined;

    const input =
        \\metric_nan NaN
        \\metric_pos_inf +Inf
        \\metric_neg_inf -Inf
        \\metric_scientific 1.234e+10
        \\metric_negative -42.5
        \\
    ;

    const result = try streamThroughFilter(
        input,
        &line_buf,
        &metadata_buf,
        &output_buf,
        1024 * 1024,
        25,
    );

    try std.testing.expectEqualStrings(input, result.output);
    try std.testing.expectEqual(@as(usize, 5), result.stats.lines_processed);
}

test "Reader/Writer streaming - labels with special characters" {
    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [4096]u8 = undefined;

    const input =
        \\metric{path="/api/v1/users"} 100
        \\metric{msg="line1\nline2"} 200
        \\metric{quote="say \"hello\""} 300
        \\metric{backslash="C:\\Users"} 400
        \\
    ;

    const result = try streamThroughFilter(
        input,
        &line_buf,
        &metadata_buf,
        &output_buf,
        1024 * 1024,
        30,
    );

    try std.testing.expectEqualStrings(input, result.output);
    try std.testing.expectEqual(@as(usize, 4), result.stats.lines_processed);
}

test "Reader/Writer streaming - unicode in labels" {
    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [4096]u8 = undefined;

    const input =
        \\metric{name="日本語"} 1
        \\metric{emoji="🚀"} 2
        \\metric{accent="café"} 3
        \\
    ;

    const result = try streamThroughFilter(
        input,
        &line_buf,
        &metadata_buf,
        &output_buf,
        1024 * 1024,
        15,
    );

    try std.testing.expectEqualStrings(input, result.output);
    try std.testing.expectEqual(@as(usize, 3), result.stats.lines_processed);
}

test "Reader/Writer streaming - timestamps" {
    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [4096]u8 = undefined;

    const input =
        \\metric_a 1 1234567890
        \\metric_b 2 1234567891000
        \\metric_c 3
        \\
    ;

    const result = try streamThroughFilter(
        input,
        &line_buf,
        &metadata_buf,
        &output_buf,
        1024 * 1024,
        20,
    );

    try std.testing.expectEqualStrings(input, result.output);
    try std.testing.expectEqual(@as(usize, 3), result.stats.lines_processed);
}

test "Reader/Writer streaming - metric names with colons" {
    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [4096]u8 = undefined;

    const input =
        \\namespace:subsystem:metric_total 100
        \\job:http_requests:rate5m 42.5
        \\
    ;

    const result = try streamThroughFilter(
        input,
        &line_buf,
        &metadata_buf,
        &output_buf,
        1024 * 1024,
        25,
    );

    try std.testing.expectEqualStrings(input, result.output);
    try std.testing.expectEqual(@as(usize, 2), result.stats.lines_processed);
}

test "Reader/Writer streaming - no trailing newline" {
    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [4096]u8 = undefined;

    const input = "metric_a 1\nmetric_b 2\nmetric_c 3";

    const result = try streamThroughFilter(
        input,
        &line_buf,
        &metadata_buf,
        &output_buf,
        1024 * 1024,
        10,
    );

    // finish() should handle partial line and add newline
    try std.testing.expectEqualStrings("metric_a 1\nmetric_b 2\nmetric_c 3\n", result.output);
    try std.testing.expectEqual(@as(usize, 3), result.stats.lines_processed);
}

test "Reader/Writer streaming - empty input" {
    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [4096]u8 = undefined;

    const input = "";

    const result = try streamThroughFilter(
        input,
        &line_buf,
        &metadata_buf,
        &output_buf,
        1024 * 1024,
        64,
    );

    try std.testing.expectEqualStrings("", result.output);
    try std.testing.expectEqual(@as(usize, 0), result.stats.lines_processed);
    try std.testing.expectEqual(@as(usize, 0), result.stats.bytes_processed);
}

test "Reader/Writer streaming - only newlines" {
    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [4096]u8 = undefined;

    const input = "\n\n\n";

    const result = try streamThroughFilter(
        input,
        &line_buf,
        &metadata_buf,
        &output_buf,
        1024 * 1024,
        1,
    );

    try std.testing.expectEqualStrings(input, result.output);
    try std.testing.expectEqual(@as(usize, 3), result.stats.lines_processed);
}

test "Reader/Writer streaming - stats accuracy" {
    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [4096]u8 = undefined;

    const input = "metric_a 1\nmetric_b 2\n"; // 22 bytes total

    const result = try streamThroughFilter(
        input,
        &line_buf,
        &metadata_buf,
        &output_buf,
        1024 * 1024,
        5,
    );

    try std.testing.expectEqual(@as(usize, 22), result.stats.bytes_processed);
    try std.testing.expectEqual(@as(usize, 22), result.stats.bytes_forwarded);
    try std.testing.expectEqual(@as(usize, 2), result.stats.lines_processed);
    try std.testing.expectEqual(@as(usize, 2), result.stats.lines_kept);
    try std.testing.expectEqual(@as(usize, 0), result.stats.lines_dropped);
    try std.testing.expect(!result.stats.scrape_truncated);
}

test "Reader/Writer streaming - very long metric name" {
    var line_buf: [2048]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [4096]u8 = undefined;

    // Create a metric with a very long name (but within buffer)
    const long_name = "a" ** 500;
    const input = long_name ++ " 42\n";

    const result = try streamThroughFilter(
        input,
        &line_buf,
        &metadata_buf,
        &output_buf,
        1024 * 1024,
        100,
    );

    try std.testing.expectEqualStrings(input, result.output);
    try std.testing.expectEqual(@as(usize, 1), result.stats.lines_processed);
}

test "Reader/Writer streaming - many small metrics" {
    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [65536]u8 = undefined;

    // Generate 100 metrics
    var input_buf: [10000]u8 = undefined;
    var input_stream = std.io.fixedBufferStream(&input_buf);
    const input_writer = input_stream.writer();

    for (0..100) |i| {
        input_writer.print("metric_{d} {d}\n", .{ i, i * 10 }) catch unreachable;
    }

    const input = input_stream.getWritten();

    const result = try streamThroughFilter(
        input,
        &line_buf,
        &metadata_buf,
        &output_buf,
        1024 * 1024,
        50,
    );

    try std.testing.expectEqualStrings(input, result.output);
    try std.testing.expectEqual(@as(usize, 100), result.stats.lines_processed);
}

test "Reader/Writer streaming - realistic prometheus output" {
    var line_buf: [4096]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [32768]u8 = undefined;

    // Realistic prometheus /metrics output
    const input =
        \\# HELP go_gc_duration_seconds A summary of the pause duration of garbage collection cycles.
        \\# TYPE go_gc_duration_seconds summary
        \\go_gc_duration_seconds{quantile="0"} 1.3955e-05
        \\go_gc_duration_seconds{quantile="0.25"} 2.5695e-05
        \\go_gc_duration_seconds{quantile="0.5"} 3.6727e-05
        \\go_gc_duration_seconds{quantile="0.75"} 5.2287e-05
        \\go_gc_duration_seconds{quantile="1"} 0.000123456
        \\go_gc_duration_seconds_sum 0.123456789
        \\go_gc_duration_seconds_count 1234
        \\# HELP go_goroutines Number of goroutines that currently exist.
        \\# TYPE go_goroutines gauge
        \\go_goroutines 42
        \\# HELP go_info Information about the Go environment.
        \\# TYPE go_info gauge
        \\go_info{version="go1.21.0"} 1
        \\# HELP go_memstats_alloc_bytes Number of bytes allocated and still in use.
        \\# TYPE go_memstats_alloc_bytes gauge
        \\go_memstats_alloc_bytes 1.234567e+07
        \\# HELP go_memstats_alloc_bytes_total Total number of bytes allocated, even if freed.
        \\# TYPE go_memstats_alloc_bytes_total counter
        \\go_memstats_alloc_bytes_total 9.87654321e+09
        \\# HELP http_requests_total Total number of HTTP requests made.
        \\# TYPE http_requests_total counter
        \\http_requests_total{method="GET",handler="/api/v1/query",code="200"} 12345
        \\http_requests_total{method="GET",handler="/api/v1/query",code="400"} 23
        \\http_requests_total{method="GET",handler="/api/v1/query",code="500"} 5
        \\http_requests_total{method="POST",handler="/api/v1/query",code="200"} 6789
        \\http_requests_total{method="GET",handler="/api/v1/labels",code="200"} 1234
        \\# HELP http_request_duration_seconds HTTP request latencies in seconds.
        \\# TYPE http_request_duration_seconds histogram
        \\http_request_duration_seconds_bucket{handler="/api/v1/query",le="0.001"} 100
        \\http_request_duration_seconds_bucket{handler="/api/v1/query",le="0.01"} 500
        \\http_request_duration_seconds_bucket{handler="/api/v1/query",le="0.1"} 900
        \\http_request_duration_seconds_bucket{handler="/api/v1/query",le="1"} 990
        \\http_request_duration_seconds_bucket{handler="/api/v1/query",le="10"} 999
        \\http_request_duration_seconds_bucket{handler="/api/v1/query",le="+Inf"} 1000
        \\http_request_duration_seconds_sum{handler="/api/v1/query"} 123.456
        \\http_request_duration_seconds_count{handler="/api/v1/query"} 1000
        \\# HELP process_cpu_seconds_total Total user and system CPU time spent in seconds.
        \\# TYPE process_cpu_seconds_total counter
        \\process_cpu_seconds_total 123.45
        \\# HELP process_resident_memory_bytes Resident memory size in bytes.
        \\# TYPE process_resident_memory_bytes gauge
        \\process_resident_memory_bytes 5.6789e+07
        \\
    ;

    const result = try streamThroughFilter(
        input,
        &line_buf,
        &metadata_buf,
        &output_buf,
        1024 * 1024,
        256, // Realistic chunk size
    );

    try std.testing.expectEqualStrings(input, result.output);
    try std.testing.expectEqual(@as(usize, 44), result.stats.lines_processed);
    try std.testing.expect(!result.stats.scrape_truncated);
}

// =============================================================================
// Policy-based Filtering Tests (PolicyStreamingFilter via FilteringWriter)
// =============================================================================
// These tests verify the PolicyStreamingFilter correctly applies policies
// to filter metrics while preserving correct HELP/TYPE metadata handling.
// All tests use FilteringWriter - the public API for integration.

const NoopEventBus = o11y.NoopEventBus;

/// Helper to stream through FilteringWriter with a given registry.
/// This tests the public API that the prometheus module will use.
fn streamWithFilteringWriter(
    input_data: []const u8,
    line_buf: []u8,
    metadata_buf: []u8,
    output_buf: []u8,
    filtering_buf: []u8,
    registry: *PolicyRegistry,
    bus: *EventBus,
    allocator: std.mem.Allocator,
) !struct { stats: FilterStats, output: []const u8 } {
    var filter = PolicyStreamingFilter.init(.{
        .line_buffer = line_buf,
        .metadata_buffer = metadata_buf,
        .max_input_bytes = 1024 * 1024,
        .registry = registry,
        .bus = bus,
        .allocator = allocator,
    });

    var output_writer = std.Io.Writer.fixed(output_buf);

    var filtering_writer = FilteringWriter.init(.{
        .filter = &filter,
        .inner = &output_writer,
        .buffer = filtering_buf,
    });

    // Write all input through the FilteringWriter
    const fw = filtering_writer.writer();
    try fw.writeAll(input_data);

    const stats = try filtering_writer.finish();
    return .{ .stats = stats, .output = output_writer.buffered() };
}

test "PolicyStreamingFilter - no policies passes all metrics" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [4096]u8 = undefined;
    var filtering_buf: [512]u8 = undefined;

    const input =
        \\# HELP http_requests_total Total requests
        \\# TYPE http_requests_total counter
        \\http_requests_total{method="get"} 100
        \\http_requests_total{method="post"} 50
        \\
    ;

    const result = try streamWithFilteringWriter(
        input,
        &line_buf,
        &metadata_buf,
        &output_buf,
        &filtering_buf,
        &registry,
        noop_bus.eventBus(),
        allocator,
    );

    // With no policies, all metrics pass through
    try std.testing.expectEqualStrings(input, result.output);
    try std.testing.expectEqual(@as(usize, 4), result.stats.lines_processed);
    try std.testing.expectEqual(@as(usize, 0), result.stats.lines_dropped);
}

test "PolicyStreamingFilter - DROP policy filters metrics by name" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create DROP policy for metrics starting with "debug_"
    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-debug"),
        .name = try allocator.dupe(u8, "drop-debug"),
        .enabled = true,
        .target = .{
            .metric = .{
                .keep = false, // drop matching metrics
            },
        },
    };
    try drop_policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "^debug_") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "test-provider", .file);

    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [4096]u8 = undefined;
    var filtering_buf: [512]u8 = undefined;

    const input =
        \\# HELP debug_internal Internal debug metric
        \\# TYPE debug_internal gauge
        \\debug_internal 42
        \\# HELP http_requests_total Total requests
        \\# TYPE http_requests_total counter
        \\http_requests_total 100
        \\
    ;

    const result = try streamWithFilteringWriter(
        input,
        &line_buf,
        &metadata_buf,
        &output_buf,
        &filtering_buf,
        &registry,
        noop_bus.eventBus(),
        allocator,
    );

    // debug_internal should be dropped, http_requests_total should remain
    // HELP/TYPE for dropped metrics should also be excluded
    try std.testing.expect(std.mem.indexOf(u8, result.output, "debug_internal") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "http_requests_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "Total requests") != null);
    try std.testing.expectEqual(@as(usize, 1), result.stats.lines_dropped);
}

test "PolicyStreamingFilter - DROP policy to keep only non-matching metrics" {
    // Note: To "keep only X", you use a DROP policy matching everything EXCEPT X.
    // A KEEP policy only affects matched metrics; unmatched metrics pass through.
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create DROP policy for metrics NOT starting with "important_"
    // This achieves "keep only important_* metrics"
    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-non-important"),
        .name = try allocator.dupe(u8, "drop-non-important"),
        .enabled = true,
        .target = .{
            .metric = .{
                .keep = false, // drop matching metrics
            },
        },
    };
    try drop_policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "^other_") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "test-provider", .file);

    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [4096]u8 = undefined;
    var filtering_buf: [512]u8 = undefined;

    const input =
        \\important_metric 100
        \\other_metric 50
        \\important_counter 200
        \\
    ;

    const result = try streamWithFilteringWriter(
        input,
        &line_buf,
        &metadata_buf,
        &output_buf,
        &filtering_buf,
        &registry,
        noop_bus.eventBus(),
        allocator,
    );

    // Only important_* metrics should remain (other_metric dropped)
    try std.testing.expect(std.mem.indexOf(u8, result.output, "important_metric") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "important_counter") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "other_metric") == null);
    try std.testing.expectEqual(@as(usize, 1), result.stats.lines_dropped);
    try std.testing.expectEqual(@as(usize, 2), result.stats.lines_kept);
}

test "PolicyStreamingFilter - filter by label value" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create DROP policy for metrics with env="debug" label
    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-debug-env"),
        .name = try allocator.dupe(u8, "drop-debug-env"),
        .enabled = true,
        .target = .{
            .metric = .{
                .keep = false,
            },
        },
    };
    try drop_policy.target.?.metric.match.append(allocator, .{
        .field = .{ .datapoint_attribute = try testMakeAttrPath(allocator, "env") },
        .match = .{ .exact = try allocator.dupe(u8, "debug") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "test-provider", .file);

    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [4096]u8 = undefined;
    var filtering_buf: [512]u8 = undefined;

    const input =
        \\http_requests{env="debug",method="get"} 10
        \\http_requests{env="prod",method="get"} 100
        \\http_requests{env="debug",method="post"} 5
        \\http_requests{env="prod",method="post"} 50
        \\
    ;

    const result = try streamWithFilteringWriter(
        input,
        &line_buf,
        &metadata_buf,
        &output_buf,
        &filtering_buf,
        &registry,
        noop_bus.eventBus(),
        allocator,
    );

    // env="debug" metrics should be dropped
    try std.testing.expect(std.mem.indexOf(u8, result.output, "env=\"debug\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "env=\"prod\"") != null);
    try std.testing.expectEqual(@as(usize, 2), result.stats.lines_dropped);
    try std.testing.expectEqual(@as(usize, 2), result.stats.lines_kept);
}

test "PolicyStreamingFilter - metadata excluded when all samples dropped" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create DROP policy for all debug_ metrics
    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-debug"),
        .name = try allocator.dupe(u8, "drop-debug"),
        .enabled = true,
        .target = .{
            .metric = .{
                .keep = false,
            },
        },
    };
    try drop_policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "^debug_") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "test-provider", .file);

    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [4096]u8 = undefined;
    var filtering_buf: [512]u8 = undefined;

    const input =
        \\# HELP debug_metric A debug metric
        \\# TYPE debug_metric gauge
        \\debug_metric{instance="a"} 1
        \\debug_metric{instance="b"} 2
        \\# HELP prod_metric A production metric
        \\# TYPE prod_metric counter
        \\prod_metric 100
        \\
    ;

    const result = try streamWithFilteringWriter(
        input,
        &line_buf,
        &metadata_buf,
        &output_buf,
        &filtering_buf,
        &registry,
        noop_bus.eventBus(),
        allocator,
    );

    // debug_metric HELP/TYPE and samples should all be excluded
    try std.testing.expect(std.mem.indexOf(u8, result.output, "debug_metric") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "A debug metric") == null);
    // prod_metric should be present with its metadata
    try std.testing.expect(std.mem.indexOf(u8, result.output, "prod_metric") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "A production metric") != null);
}

test "PolicyStreamingFilter - metadata included when some samples kept" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create DROP policy for instance="debug" label
    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-debug-instance"),
        .name = try allocator.dupe(u8, "drop-debug-instance"),
        .enabled = true,
        .target = .{
            .metric = .{
                .keep = false,
            },
        },
    };
    try drop_policy.target.?.metric.match.append(allocator, .{
        .field = .{ .datapoint_attribute = try testMakeAttrPath(allocator, "instance") },
        .match = .{ .exact = try allocator.dupe(u8, "debug") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "test-provider", .file);

    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [4096]u8 = undefined;
    var filtering_buf: [512]u8 = undefined;

    const input =
        \\# HELP my_metric A metric with multiple instances
        \\# TYPE my_metric gauge
        \\my_metric{instance="debug"} 1
        \\my_metric{instance="prod"} 100
        \\
    ;

    const result = try streamWithFilteringWriter(
        input,
        &line_buf,
        &metadata_buf,
        &output_buf,
        &filtering_buf,
        &registry,
        noop_bus.eventBus(),
        allocator,
    );

    // HELP/TYPE should be included because at least one sample is kept
    try std.testing.expect(std.mem.indexOf(u8, result.output, "# HELP my_metric") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "# TYPE my_metric") != null);
    // instance="debug" dropped, instance="prod" kept
    try std.testing.expect(std.mem.indexOf(u8, result.output, "instance=\"debug\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "instance=\"prod\"") != null);
}

test "PolicyStreamingFilter - histogram buckets filtered together" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create DROP policy for debug histograms
    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-debug-histogram"),
        .name = try allocator.dupe(u8, "drop-debug-histogram"),
        .enabled = true,
        .target = .{
            .metric = .{
                .keep = false,
            },
        },
    };
    try drop_policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "^debug_") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "test-provider", .file);

    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [8192]u8 = undefined;
    var filtering_buf: [512]u8 = undefined;

    const input =
        \\# HELP debug_duration Debug request duration
        \\# TYPE debug_duration histogram
        \\debug_duration_bucket{le="0.1"} 10
        \\debug_duration_bucket{le="1"} 50
        \\debug_duration_bucket{le="+Inf"} 100
        \\debug_duration_sum 123.45
        \\debug_duration_count 100
        \\# HELP http_duration HTTP request duration
        \\# TYPE http_duration histogram
        \\http_duration_bucket{le="0.1"} 1000
        \\http_duration_bucket{le="1"} 5000
        \\http_duration_bucket{le="+Inf"} 10000
        \\http_duration_sum 12345.67
        \\http_duration_count 10000
        \\
    ;

    const result = try streamWithFilteringWriter(
        input,
        &line_buf,
        &metadata_buf,
        &output_buf,
        &filtering_buf,
        &registry,
        noop_bus.eventBus(),
        allocator,
    );

    // All debug_duration* should be dropped
    try std.testing.expect(std.mem.indexOf(u8, result.output, "debug_duration") == null);
    // All http_duration* should remain
    try std.testing.expect(std.mem.indexOf(u8, result.output, "http_duration_bucket") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "http_duration_sum") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "http_duration_count") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "# HELP http_duration") != null);
}

test "PolicyStreamingFilter - comments preserved regardless of policy" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create DROP policy for all metrics starting with "metric_"
    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-all"),
        .name = try allocator.dupe(u8, "drop-all"),
        .enabled = true,
        .target = .{
            .metric = .{
                .keep = false,
            },
        },
    };
    try drop_policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "^metric_") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "test-provider", .file);

    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [4096]u8 = undefined;
    var filtering_buf: [512]u8 = undefined;

    const input =
        \\# This is a comment
        \\# Another comment
        \\metric_a 1
        \\metric_b 2
        \\
    ;

    const result = try streamWithFilteringWriter(
        input,
        &line_buf,
        &metadata_buf,
        &output_buf,
        &filtering_buf,
        &registry,
        noop_bus.eventBus(),
        allocator,
    );

    // Comments should be preserved even when metrics are dropped
    try std.testing.expect(std.mem.indexOf(u8, result.output, "# This is a comment") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "# Another comment") != null);
    // Metrics should be dropped
    try std.testing.expect(std.mem.indexOf(u8, result.output, "metric_a") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "metric_b") == null);
}

test "PolicyStreamingFilter - empty lines preserved regardless of policy" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create DROP policy for debug metrics
    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-debug"),
        .name = try allocator.dupe(u8, "drop-debug"),
        .enabled = true,
        .target = .{
            .metric = .{
                .keep = false,
            },
        },
    };
    try drop_policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "^debug_") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "test-provider", .file);

    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [4096]u8 = undefined;
    var filtering_buf: [512]u8 = undefined;

    const input = "debug_metric 1\n\nprod_metric 100\n\n";

    const result = try streamWithFilteringWriter(
        input,
        &line_buf,
        &metadata_buf,
        &output_buf,
        &filtering_buf,
        &registry,
        noop_bus.eventBus(),
        allocator,
    );

    // Empty lines should be preserved
    try std.testing.expect(std.mem.indexOf(u8, result.output, "\n\n") != null);
    // prod_metric kept, debug_metric dropped
    try std.testing.expect(std.mem.indexOf(u8, result.output, "prod_metric") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "debug_metric") == null);
}

test "PolicyStreamingFilter - stats track dropped vs kept correctly" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create DROP policy for debug metrics
    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-debug"),
        .name = try allocator.dupe(u8, "drop-debug"),
        .enabled = true,
        .target = .{
            .metric = .{
                .keep = false,
            },
        },
    };
    try drop_policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "^debug_") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "test-provider", .file);

    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [4096]u8 = undefined;
    var filtering_buf: [512]u8 = undefined;

    const input =
        \\# Comment line
        \\debug_metric_1 1
        \\debug_metric_2 2
        \\debug_metric_3 3
        \\prod_metric_1 100
        \\prod_metric_2 200
        \\
    ;

    const result = try streamWithFilteringWriter(
        input,
        &line_buf,
        &metadata_buf,
        &output_buf,
        &filtering_buf,
        &registry,
        noop_bus.eventBus(),
        allocator,
    );

    // 6 total lines processed
    try std.testing.expectEqual(@as(usize, 6), result.stats.lines_processed);
    // 3 debug metrics dropped
    try std.testing.expectEqual(@as(usize, 3), result.stats.lines_dropped);
    // 1 comment + 2 prod metrics kept
    try std.testing.expectEqual(@as(usize, 3), result.stats.lines_kept);
}

test "PolicyStreamingFilter - max_input_bytes truncation with policy" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create DROP policy for debug metrics
    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-debug"),
        .name = try allocator.dupe(u8, "drop-debug"),
        .enabled = true,
        .target = .{
            .metric = .{
                .keep = false,
            },
        },
    };
    try drop_policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "^debug_") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "test-provider", .file);

    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [4096]u8 = undefined;

    // Input has 5 lines with varying lengths:
    // metric_a 1\n = 11 bytes
    // debug_b 2\n  = 10 bytes
    // metric_c 3\n = 11 bytes (total: 32 bytes)
    // metric_d 4\n = 11 bytes (total: 43 bytes)
    // metric_e 5\n = 11 bytes (total: 54 bytes)
    const input =
        \\metric_a 1
        \\debug_b 2
        \\metric_c 3
        \\metric_d 4
        \\metric_e 5
        \\
    ;

    // Create filter with max_input_bytes = 32 (exactly first 3 lines)
    var filter = PolicyStreamingFilter.init(.{
        .line_buffer = &line_buf,
        .metadata_buffer = &metadata_buf,
        .max_input_bytes = 32,
        .registry = &registry,
        .bus = noop_bus.eventBus(),
        .allocator = allocator,
    });

    var output_writer = std.Io.Writer.fixed(&output_buf);

    // Process all at once
    const result = try filter.processChunk(input, &output_writer);

    try std.testing.expect(result.should_stop);
    try std.testing.expectEqual(@as(usize, 32), result.consumed);

    const stats = try filter.finish(&output_writer);

    // Should have truncated
    try std.testing.expect(stats.scrape_truncated);
    try std.testing.expectEqual(@as(usize, 32), stats.bytes_processed);
    // 3 lines processed (metric_a, debug_b, metric_c)
    try std.testing.expectEqual(@as(usize, 3), stats.lines_processed);
    // 1 line dropped (debug_b)
    try std.testing.expectEqual(@as(usize, 1), stats.lines_dropped);
    // 2 lines kept (metric_a, metric_c)
    try std.testing.expectEqual(@as(usize, 2), stats.lines_kept);

    // Check output only has kept metrics
    const output = output_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "metric_a") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "metric_c") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "debug_b") == null);
    // metric_d and metric_e should not appear (truncated)
    try std.testing.expect(std.mem.indexOf(u8, output, "metric_d") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "metric_e") == null);
}

// =============================================================================
// FilteringWriter Tests
// =============================================================================

test "FilteringWriter - basic streaming with reader.stream() pattern" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create DROP policy for debug metrics
    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-debug"),
        .name = try allocator.dupe(u8, "drop-debug"),
        .enabled = true,
        .target = .{
            .metric = .{
                .keep = false,
            },
        },
    };
    try drop_policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "^debug_") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "test-provider", .file);

    // Setup buffers
    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [4096]u8 = undefined;
    var filtering_buf: [512]u8 = undefined;

    // Create filter
    var filter = PolicyStreamingFilter.init(.{
        .line_buffer = &line_buf,
        .metadata_buffer = &metadata_buf,
        .max_input_bytes = 1024 * 1024,
        .registry = &registry,
        .bus = noop_bus.eventBus(),
        .allocator = allocator,
    });

    // Create output writer (simulates response writer)
    var output_writer = std.Io.Writer.fixed(&output_buf);

    // Create filtering writer
    var filtering_writer = FilteringWriter.init(.{
        .filter = &filter,
        .inner = &output_writer,
        .buffer = &filtering_buf,
    });

    const input =
        \\# HELP http_requests Total requests
        \\# TYPE http_requests counter
        \\http_requests 100
        \\debug_internal 999
        \\http_errors 5
        \\
    ;

    // Simulate reader.stream() by writing to the filtering writer
    const fw = filtering_writer.writer();
    try fw.writeAll(input);

    // Finish and get stats
    const stats = try filtering_writer.finish();

    // Verify stats
    try std.testing.expectEqual(@as(usize, 5), stats.lines_processed);
    try std.testing.expectEqual(@as(usize, 1), stats.lines_dropped);
    try std.testing.expectEqual(@as(usize, 4), stats.lines_kept);

    // Verify output
    const output = output_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "http_requests 100") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "http_errors 5") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "debug_internal") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "# HELP http_requests") != null);
}

test "FilteringWriter - simulated chunked streaming" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // No policies - passthrough
    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [4096]u8 = undefined;
    var filtering_buf: [32]u8 = undefined; // Small buffer to force multiple drains

    var filter = PolicyStreamingFilter.init(.{
        .line_buffer = &line_buf,
        .metadata_buffer = &metadata_buf,
        .max_input_bytes = 1024 * 1024,
        .registry = &registry,
        .bus = noop_bus.eventBus(),
        .allocator = allocator,
    });

    var output_writer = std.Io.Writer.fixed(&output_buf);

    var filtering_writer = FilteringWriter.init(.{
        .filter = &filter,
        .inner = &output_writer,
        .buffer = &filtering_buf,
    });

    const input =
        \\metric_a 1
        \\metric_b 2
        \\metric_c 3
        \\metric_d 4
        \\
    ;

    // Write in small chunks to simulate streaming
    const fw = filtering_writer.writer();
    var pos: usize = 0;
    const chunk_size: usize = 8;
    while (pos < input.len) {
        const end = @min(pos + chunk_size, input.len);
        try fw.writeAll(input[pos..end]);
        pos = end;
    }

    const stats = try filtering_writer.finish();

    try std.testing.expectEqual(@as(usize, 4), stats.lines_processed);
    try std.testing.expectEqual(@as(usize, 4), stats.lines_kept);

    const output = output_writer.buffered();
    try std.testing.expectEqualStrings(input, output);
}

test "FilteringWriter - max_input_bytes limit" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // No policies - test just the byte limit
    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [1536]u8 = undefined;
    var output_buf: [4096]u8 = undefined;
    var filtering_buf: [256]u8 = undefined;

    var filter = PolicyStreamingFilter.init(.{
        .line_buffer = &line_buf,
        .metadata_buffer = &metadata_buf,
        .max_input_bytes = 25, // Small limit
        .registry = &registry,
        .bus = noop_bus.eventBus(),
        .allocator = allocator,
    });

    var output_writer = std.Io.Writer.fixed(&output_buf);

    var filtering_writer = FilteringWriter.init(.{
        .filter = &filter,
        .inner = &output_writer,
        .buffer = &filtering_buf,
    });

    const input =
        \\metric_a 1
        \\metric_b 2
        \\metric_c 3
        \\metric_d 4
        \\
    ;

    // Write all data - filter should stop at max_input_bytes
    const fw = filtering_writer.writer();
    try fw.writeAll(input);

    const stats = try filtering_writer.finish();

    // Should have truncated after ~25 bytes (2 lines = 22 bytes, 3 lines = 33 bytes)
    // With limit 25, we get 2 complete lines (22 bytes) then stop partway through 3rd
    try std.testing.expect(stats.scrape_truncated);
    try std.testing.expect(stats.bytes_processed <= 25);
}
