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
const line_parser = @import("line_parser.zig");
const field_accessor = @import("field_accessor.zig");
const policy = @import("../policy/root.zig");
const o11y = @import("../observability/root.zig");

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
    max_scrape_bytes: usize,

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

    // State
    stopped: bool,

    pub const Config = struct {
        line_buffer: []u8,
        metadata_buffer: []u8,
        max_scrape_bytes: usize,
    };

    pub fn init(config: Config) StreamingPrometheusFilter {
        return .{
            .max_scrape_bytes = config.max_scrape_bytes,
            .line_buffer = config.line_buffer,
            .line_len = 0,
            .metadata_buffer = config.metadata_buffer,
            .bytes_processed = 0,
            .bytes_forwarded = 0,
            .lines_processed = 0,
            .lines_dropped = 0,
            .lines_kept = 0,
            .scrape_truncated = false,
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
        // Check data limit before processing
        const remaining = self.max_scrape_bytes -| self.bytes_processed;
        if (remaining == 0) {
            self.scrape_truncated = true;
            self.stopped = true;
            return .{ .consumed = 0, .should_stop = true };
        }

        // Only process up to remaining budget
        const to_process = @min(chunk.len, remaining);
        var consumed: usize = 0;

        for (chunk[0..to_process]) |byte| {
            consumed += 1;
            self.bytes_processed += 1;

            if (byte == '\n') {
                // Process the complete line
                try self.processLine(writer);
                self.line_len = 0;
            } else if (self.line_len < self.line_buffer.len) {
                // Accumulate byte into line buffer
                self.line_buffer[self.line_len] = byte;
                self.line_len += 1;
            }
            // If line exceeds buffer, we truncate (bytes are dropped until newline)
        }

        // Check if we've hit the limit after processing
        if (self.bytes_processed >= self.max_scrape_bytes) {
            self.scrape_truncated = true;
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
        // If there's a partial line at the end (no trailing newline), forward it
        if (self.line_len > 0) {
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
        max_scrape_bytes: usize,
        registry: *PolicyRegistry,
        bus: *EventBus,
        allocator: std.mem.Allocator,
    };

    pub fn init(config: Config) PolicyStreamingFilter {
        return .{
            .base = StreamingPrometheusFilter.init(.{
                .line_buffer = config.line_buffer,
                .metadata_buffer = config.metadata_buffer,
                .max_scrape_bytes = config.max_scrape_bytes,
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
        // Check data limit before processing
        const remaining = self.base.max_scrape_bytes -| self.base.bytes_processed;
        if (remaining == 0) {
            self.base.scrape_truncated = true;
            self.base.stopped = true;
            return .{ .consumed = 0, .should_stop = true };
        }

        // Only process up to remaining budget
        const to_process = @min(chunk.len, remaining);
        var consumed: usize = 0;

        for (chunk[0..to_process]) |byte| {
            consumed += 1;
            self.base.bytes_processed += 1;

            if (byte == '\n') {
                // Process the complete line with policy evaluation
                try self.processLineWithPolicy(writer);
                self.base.line_len = 0;
            } else if (self.base.line_len < self.base.line_buffer.len) {
                self.base.line_buffer[self.base.line_len] = byte;
                self.base.line_len += 1;
            }
        }

        if (self.base.bytes_processed >= self.base.max_scrape_bytes) {
            self.base.scrape_truncated = true;
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
        if (self.base.line_len > 0) {
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
// Tests
// =============================================================================

test "StreamingPrometheusFilter - passthrough simple input" {
    var line_buf: [1024]u8 = undefined;
    var metadata_buf: [512]u8 = undefined;
    var output_buf: [4096]u8 = undefined;

    var filter = StreamingPrometheusFilter.init(.{
        .line_buffer = &line_buf,
        .metadata_buffer = &metadata_buf,
        .max_scrape_bytes = 1024 * 1024,
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
        .max_scrape_bytes = 1024 * 1024,
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
        .max_scrape_bytes = 20, // Very small limit
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
        .max_scrape_bytes = 1024 * 1024,
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
        .max_scrape_bytes = 1024 * 1024,
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
        .max_scrape_bytes = 1024 * 1024,
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
        .max_scrape_bytes = 1024 * 1024,
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
        .max_scrape_bytes = 1024 * 1024,
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
        .max_scrape_bytes = 11, // Exactly "metric_a 1\n".len
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
