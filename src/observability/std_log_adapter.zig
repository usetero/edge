//! Std.log Adapter for EventBus
//!
//! Provides integration between Zig's std.log and the EventBus observability system.
//! This allows legacy code using std.log to emit structured events through the EventBus.
//!
//! Usage:
//! ```zig
//! const std = @import("std");
//! const o11y = @import("observability");
//!
//! // Override std.log options to use the adapter
//! pub const std_options: std.Options = .{
//!     .logFn = o11y.StdLogAdapter.logFn,
//! };
//!
//! // Initialize the adapter with your EventBus (call once at startup)
//! var stdio_bus: o11y.StdioEventBus = undefined;
//! stdio_bus.init();
//! o11y.StdLogAdapter.init(stdio_bus.eventBus());
//!
//! // Now std.log calls go through EventBus
//! const log = std.log.scoped(.my_module);
//! log.info("User logged in", .{});
//! ```

const std = @import("std");
const EventBus = @import("event_bus.zig").EventBus;
const Level = @import("level.zig").Level;

/// Global EventBus pointer for std.log adapter.
/// Must be initialized before any std.log calls.
var global_bus: ?*EventBus = null;

/// Std.log adapter that routes log messages through the EventBus.
///
/// IMPORTANT: Call init() with your EventBus before any std.log calls.
pub const StdLogAdapter = struct {
    /// Initialize the adapter with an EventBus.
    /// This must be called before any std.log calls are made.
    pub fn init(bus: *EventBus) void {
        global_bus = bus;
    }

    /// Reset the adapter (mainly for testing).
    pub fn deinit() void {
        global_bus = null;
    }

    /// Log function compatible with std.Options.logFn
    pub fn logFn(
        comptime level: std.log.Level,
        comptime scope: @Type(.enum_literal),
        comptime format: []const u8,
        args: anytype,
    ) void {
        const bus = global_bus orelse {
            // Fallback to default log if not initialized
            std.log.defaultLog(level, scope, format, args);
            return;
        };

        const event_level = mapLevel(level);

        // Check level filter
        if (@intFromEnum(event_level) < @intFromEnum(bus.min_level)) {
            return;
        }

        // Select writer based on level
        const writer = if (event_level == .err) bus.err_writer else bus.writer;

        // Timestamp (ISO 8601 with milliseconds)
        const millis = std.time.milliTimestamp();
        const secs: u64 = @intCast(@divFloor(millis, 1000));
        const ms: u64 = @intCast(@mod(millis, 1000));
        const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = secs };
        const epoch_day = epoch_seconds.getEpochDay();
        const year_day = epoch_day.calculateYearDay();
        const month_day = year_day.calculateMonthDay();
        const day_seconds = epoch_seconds.getDaySeconds();

        // Format: 2025-12-03T14:30:45.123Z [INFO] scope: message
        writer.print("{d}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z [{s}] {s}: ", .{
            year_day.year,
            month_day.month.numeric(),
            month_day.day_index + 1,
            day_seconds.getHoursIntoDay(),
            day_seconds.getMinutesIntoHour(),
            day_seconds.getSecondsIntoMinute(),
            ms,
            event_level.asText(),
            @tagName(scope),
        }) catch return;

        // Print the formatted message
        writer.print(format, args) catch return;

        // Newline and flush
        writer.writeAll("\n") catch return;
        writer.flush() catch return;
    }

    /// Map std.log.Level to our Level
    fn mapLevel(level: std.log.Level) Level {
        return switch (level) {
            .debug => .debug,
            .info => .info,
            .warn => .warn,
            .err => .err,
        };
    }
};

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;

/// Test writer that captures output
const TestWriter = struct {
    io_writer: std.Io.Writer.Allocating,

    fn init(allocator: std.mem.Allocator) TestWriter {
        return .{
            .io_writer = std.Io.Writer.Allocating.init(allocator),
        };
    }

    fn deinit(self: *TestWriter) void {
        self.io_writer.deinit();
    }

    fn writer(self: *TestWriter) *std.Io.Writer {
        return &self.io_writer.writer;
    }

    fn getOutput(self: *TestWriter) []const u8 {
        return self.io_writer.written();
    }

    fn reset(self: *TestWriter) void {
        self.io_writer.clearRetainingCapacity();
    }
};

test "StdLogAdapter: formats log message correctly" {
    var tw = TestWriter.init(testing.allocator);
    defer tw.deinit();

    var bus = EventBus.init(tw.writer());
    bus.setLevel(.debug);

    StdLogAdapter.init(&bus);
    defer StdLogAdapter.deinit();

    // Call logFn directly since we can't override std_options in tests
    StdLogAdapter.logFn(.info, .test_scope, "hello {s}", .{"world"});

    const output = tw.getOutput();
    try testing.expect(std.mem.containsAtLeast(u8, output, 1, "[INFO]"));
    try testing.expect(std.mem.containsAtLeast(u8, output, 1, "test_scope:"));
    try testing.expect(std.mem.containsAtLeast(u8, output, 1, "hello world"));
}

test "StdLogAdapter: respects level filtering" {
    var tw = TestWriter.init(testing.allocator);
    defer tw.deinit();

    var bus = EventBus.init(tw.writer());
    bus.setLevel(.warn); // Only warn and above

    StdLogAdapter.init(&bus);
    defer StdLogAdapter.deinit();

    StdLogAdapter.logFn(.debug, .test_scope, "debug message", .{});
    StdLogAdapter.logFn(.info, .test_scope, "info message", .{});
    StdLogAdapter.logFn(.warn, .test_scope, "warn message", .{});
    StdLogAdapter.logFn(.err, .test_scope, "error message", .{});

    const output = tw.getOutput();
    try testing.expect(!std.mem.containsAtLeast(u8, output, 1, "debug message"));
    try testing.expect(!std.mem.containsAtLeast(u8, output, 1, "info message"));
    try testing.expect(std.mem.containsAtLeast(u8, output, 1, "warn message"));
    try testing.expect(std.mem.containsAtLeast(u8, output, 1, "error message"));
}

test "StdLogAdapter: maps levels correctly" {
    try testing.expectEqual(Level.debug, StdLogAdapter.mapLevel(.debug));
    try testing.expectEqual(Level.info, StdLogAdapter.mapLevel(.info));
    try testing.expectEqual(Level.warn, StdLogAdapter.mapLevel(.warn));
    try testing.expectEqual(Level.err, StdLogAdapter.mapLevel(.err));
}

test "StdLogAdapter: routes errors to err_writer" {
    var stdout_tw = TestWriter.init(testing.allocator);
    defer stdout_tw.deinit();

    var stderr_tw = TestWriter.init(testing.allocator);
    defer stderr_tw.deinit();

    var bus = EventBus.initDual(stdout_tw.writer(), stderr_tw.writer());
    bus.setLevel(.debug);

    StdLogAdapter.init(&bus);
    defer StdLogAdapter.deinit();

    StdLogAdapter.logFn(.info, .test_scope, "info goes to stdout", .{});
    StdLogAdapter.logFn(.err, .test_scope, "error goes to stderr", .{});

    const stdout_output = stdout_tw.getOutput();
    const stderr_output = stderr_tw.getOutput();

    try testing.expect(std.mem.containsAtLeast(u8, stdout_output, 1, "info goes to stdout"));
    try testing.expect(!std.mem.containsAtLeast(u8, stdout_output, 1, "error goes to stderr"));

    try testing.expect(!std.mem.containsAtLeast(u8, stderr_output, 1, "info goes to stdout"));
    try testing.expect(std.mem.containsAtLeast(u8, stderr_output, 1, "error goes to stderr"));
}
