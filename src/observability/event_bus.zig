const std = @import("std");
const Level = @import("level.zig").Level;
const Span = @import("span.zig").Span;

/// Derive event name from type name
/// UserCreated -> user.created
/// PatternGenerationStarted -> pattern.generation.started
fn eventName(comptime T: type) []const u8 {
    const type_name = @typeName(T);

    // Find the last component after any dots (module path)
    const start = comptime blk: {
        var s: usize = 0;
        for (type_name, 0..) |c, i| {
            if (c == '.') s = i + 1;
        }
        break :blk s;
    };

    const name = type_name[start..];

    // Convert PascalCase to snake.case at comptime
    const result = comptime blk: {
        var buf: [256]u8 = undefined;
        var len: usize = 0;
        var prev_was_upper = false;

        for (name) |c| {
            if (c >= 'A' and c <= 'Z') {
                // Insert dot before uppercase (if not first char and prev wasn't upper)
                if (len > 0 and !prev_was_upper) {
                    buf[len] = '.';
                    len += 1;
                }
                buf[len] = c + 32; // toLowerCase
                len += 1;
                prev_was_upper = true;
            } else {
                buf[len] = c;
                len += 1;
                prev_was_upper = false;
            }
        }

        break :blk buf[0..len].*;
    };

    return &result;
}

/// EventBus emits structured events for observability.
/// Events are structs that describe what happened - the EventBus formats and outputs them.
///
/// Usage:
/// ```
/// const events = @import("observability");
///
/// // Simple event
/// bus.info(UserLoggedIn{ .username = "alice" });
///
/// // Timed operation with span
/// var span = bus.started(.info, RequestStarted{ .path = "/api" });
/// defer span.completed(RequestCompleted{ .status = 200 });
///
/// // Events within the span get timing automatically
/// bus.withSpan(&span).info(StepCompleted{ .step = "validation" });
/// ```
/// Wrapper that owns stdout/stderr writers with buffers.
/// Routes error-level events to stderr, everything else to stdout.
pub const StdioEventBus = struct {
    stdout_writer: std.fs.File.Writer,
    stderr_writer: std.fs.File.Writer,
    bus: EventBus,

    /// Buffers for writers - must be kept alive with the struct
    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;

    pub fn init() StdioEventBus {
        var self: StdioEventBus = undefined;
        self.stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
        self.stderr_writer = std.fs.File.stderr().writer(&stderr_buf);
        self.bus = EventBus.initDual(&self.stdout_writer.interface, &self.stderr_writer.interface);
        return self;
    }

    /// Get a pointer to the EventBus for use
    pub fn eventBus(self: *StdioEventBus) *EventBus {
        return &self.bus;
    }
};

pub const EventBus = struct {
    /// Writer for non-error events (debug, info, warn)
    writer: *std.Io.Writer,
    /// Writer for error events (defaults to same as writer if not set)
    err_writer: *std.Io.Writer,
    min_level: Level,
    current_span: ?*const Span,

    /// Initialize with a single std.Io.Writer for all levels
    pub fn init(writer: *std.Io.Writer) EventBus {
        return .{
            .writer = writer,
            .err_writer = writer,
            .min_level = .info,
            .current_span = null,
        };
    }

    /// Initialize with separate writers: stdout for non-errors, stderr for errors
    pub fn initDual(stdout_writer: *std.Io.Writer, stderr_writer: *std.Io.Writer) EventBus {
        return .{
            .writer = stdout_writer,
            .err_writer = stderr_writer,
            .min_level = .info,
            .current_span = null,
        };
    }

    /// Set minimum log level
    pub fn setLevel(self: *EventBus, level: Level) void {
        self.min_level = level;
    }

    /// Create a child EventBus with a span context
    pub fn withSpan(self: EventBus, span: *const Span) EventBus {
        return .{
            .writer = self.writer,
            .err_writer = self.err_writer,
            .min_level = self.min_level,
            .current_span = span,
        };
    }

    /// Get the appropriate writer for the given level
    fn writerForLevel(self: *EventBus, level: Level) *std.Io.Writer {
        return if (level == .err) self.err_writer else self.writer;
    }

    /// Start a timed span. Returns a SpanGuard that should be deferred.
    /// The started event is emitted immediately.
    /// The event type name becomes the span name (e.g., BatchProcessingStarted -> batch.processing)
    pub fn started(
        self: *EventBus,
        comptime level: Level,
        event: anytype,
    ) SpanGuard(@TypeOf(event)) {
        const full_name = comptime eventName(@TypeOf(event));
        // Remove ".started" suffix if present to get base span name
        const span_name = comptime blk: {
            const suffix = ".started";
            if (std.mem.endsWith(u8, full_name, suffix)) {
                break :blk full_name[0 .. full_name.len - suffix.len];
            }
            break :blk full_name;
        };

        var guard = SpanGuard(@TypeOf(event)){
            .bus = self,
            .span = .{
                .id = Span.generateSpanId(),
                .name = span_name,
                .level = level,
                .start_time = std.time.microTimestamp(),
                .parent = self.current_span,
            },
        };

        // Emit the started event
        guard.bus.emitInternal(level, &guard.span, event);

        return guard;
    }

    /// Emit a debug event
    pub fn debug(self: *EventBus, event: anytype) void {
        self.emit(.debug, event);
    }

    /// Emit an info event
    pub fn info(self: *EventBus, event: anytype) void {
        self.emit(.info, event);
    }

    /// Emit a warning event
    pub fn warn(self: *EventBus, event: anytype) void {
        self.emit(.warn, event);
    }

    /// Emit an error event
    pub fn err(self: *EventBus, event: anytype) void {
        self.emit(.err, event);
    }

    /// Emit an event at the specified level
    pub fn emit(self: *EventBus, level: Level, event: anytype) void {
        self.emitInternal(level, self.current_span, event);
    }

    fn emitInternal(
        self: *EventBus,
        level: Level,
        span: ?*const Span,
        event: anytype,
    ) void {
        const name = comptime eventName(@TypeOf(event));
        // Check level filter
        if (@intFromEnum(level) < @intFromEnum(self.min_level)) {
            return;
        }

        // Select writer based on level (errors go to err_writer)
        const writer = self.writerForLevel(level);

        // Timestamp (HH:MM:SS)
        const timestamp = std.time.timestamp();
        const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = @intCast(timestamp) };
        const day_seconds = epoch_seconds.getDaySeconds();

        writer.print("{d:0>2}:{d:0>2}:{d:0>2} [{s}] {s}", .{
            day_seconds.getHoursIntoDay(),
            day_seconds.getMinutesIntoHour(),
            day_seconds.getSecondsIntoMinute(),
            level.asText(),
            name,
        }) catch return;

        // Event fields
        const T = @TypeOf(event);
        const fields = @typeInfo(T).@"struct".fields;
        inline for (fields) |field| {
            const value = @field(event, field.name);
            writeField(writer, field.name, value);
        }

        // Span ID and elapsed time if we have a span
        if (span) |s| {
            var span_id_buf: [16]u8 = undefined;
            const span_id = Span.formatSpanId(s.id, &span_id_buf);
            writer.print(" span_id={s}", .{span_id}) catch return;

            var elapsed_buf: [32]u8 = undefined;
            const elapsed = s.formatElapsed(&elapsed_buf);
            writer.print(" elapsed={s}", .{elapsed}) catch return;
        }

        // Newline and flush
        writer.writeAll("\n") catch return;
        writer.flush() catch return;
    }

    fn writeField(writer: *std.Io.Writer, name: []const u8, value: anytype) void {
        const T = @TypeOf(value);

        if (T == []const u8 or T == []u8) {
            writer.print(" {s}=\"{s}\"", .{ name, value }) catch return;
        } else if (@typeInfo(T) == .pointer) {
            // Handle pointer to array (like *const [N]u8)
            const child = @typeInfo(T).pointer.child;
            if (@typeInfo(child) == .array) {
                const elem_type = @typeInfo(child).array.child;
                if (elem_type == u8) {
                    writer.print(" {s}=\"{s}\"", .{ name, value }) catch return;
                    return;
                }
            }
            writer.print(" {s}={any}", .{ name, value }) catch return;
        } else if (@typeInfo(T) == .int or @typeInfo(T) == .comptime_int) {
            writer.print(" {s}={d}", .{ name, value }) catch return;
        } else if (@typeInfo(T) == .float or @typeInfo(T) == .comptime_float) {
            writer.print(" {s}={d:.2}", .{ name, value }) catch return;
        } else if (@typeInfo(T) == .bool) {
            writer.print(" {s}={}", .{ name, value }) catch return;
        } else if (@typeInfo(T) == .@"enum") {
            writer.print(" {s}={s}", .{ name, @tagName(value) }) catch return;
        } else if (@typeInfo(T) == .optional) {
            if (value) |v| {
                writeField(writer, name, v);
            } else {
                writer.print(" {s}=null", .{name}) catch return;
            }
        } else if (@typeInfo(T) == .error_union) {
            if (value) |v| {
                writeField(writer, name, v);
            } else |e| {
                writer.print(" {s}={s}", .{ name, @errorName(e) }) catch return;
            }
        } else if (T == anyerror or @typeInfo(T) == .error_set) {
            writer.print(" {s}={s}", .{ name, @errorName(value) }) catch return;
        } else {
            writer.print(" {s}={any}", .{ name, value }) catch return;
        }
    }
};

/// SpanGuard wraps a span and provides scoped completion
/// Generic over the started event type to derive the span name at comptime
pub fn SpanGuard(comptime StartedEvent: type) type {
    const full_name = comptime eventName(StartedEvent);
    // Remove ".started" suffix if present to get base span name
    const span_name = comptime blk: {
        const suffix = ".started";
        if (std.mem.endsWith(u8, full_name, suffix)) {
            break :blk full_name[0 .. full_name.len - suffix.len];
        }
        break :blk full_name;
    };

    return struct {
        bus: *EventBus,
        span: Span,

        const Self = @This();

        /// Get an EventBus that includes this span's context
        pub fn eventBus(self: *Self) EventBus {
            return self.bus.withSpan(&self.span);
        }

        /// Complete the span with a completion event
        pub fn completed(self: *Self, event: anytype) void {
            _ = span_name; // Use the comptime span_name
            self.bus.emitInternal(
                self.span.level,
                &self.span,
                event,
            );
        }

        /// Complete the span without an event (just log completion)
        pub fn done(self: *Self) void {
            const CompletedEvent = struct {};
            self.bus.emitInternal(
                self.span.level,
                &self.span,
                CompletedEvent{},
            );
        }
    };
}

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;

/// Test writer that captures output to an ArrayList
const TestWriter = struct {
    output: std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    io_writer: std.Io.Writer.Allocating,

    fn init(allocator: std.mem.Allocator) TestWriter {
        return .{
            .output = .{},
            .allocator = allocator,
            .io_writer = std.Io.Writer.Allocating.init(allocator),
        };
    }

    fn deinit(self: *TestWriter) void {
        self.output.deinit(self.allocator);
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

test "EventBus: simple info event" {
    var tw = TestWriter.init(testing.allocator);
    defer tw.deinit();

    var bus = EventBus.init(tw.writer());
    bus.setLevel(.debug);

    const UserLoggedIn = struct {
        username: []const u8,
        method: []const u8,
    };

    bus.info(UserLoggedIn{ .username = "alice", .method = "oauth" });

    const output = tw.getOutput();
    try testing.expect(std.mem.containsAtLeast(u8, output, 1, "[INFO]"));
    try testing.expect(std.mem.containsAtLeast(u8, output, 1, "user.logged.in"));
    try testing.expect(std.mem.containsAtLeast(u8, output, 1, "username=\"alice\""));
    try testing.expect(std.mem.containsAtLeast(u8, output, 1, "method=\"oauth\""));
}

test "EventBus: level filtering" {
    var tw = TestWriter.init(testing.allocator);
    defer tw.deinit();

    var bus = EventBus.init(tw.writer());
    bus.setLevel(.warn); // Only warn and above

    const DebugEvent = struct { detail: []const u8 };
    const WarnEvent = struct { message: []const u8 };

    bus.debug(DebugEvent{ .detail = "should not appear" });
    bus.warn(WarnEvent{ .message = "should appear" });

    const output = tw.getOutput();
    try testing.expect(!std.mem.containsAtLeast(u8, output, 1, "should not appear"));
    try testing.expect(std.mem.containsAtLeast(u8, output, 1, "should appear"));
}

test "EventBus: span with timing" {
    var tw = TestWriter.init(testing.allocator);
    defer tw.deinit();

    var bus = EventBus.init(tw.writer());
    bus.setLevel(.debug);

    const BatchProcessingStarted = struct { batch_id: u32 };
    const BatchProcessingCompleted = struct { items_processed: u32 };

    var span = bus.started(.info, BatchProcessingStarted{ .batch_id = 123 });

    // Simulate some work
    std.Thread.sleep(10 * std.time.ns_per_ms);

    span.completed(BatchProcessingCompleted{ .items_processed = 5 });

    const output = tw.getOutput();
    try testing.expect(std.mem.containsAtLeast(u8, output, 1, "batch.processing.started"));
    try testing.expect(std.mem.containsAtLeast(u8, output, 1, "batch_id=123"));
    try testing.expect(std.mem.containsAtLeast(u8, output, 1, "batch.processing.completed"));
    try testing.expect(std.mem.containsAtLeast(u8, output, 1, "items_processed=5"));
    try testing.expect(std.mem.containsAtLeast(u8, output, 1, "elapsed="));
}

test "EventBus: numeric and boolean fields" {
    var tw = TestWriter.init(testing.allocator);
    defer tw.deinit();

    var bus = EventBus.init(tw.writer());
    bus.setLevel(.debug);

    const MetricsEvent = struct {
        count: u32,
        rate: f32,
        success: bool,
    };

    bus.info(MetricsEvent{ .count = 42, .rate = 3.14, .success = true });

    const output = tw.getOutput();
    try testing.expect(std.mem.containsAtLeast(u8, output, 1, "count=42"));
    try testing.expect(std.mem.containsAtLeast(u8, output, 1, "rate=3.14"));
    try testing.expect(std.mem.containsAtLeast(u8, output, 1, "success=true"));
}

test "EventBus: enum fields" {
    var tw = TestWriter.init(testing.allocator);
    defer tw.deinit();

    var bus = EventBus.init(tw.writer());
    bus.setLevel(.debug);

    const Status = enum { pending, running, completed };
    const StatusEvent = struct { status: Status };

    bus.info(StatusEvent{ .status = .running });

    const output = tw.getOutput();
    try testing.expect(std.mem.containsAtLeast(u8, output, 1, "status=running"));
}

test "EventBus: optional fields" {
    var tw = TestWriter.init(testing.allocator);
    defer tw.deinit();

    var bus = EventBus.init(tw.writer());
    bus.setLevel(.debug);

    const OptionalEvent = struct {
        name: []const u8,
        error_msg: ?[]const u8,
    };

    bus.info(OptionalEvent{ .name = "test", .error_msg = null });
    bus.info(OptionalEvent{ .name = "test2", .error_msg = "something failed" });

    const output = tw.getOutput();
    try testing.expect(std.mem.containsAtLeast(u8, output, 1, "error_msg=null"));
    try testing.expect(std.mem.containsAtLeast(u8, output, 1, "error_msg=\"something failed\""));
}

test "eventName: PascalCase to snake.case" {
    const UserCreated = struct {};
    const name1 = eventName(UserCreated);
    // Name will include module path, but should end with the converted name
    try testing.expect(std.mem.endsWith(u8, name1, "user.created"));

    const PatternGenerationStarted = struct {};
    const name2 = eventName(PatternGenerationStarted);
    try testing.expect(std.mem.endsWith(u8, name2, "pattern.generation.started"));
}
