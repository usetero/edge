//! Lambda Extensions API Client
//!
//! Implements the AWS Lambda Extensions API for external extensions.
//! See: https://docs.aws.amazon.com/lambda/latest/dg/runtimes-extensions-api.html
//!
//! External extensions run as a separate process alongside the Lambda function.
//! They must:
//! 1. Register with the Extensions API during the init phase
//! 2. Poll for events (INVOKE, SHUTDOWN) in a loop
//! 3. Shut down gracefully when receiving SHUTDOWN event

const std = @import("std");
const o11y = @import("../observability/root.zig");
const EventBus = o11y.EventBus;

// =============================================================================
// Observability Events
// =============================================================================

const ExtensionRegistering = struct { name: []const u8 };
const ExtensionRegistered = struct { identifier: []const u8 };
const ExtensionRegistrationFailed = struct { status: u16, err: []const u8 };
const ExtensionEventReceived = struct { event_type: []const u8 };
const ExtensionEventPollFailed = struct { err: []const u8 };
const ExtensionShutdownReceived = struct { reason: []const u8, deadline_ms: u64 };

// =============================================================================
// Types
// =============================================================================

/// Lambda extension event types
pub const EventType = enum {
    invoke,
    shutdown,
};

/// Shutdown reason from Lambda
pub const ShutdownReason = enum {
    spindown, // Normal shutdown (SPINDOWN)
    timeout, // Extension timeout (TIMEOUT)
    failure, // Extension failure (FAILURE)
    sandbox_terminated, // Sandbox terminated (from RIE)
    unknown,
};

/// Event received from Lambda Extensions API
pub const ExtensionEvent = union(EventType) {
    invoke: InvokeEvent,
    shutdown: ShutdownEvent,
};

pub const InvokeEvent = struct {
    request_id: []const u8,
    invoked_function_arn: []const u8,
    deadline_ms: u64,
};

pub const ShutdownEvent = struct {
    reason: ShutdownReason,
    deadline_ms: u64,
};

// =============================================================================
// Extensions API Client
// =============================================================================

pub const ExtensionClient = struct {
    allocator: std.mem.Allocator,
    http_client: std.http.Client,
    runtime_api: []const u8, // e.g., "127.0.0.1:9001"
    extension_id: ?[]const u8,
    extension_name: []const u8,
    bus: *EventBus,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        bus: *EventBus,
        extension_name: []const u8,
    ) !*Self {
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        // Get runtime API endpoint from environment
        const runtime_api = std.posix.getenv("AWS_LAMBDA_RUNTIME_API") orelse
            return error.MissingRuntimeApiEnv;

        const runtime_api_copy = try allocator.dupe(u8, runtime_api);
        errdefer allocator.free(runtime_api_copy);

        const name_copy = try allocator.dupe(u8, extension_name);

        self.* = .{
            .allocator = allocator,
            .http_client = std.http.Client{ .allocator = allocator },
            .runtime_api = runtime_api_copy,
            .extension_id = null,
            .extension_name = name_copy,
            .bus = bus,
        };

        return self;
    }

    pub fn deinit(self: *Self) void {
        if (self.extension_id) |id| self.allocator.free(id);
        self.allocator.free(self.extension_name);
        self.allocator.free(self.runtime_api);
        self.http_client.deinit();
        self.allocator.destroy(self);
    }

    /// Register this extension with the Lambda Extensions API.
    /// Must be called before the init phase completes.
    pub fn register(self: *Self) !void {
        self.bus.info(ExtensionRegistering{ .name = self.extension_name });

        // Build registration URL
        var url_buf: [256]u8 = undefined;
        const url = try std.fmt.bufPrint(
            &url_buf,
            "http://{s}/2020-01-01/extension/register",
            .{self.runtime_api},
        );

        // Registration payload - subscribe to INVOKE and SHUTDOWN events
        var payload_buf: [64]u8 = undefined;
        const payload = "{\"events\":[\"INVOKE\",\"SHUTDOWN\"]}";
        @memcpy(payload_buf[0..payload.len], payload);
        const payload_slice = payload_buf[0..payload.len];

        // Use lower-level request API to access response headers
        const uri = try std.Uri.parse(url);

        // Extra headers for registration
        const extra_headers = [_]std.http.Header{
            .{ .name = "Lambda-Extension-Name", .value = self.extension_name },
            .{ .name = "Content-Type", .value = "application/json" },
        };

        var req = try self.http_client.request(.POST, uri, .{
            .extra_headers = &extra_headers,
        });
        defer req.deinit();

        // Set content length and send the request body
        req.transfer_encoding = .{ .content_length = payload_slice.len };
        try req.sendBodyComplete(payload_slice);

        // Receive response headers
        var recv_buffer: [4096]u8 = undefined;
        var response = try req.receiveHead(&recv_buffer);

        if (response.head.status != .ok) {
            self.bus.err(ExtensionRegistrationFailed{
                .status = @intFromEnum(response.head.status),
                .err = "registration failed",
            });
            return error.RegistrationFailed;
        }

        // Extract Lambda-Extension-Identifier from response headers
        const extension_id = blk: {
            var it = response.head.iterateHeaders();
            while (it.next()) |header| {
                if (std.ascii.eqlIgnoreCase(header.name, "lambda-extension-identifier")) {
                    break :blk header.value;
                }
            }
            break :blk null;
        };

        if (extension_id) |id| {
            self.extension_id = try self.allocator.dupe(u8, id);
            self.bus.info(ExtensionRegistered{ .identifier = self.extension_id.? });
        } else {
            return error.MissingExtensionId;
        }
    }

    /// Poll for the next event from Lambda. This call blocks until an event
    /// is available. There is no timeout - Lambda controls when events arrive.
    pub fn nextEvent(self: *Self, arena: std.mem.Allocator) !ExtensionEvent {
        const ext_id = self.extension_id orelse return error.NotRegistered;

        // Build event next URL
        var url_buf: [256]u8 = undefined;
        const url = try std.fmt.bufPrint(
            &url_buf,
            "http://{s}/2020-01-01/extension/event/next",
            .{self.runtime_api},
        );

        const headers = [_]std.http.Header{
            .{ .name = "Lambda-Extension-Identifier", .value = ext_id },
        };

        var body: std.Io.Writer.Allocating = .init(arena);
        // Note: don't defer deinit - arena owns the memory

        const result = self.http_client.fetch(.{
            .location = .{ .url = url },
            .method = .GET,
            .extra_headers = &headers,
            .response_writer = &body.writer,
        }) catch |err| {
            self.bus.err(ExtensionEventPollFailed{ .err = @errorName(err) });
            return err;
        };

        if (result.status != .ok) {
            return error.EventPollFailed;
        }

        // Parse event JSON
        const response_body = body.written();
        return try parseEvent(arena, response_body, self.bus);
    }

    fn parseEvent(allocator: std.mem.Allocator, body: []const u8, bus: *EventBus) !ExtensionEvent {
        const parsed = try std.json.parseFromSlice(
            EventJson,
            allocator,
            body,
            .{ .ignore_unknown_fields = true },
        );
        defer parsed.deinit();

        const event = parsed.value;

        bus.debug(ExtensionEventReceived{ .event_type = event.eventType });

        if (std.mem.eql(u8, event.eventType, "INVOKE")) {
            return .{ .invoke = .{
                .request_id = try allocator.dupe(u8, event.requestId orelse ""),
                .invoked_function_arn = try allocator.dupe(u8, event.invokedFunctionArn orelse ""),
                .deadline_ms = event.deadlineMs orelse 0,
            } };
        } else if (std.mem.eql(u8, event.eventType, "SHUTDOWN")) {
            const reason = parseShutdownReason(event.shutdownReason);
            bus.info(ExtensionShutdownReceived{
                .reason = event.shutdownReason orelse "unknown",
                .deadline_ms = event.deadlineMs orelse 0,
            });
            return .{ .shutdown = .{
                .reason = reason,
                .deadline_ms = event.deadlineMs orelse 0,
            } };
        }

        return error.UnknownEventType;
    }

    fn parseShutdownReason(reason: ?[]const u8) ShutdownReason {
        const r = reason orelse return .unknown;
        // Lambda API uses uppercase, RIE uses mixed case
        if (std.ascii.eqlIgnoreCase(r, "spindown")) return .spindown;
        if (std.ascii.eqlIgnoreCase(r, "timeout")) return .timeout;
        if (std.ascii.eqlIgnoreCase(r, "failure")) return .failure;
        if (std.ascii.eqlIgnoreCase(r, "sandboxterminated")) return .sandbox_terminated;
        return .unknown;
    }
};

// JSON schema for event parsing
const EventJson = struct {
    eventType: []const u8,
    requestId: ?[]const u8 = null,
    invokedFunctionArn: ?[]const u8 = null,
    deadlineMs: ?u64 = null,
    shutdownReason: ?[]const u8 = null,
};

// =============================================================================
// Tests
// =============================================================================

test "parseShutdownReason" {
    try std.testing.expectEqual(ShutdownReason.spindown, ExtensionClient.parseShutdownReason("spindown"));
    try std.testing.expectEqual(ShutdownReason.spindown, ExtensionClient.parseShutdownReason("SPINDOWN"));
    try std.testing.expectEqual(ShutdownReason.timeout, ExtensionClient.parseShutdownReason("timeout"));
    try std.testing.expectEqual(ShutdownReason.timeout, ExtensionClient.parseShutdownReason("TIMEOUT"));
    try std.testing.expectEqual(ShutdownReason.failure, ExtensionClient.parseShutdownReason("failure"));
    try std.testing.expectEqual(ShutdownReason.failure, ExtensionClient.parseShutdownReason("FAILURE"));
    try std.testing.expectEqual(ShutdownReason.sandbox_terminated, ExtensionClient.parseShutdownReason("SandboxTerminated"));
    try std.testing.expectEqual(ShutdownReason.unknown, ExtensionClient.parseShutdownReason("other"));
    try std.testing.expectEqual(ShutdownReason.unknown, ExtensionClient.parseShutdownReason(null));
}

test "EventJson parsing" {
    const allocator = std.testing.allocator;

    // Test INVOKE event
    const invoke_json =
        \\{"eventType":"INVOKE","requestId":"abc-123","invokedFunctionArn":"arn:aws:lambda:us-east-1:123456789:function:test","deadlineMs":1234567890}
    ;
    const invoke_parsed = try std.json.parseFromSlice(EventJson, allocator, invoke_json, .{});
    defer invoke_parsed.deinit();

    try std.testing.expectEqualStrings("INVOKE", invoke_parsed.value.eventType);
    try std.testing.expectEqualStrings("abc-123", invoke_parsed.value.requestId.?);

    // Test SHUTDOWN event
    const shutdown_json =
        \\{"eventType":"SHUTDOWN","shutdownReason":"spindown","deadlineMs":1234567890}
    ;
    const shutdown_parsed = try std.json.parseFromSlice(EventJson, allocator, shutdown_json, .{});
    defer shutdown_parsed.deinit();

    try std.testing.expectEqualStrings("SHUTDOWN", shutdown_parsed.value.eventType);
    try std.testing.expectEqualStrings("spindown", shutdown_parsed.value.shutdownReason.?);
}
