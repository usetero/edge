const std = @import("std");
const policy_provider = @import("../../core/policy_provider.zig");
const policy_source = @import("../../core/policy_source.zig");
const parser = @import("../parser.zig");
const types = @import("../types.zig");
const proto = @import("proto");

const PolicyCallback = policy_provider.PolicyCallback;
const PolicyUpdate = policy_provider.PolicyUpdate;
const SourceType = policy_source.SourceType;
const SyncRequest = proto.policy.SyncRequest;
const SyncResponse = proto.policy.SyncResponse;
const ClientMetadata = proto.policy.ClientMetadata;

/// HTTP-based policy provider that polls a remote endpoint
pub const HttpProvider = struct {
    allocator: std.mem.Allocator,
    http_client: std.http.Client,
    config_url: []const u8,
    poll_interval_ns: u64,
    callback: ?PolicyCallback,
    poll_thread: ?std.Thread,
    shutdown_flag: std.atomic.Value(bool),
    last_etag: ?[]u8,

    // Edge metadata for sync requests
    edge_id: []const u8,
    version: []const u8,
    workspace_id: []const u8,
    last_sync_timestamp: i64,

    pub fn init(
        allocator: std.mem.Allocator,
        config_url: []const u8,
        poll_interval_seconds: u64,
        workspace_id: []const u8,
    ) !*HttpProvider {
        const self = try allocator.create(HttpProvider);
        errdefer allocator.destroy(self);

        const url_copy = try allocator.dupe(u8, config_url);
        errdefer allocator.free(url_copy);

        // Generate edge ID (could be from config or generated)
        // For now, use a simple UUID-like identifier
        var edge_id_buf: [36]u8 = undefined;
        const edge_id = try std.fmt.bufPrint(&edge_id_buf, "edge-{d}", .{std.time.milliTimestamp()});
        const edge_id_copy = try allocator.dupe(u8, edge_id);
        errdefer allocator.free(edge_id_copy);

        const version_copy = try allocator.dupe(u8, "0.1.0");
        errdefer allocator.free(version_copy);

        const workspace_id_copy = try allocator.dupe(u8, workspace_id);
        errdefer allocator.free(workspace_id_copy);

        self.* = .{
            .allocator = allocator,
            .http_client = std.http.Client{ .allocator = allocator },
            .config_url = url_copy,
            .poll_interval_ns = poll_interval_seconds * std.time.ns_per_s,
            .callback = null,
            .poll_thread = null,
            .shutdown_flag = std.atomic.Value(bool).init(false),
            .last_etag = null,
            .edge_id = edge_id_copy,
            .version = version_copy,
            .workspace_id = workspace_id_copy,
            .last_sync_timestamp = 0,
        };

        return self;
    }

    pub fn subscribe(self: *HttpProvider, callback: PolicyCallback) !void {
        self.callback = callback;

        // Initial fetch and notify (non-fatal if it fails)
        self.fetchAndNotify() catch |err| {
            std.log.warn("Initial HTTP policy fetch failed: {}. Will retry on next poll.", .{err});
        };

        // Start polling
        self.poll_thread = try std.Thread.spawn(.{}, pollLoop, .{self});
    }

    pub fn shutdown(self: *HttpProvider) void {
        self.shutdown_flag.store(true, .release);

        if (self.poll_thread) |thread| {
            thread.join();
            self.poll_thread = null;
        }
    }

    pub fn deinit(self: *HttpProvider) void {
        // Ensure shutdown is called first
        self.shutdown();

        if (self.last_etag) |etag| {
            self.allocator.free(etag);
        }

        self.http_client.deinit();
        self.allocator.free(self.config_url);
        self.allocator.free(self.edge_id);
        self.allocator.free(self.version);
        self.allocator.free(self.workspace_id);
        self.allocator.destroy(self);
    }

    fn pollLoop(self: *HttpProvider) void {
        while (!self.shutdown_flag.load(.acquire)) {
            // Sleep in small increments so we can respond quickly to shutdown
            const sleep_increment_ns = 100 * std.time.ns_per_ms; // 100ms
            var slept_ns: u64 = 0;

            while (slept_ns < self.poll_interval_ns and !self.shutdown_flag.load(.acquire)) {
                std.Thread.sleep(sleep_increment_ns);
                slept_ns += sleep_increment_ns;
            }

            if (self.shutdown_flag.load(.acquire)) break;

            self.fetchAndNotify() catch |err| {
                std.log.err("HTTP provider fetch failed from {s}: {}", .{ self.config_url, err });
            };
        }
    }

    fn fetchAndNotify(self: *HttpProvider) !void {
        std.log.debug("Fetching policies from HTTP: {s}", .{self.config_url});

        var new_etag: ?[]u8 = null;
        var maybe_parsed = try self.fetchPolicies(&new_etag);

        if (maybe_parsed) |*parsed| {
            defer parsed.deinit();

            const response = parsed.value;

            // Update ETag
            if (self.last_etag) |old_etag| {
                self.allocator.free(old_etag);
            }
            self.last_etag = new_etag;

            // Update last sync timestamp
            self.last_sync_timestamp = @intCast(response.sync_timestamp_unix_nano);

            // Extract policies from response
            if (response.policy_set) |policy_set| {
                if (self.callback) |cb| {
                    try cb.call(.{
                        .policies = policy_set.policies.items,
                        .source = .http,
                    });
                }

                std.log.info("Loaded {} policies from {s} (sync_timestamp: {})", .{
                    policy_set.policies.items.len,
                    self.config_url,
                    response.sync_timestamp_unix_nano,
                });
            } else {
                std.log.warn("Received SyncResponse with no policy_set", .{});
            }
        } else {
            // 304 Not Modified
            std.log.debug("Policies unchanged (304 Not Modified)", .{});
        }
    }

    fn fetchPolicies(self: *HttpProvider, out_etag: *?[]u8) !?std.json.Parsed(SyncResponse) {
        const uri = try std.Uri.parse(self.config_url);

        // Create SyncRequest with metadata
        const sync_request = SyncRequest{
            .client_metadata = ClientMetadata{
                .last_sync_timestamp_unix_nano = @intCast(self.last_sync_timestamp),
                .resource_attributes = .{},
            },
        };

        // Encode SyncRequest to JSON
        const request_body = try sync_request.jsonEncode(.{}, self.allocator);
        defer self.allocator.free(request_body);

        std.log.debug("Sending SyncRequest: {s}", .{request_body});

        // Prepare headers
        var headers_buffer: [2]std.http.Header = undefined;
        var headers_count: usize = 0;

        headers_buffer[headers_count] = .{
            .name = "content-type",
            .value = "application/json",
        };
        headers_count += 1;

        if (self.last_etag) |etag| {
            headers_buffer[headers_count] = .{
                .name = "if-none-match",
                .value = etag,
            };
            headers_count += 1;
        }

        const extra_headers = headers_buffer[0..headers_count];

        // Create request
        var req = try self.http_client.request(.POST, uri, .{
            .extra_headers = extra_headers,
        });
        defer req.deinit();

        // Send request with body
        try req.sendBodyComplete(@constCast(request_body));

        // Receive response headers
        var response = try req.receiveHead(&.{});

        // Check for 304 Not Modified
        if (response.head.status == .not_modified) {
            std.log.debug("Policies unchanged (304 Not Modified)", .{});
            return null;
        }

        // Check status code
        if (response.head.status != .ok) {
            std.log.err("HTTP sync request to {s} failed with status: {} {s}", .{
                self.config_url,
                @intFromEnum(response.head.status),
                response.head.status.phrase() orelse "Unknown",
            });
            return error.HttpRequestFailed;
        }

        // Extract ETag from response headers
        var it = response.head.iterateHeaders();
        while (it.next()) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "etag")) {
                out_etag.* = try self.allocator.dupe(u8, header.value);
            }
        }

        // Read response body using allocating writer
        var body_writer = std.Io.Writer.Allocating.init(self.allocator);
        defer body_writer.deinit();

        // Buffer for streaming response
        var read_buffer: [4096]u8 = undefined;
        const body_reader = response.reader(&read_buffer);

        // Stream response to allocating writer
        _ = try body_reader.stream(&body_writer.writer, std.io.Limit.limited(std.math.maxInt(usize)));

        const response_body = body_writer.written();

        // Decode SyncResponse from JSON
        const parsed = try SyncResponse.jsonDecode(response_body, .{}, self.allocator);

        return parsed;
    }
};
