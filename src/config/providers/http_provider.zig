const std = @import("std");
const policy_provider = @import("../../core/policy_provider.zig");
const policy_source = @import("../../core/policy_source.zig");
const parser = @import("../parser.zig");
const types = @import("../types.zig");
const proto = @import("proto");
const protobuf = @import("protobuf");
const o11y = @import("../../observability/root.zig");

const PolicyCallback = policy_provider.PolicyCallback;
const PolicyUpdate = policy_provider.PolicyUpdate;
const SourceType = policy_source.SourceType;
const SyncRequest = proto.policy.SyncRequest;
const SyncResponse = proto.policy.SyncResponse;
const ClientMetadata = proto.policy.ClientMetadata;
const PolicySyncStatus = proto.policy.PolicySyncStatus;
const PolicyType = proto.policy.PolicyType;
const KeyValue = proto.common.KeyValue;
const AnyValue = proto.common.AnyValue;
const ServiceMetadata = types.ServiceMetadata;
const EventBus = o11y.EventBus;

// =============================================================================
// Observability Events
// =============================================================================

const PolicyErrorRecordFailed = struct { policy_id: []const u8 };
const HttpInitialFetchFailed = struct { err: []const u8 };
const HttpFetchFailed = struct { url: []const u8, err: []const u8 };
const HttpPoliciesUnchanged = struct { reason: []const u8 };
const HttpPolicyHashUpdated = struct { hash: []const u8 };
const HttpPoliciesLoaded = struct { count: usize, url: []const u8, sync_timestamp: u64 };
const HttpSyncRequestFailed = struct { url: []const u8, status: u16 };
const HTTPNotModified = struct {};
const HTTPFetchStarted = struct {};
const HTTPFetchCompleted = struct {};

/// Tracks status for a specific policy (hits, misses, errors)
const PolicyStatusRecord = struct {
    hits: i64 = 0,
    misses: i64 = 0,
    errors: std.ArrayListUnmanaged([]const u8) = .{},

    fn deinit(self: *PolicyStatusRecord, allocator: std.mem.Allocator) void {
        for (self.errors.items) |msg| {
            allocator.free(msg);
        }
        self.errors.deinit(allocator);
    }
};

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

    // Service metadata for sync requests (not owned, references config)
    service: ServiceMetadata,
    workspace_id: []const u8,
    last_sync_timestamp: u64,
    last_successful_hash: ?[]u8,

    // Policy status tracking: maps policy_id -> PolicyStatusRecord
    // Used to report hits/misses/errors encountered when applying policies
    policy_statuses: std.StringHashMapUnmanaged(PolicyStatusRecord),

    // Mutex for thread-safe access to synced state
    sync_state_mutex: std.Thread.Mutex,

    // Event bus for observability
    bus: *EventBus,

    pub fn init(
        allocator: std.mem.Allocator,
        bus: *EventBus,
        config_url: []const u8,
        poll_interval_seconds: u64,
        workspace_id: []const u8,
        service: ServiceMetadata,
    ) !*HttpProvider {
        const self = try allocator.create(HttpProvider);
        errdefer allocator.destroy(self);

        const url_copy = try allocator.dupe(u8, config_url);
        errdefer allocator.free(url_copy);

        self.* = .{
            .allocator = allocator,
            .http_client = std.http.Client{ .allocator = allocator },
            .config_url = url_copy,
            .poll_interval_ns = poll_interval_seconds * std.time.ns_per_s,
            .callback = null,
            .poll_thread = null,
            .shutdown_flag = std.atomic.Value(bool).init(false),
            .last_etag = null,
            .service = service,
            .workspace_id = workspace_id,
            .last_sync_timestamp = 0,
            .last_successful_hash = null,
            .policy_statuses = .{},
            .sync_state_mutex = .{},
            .bus = bus,
        };

        return self;
    }

    /// Record the hash from a successful sync.
    /// This hash will be sent in subsequent sync requests.
    pub fn recordSyncedHash(self: *HttpProvider, hash: []const u8) !void {
        self.sync_state_mutex.lock();
        defer self.sync_state_mutex.unlock();

        // Free old hash if exists
        if (self.last_successful_hash) |old_hash| {
            self.allocator.free(old_hash);
        }

        self.last_successful_hash = try self.allocator.dupe(u8, hash);
    }

    /// Record an error for a specific policy.
    /// These errors will be sent in subsequent sync requests.
    /// Conforms to PolicyProvider interface (void return, logs errors internally).
    pub fn recordPolicyError(self: *HttpProvider, policy_id: []const u8, error_message: []const u8) void {
        self.sync_state_mutex.lock();
        defer self.sync_state_mutex.unlock();

        const msg_copy = self.allocator.dupe(u8, error_message) catch {
            self.bus.err(PolicyErrorRecordFailed{ .policy_id = policy_id });
            return;
        };

        if (self.policy_statuses.getPtr(policy_id)) |record| {
            // Append to existing error list
            record.errors.append(self.allocator, msg_copy) catch {
                self.allocator.free(msg_copy);
                self.bus.err(PolicyErrorRecordFailed{ .policy_id = policy_id });
                return;
            };
        } else {
            // Create new entry
            const id_copy = self.allocator.dupe(u8, policy_id) catch {
                self.allocator.free(msg_copy);
                self.bus.err(PolicyErrorRecordFailed{ .policy_id = policy_id });
                return;
            };

            var record = PolicyStatusRecord{};
            record.errors.append(self.allocator, msg_copy) catch {
                self.allocator.free(msg_copy);
                self.allocator.free(id_copy);
                self.bus.err(PolicyErrorRecordFailed{ .policy_id = policy_id });
                return;
            };

            self.policy_statuses.put(self.allocator, id_copy, record) catch {
                self.allocator.free(msg_copy);
                self.allocator.free(id_copy);
                record.deinit(self.allocator);
                self.bus.err(PolicyErrorRecordFailed{ .policy_id = policy_id });
                return;
            };
        }
    }

    /// Clear all recorded policy statuses.
    /// Call this after statuses have been successfully reported to the server.
    pub fn clearPolicyStatuses(self: *HttpProvider) void {
        self.sync_state_mutex.lock();
        defer self.sync_state_mutex.unlock();

        var it = self.policy_statuses.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.policy_statuses.clearRetainingCapacity();
    }

    pub fn subscribe(self: *HttpProvider, callback: PolicyCallback) !void {
        self.callback = callback;

        // Initial fetch and notify (non-fatal if it fails)
        self.fetchAndNotify() catch |err| {
            self.bus.warn(HttpInitialFetchFailed{ .err = @errorName(err) });
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

        if (self.last_successful_hash) |hash| {
            self.allocator.free(hash);
        }

        // Free policy statuses
        var ps_it = self.policy_statuses.iterator();
        while (ps_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.policy_statuses.deinit(self.allocator);

        self.http_client.deinit();
        self.allocator.free(self.config_url);

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
                self.bus.err(HttpFetchFailed{ .url = self.config_url, .err = @errorName(err) });
            };
        }
    }

    fn fetchAndNotify(self: *HttpProvider) !void {
        var new_etag: ?[]u8 = null;
        var span = self.bus.started(.debug, HTTPFetchStarted{});
        defer span.completed(HTTPFetchCompleted{});
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
            self.last_sync_timestamp = response.sync_timestamp_unix_nano;

            // Check if content has changed by comparing hashes
            const hash_unchanged = blk: {
                if (response.hash.len == 0) break :blk false;
                if (self.last_successful_hash) |old_hash| {
                    break :blk std.mem.eql(u8, old_hash, response.hash);
                }
                break :blk false;
            };

            if (hash_unchanged) {
                self.bus.debug(HttpPoliciesUnchanged{ .reason = "hash" });
                return;
            }

            // Record the hash for future sync requests
            if (response.hash.len > 0) {
                try self.recordSyncedHash(response.hash);
                self.bus.info(HttpPolicyHashUpdated{ .hash = response.hash });
            }

            // Notify callback with policies from response
            if (self.callback) |cb| {
                try cb.call(.{
                    .policies = response.policies.items,
                    .source = .http,
                });
            }

            self.bus.info(HttpPoliciesLoaded{
                .count = response.policies.items.len,
                .url = self.config_url,
                .sync_timestamp = response.sync_timestamp_unix_nano,
            });
        } else {
            // 304 Not Modified
            self.bus.debug(HttpPoliciesUnchanged{ .reason = "304" });
        }
    }

    fn fetchPolicies(self: *HttpProvider, out_etag: *?[]u8) !?std.json.Parsed(SyncResponse) {
        const uri = try std.Uri.parse(self.config_url);

        // Build resource_attributes with required fields:
        // - service.name
        // - service.instance.id
        // - service.version
        // - service.namespace
        const resource_attributes = [_]KeyValue{
            .{ .key = "service.name", .value = .{ .value = .{ .string_value = self.service.name } } },
            .{ .key = "service.instance.id", .value = .{ .value = .{ .string_value = self.service.instance_id } } },
            .{ .key = "service.version", .value = .{ .value = .{ .string_value = self.service.version } } },
            .{ .key = "service.namespace", .value = .{ .value = .{ .string_value = self.service.namespace } } },
        };

        // Build labels with required fields:
        // - workspace.id
        const labels = [_]KeyValue{
            .{ .key = "workspace.id", .value = .{ .value = .{ .string_value = self.workspace_id } } },
        };

        // Build supported_policy_types
        const supported_policy_types = [_]PolicyType{.POLICY_TYPE_LOG_FILTER};

        // Build policy_statuses from our tracked state
        var policy_statuses_list = std.ArrayListUnmanaged(PolicySyncStatus){};
        defer policy_statuses_list.deinit(self.allocator);

        // Lock to read sync state
        self.sync_state_mutex.lock();
        defer self.sync_state_mutex.unlock();

        // Build PolicySyncStatus entries from tracked policy statuses
        var ps_it = self.policy_statuses.iterator();
        while (ps_it.next()) |entry| {
            try policy_statuses_list.append(self.allocator, .{
                .id = entry.key_ptr.*,
                .hits = entry.value_ptr.hits,
                .misses = entry.value_ptr.misses,
                .errors = entry.value_ptr.errors,
            });
        }

        // Get last successful hash (if any)
        const last_hash: []const u8 = self.last_successful_hash orelse &.{};

        // Create SyncRequest with the new structure
        const sync_request = SyncRequest{
            .client_metadata = ClientMetadata{
                .supported_policy_types = .{ .items = @constCast(&supported_policy_types), .capacity = supported_policy_types.len },
                .resource_attributes = .{ .items = @constCast(&resource_attributes), .capacity = resource_attributes.len },
                .labels = .{ .items = @constCast(&labels), .capacity = labels.len },
            },
            .full_sync = self.last_sync_timestamp == 0,
            .last_sync_timestamp_unix_nano = self.last_sync_timestamp,
            .last_successful_hash = last_hash,
            .policy_statuses = policy_statuses_list,
        };

        // Encode SyncRequest to JSON
        protobuf.json.pb_options.emit_oneof_field_name = false;
        const request_body = try sync_request.jsonEncode(.{}, self.allocator);
        defer self.allocator.free(request_body);

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
            self.bus.debug(HTTPNotModified{});
            return null;
        }

        // Check status code
        if (response.head.status != .ok) {
            self.bus.err(HttpSyncRequestFailed{
                .url = self.config_url,
                .status = @intFromEnum(response.head.status),
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
