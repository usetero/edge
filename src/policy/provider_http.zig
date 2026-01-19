const std = @import("std");
const policy_provider = @import("./provider.zig");
const types = @import("./types.zig");
const proto = @import("proto");
const protobuf = @import("protobuf");
const o11y = @import("../observability/root.zig");

const PolicyCallback = policy_provider.PolicyCallback;
const TransformResult = policy_provider.TransformResult;
const SyncRequest = proto.policy.SyncRequest;
const SyncResponse = proto.policy.SyncResponse;
const ClientMetadata = proto.policy.ClientMetadata;
const PolicySyncStatus = proto.policy.PolicySyncStatus;
const TransformStageStatus = proto.policy.TransformStageStatus;
const PolicyStage = proto.policy.PolicyStage;
const KeyValue = proto.common.KeyValue;
const AnyValue = proto.common.AnyValue;
const ServiceMetadata = types.ServiceMetadata;
const EventBus = o11y.EventBus;

/// A header to be sent with HTTP requests
pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

// =============================================================================
// Observability Events
// =============================================================================

const PolicyErrorRecordFailed = struct { policy_id: []const u8 };
const HttpInitialFetchFailed = struct { err: []const u8 };
const HttpFetchFailed = struct { url: []const u8, err: []const u8 };
const HttpJsonDecodeFailed = struct { err: []const u8, body_preview: []const u8 };
const HttpPoliciesUnchanged = struct { reason: []const u8 };
const HttpPolicyHashUpdated = struct { hash: []const u8 };
const HttpPoliciesLoaded = struct { count: usize, url: []const u8, sync_timestamp: u64 };
const HttpSyncRequestFailed = struct { url: []const u8, status: u16 };
const HTTPFetchStarted = struct {};
const HTTPFetchCompleted = struct {};

/// Tracks status for a specific policy (hits, misses, errors, transform results)
const PolicyStatusRecord = struct {
    hits: i64 = 0,
    misses: i64 = 0,
    errors: std.ArrayListUnmanaged([]const u8) = .{},
    /// Accumulated transform results (attempted/applied counts)
    transform_result: TransformResult = .{},

    fn deinit(self: *PolicyStatusRecord, allocator: std.mem.Allocator) void {
        for (self.errors.items) |msg| {
            allocator.free(msg);
        }
        self.errors.deinit(allocator);
    }

    fn addTransformResult(self: *PolicyStatusRecord, result: TransformResult) void {
        self.transform_result.removes_attempted += result.removes_attempted;
        self.transform_result.removes_applied += result.removes_applied;
        self.transform_result.redacts_attempted += result.redacts_attempted;
        self.transform_result.redacts_applied += result.redacts_applied;
        self.transform_result.renames_attempted += result.renames_attempted;
        self.transform_result.renames_applied += result.renames_applied;
        self.transform_result.adds_attempted += result.adds_attempted;
        self.transform_result.adds_applied += result.adds_applied;
    }
};

/// HTTP-based policy provider that polls a remote endpoint
pub const HttpProvider = struct {
    allocator: std.mem.Allocator,
    /// Unique identifier for this provider
    id: []const u8,
    http_client: std.http.Client,
    config_url: []const u8,
    poll_interval_ns: u64,
    callback: ?PolicyCallback,
    poll_thread: ?std.Thread,
    shutdown_flag: std.atomic.Value(bool),

    // Service metadata for sync requests (not owned, references config)
    service: ServiceMetadata,
    last_sync_timestamp: u64,
    last_successful_hash: ?[]u8,

    // Policy status tracking: maps policy_id -> PolicyStatusRecord
    // Used to report hits/misses/errors encountered when applying policies
    policy_statuses: std.StringHashMapUnmanaged(PolicyStatusRecord),

    // Custom headers to send with HTTP requests (owned, copied from config)
    custom_headers: []Header,

    // Mutex for thread-safe access to synced state
    sync_state_mutex: std.Thread.Mutex,

    // Event bus for observability
    bus: *EventBus,

    pub fn init(
        allocator: std.mem.Allocator,
        bus: *EventBus,
        id: []const u8,
        config_url: []const u8,
        poll_interval_seconds: u64,
        service: ServiceMetadata,
        headers: []const Header,
    ) !*HttpProvider {
        const self = try allocator.create(HttpProvider);
        errdefer allocator.destroy(self);

        const id_copy = try allocator.dupe(u8, id);
        errdefer allocator.free(id_copy);

        const url_copy = try allocator.dupe(u8, config_url);
        errdefer allocator.free(url_copy);

        // Copy headers (both the slice and the string contents)
        const headers_copy = try allocator.alloc(Header, headers.len);
        errdefer allocator.free(headers_copy);

        var headers_initialized: usize = 0;
        errdefer {
            for (headers_copy[0..headers_initialized]) |h| {
                allocator.free(h.name);
                allocator.free(h.value);
            }
        }

        for (headers, 0..) |h, i| {
            const name_copy = try allocator.dupe(u8, h.name);
            errdefer allocator.free(name_copy);
            const value_copy = try allocator.dupe(u8, h.value);
            headers_copy[i] = .{ .name = name_copy, .value = value_copy };
            headers_initialized = i + 1;
        }

        self.* = .{
            .allocator = allocator,
            .id = id_copy,
            .http_client = std.http.Client{ .allocator = allocator },
            .config_url = url_copy,
            .poll_interval_ns = poll_interval_seconds * std.time.ns_per_s,
            .callback = null,
            .poll_thread = null,
            .shutdown_flag = std.atomic.Value(bool).init(false),
            .service = service,
            .last_sync_timestamp = 0,
            .last_successful_hash = null,
            .policy_statuses = .{},
            .custom_headers = headers_copy,
            .sync_state_mutex = .{},
            .bus = bus,
        };

        return self;
    }

    /// Get the unique identifier for this provider
    pub fn getId(self: *HttpProvider) []const u8 {
        return self.id;
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

    /// Record statistics about policy hits, misses, and transform stats.
    /// These stats will be sent in subsequent sync requests.
    /// Conforms to PolicyProvider interface (void return, logs errors internally).
    pub fn recordPolicyStats(self: *HttpProvider, policy_id: []const u8, hits: i64, misses: i64, transform_result: TransformResult) void {
        self.sync_state_mutex.lock();
        defer self.sync_state_mutex.unlock();

        if (self.policy_statuses.getPtr(policy_id)) |record| {
            // Update existing record
            record.hits += hits;
            record.misses += misses;
            record.addTransformResult(transform_result);
        } else {
            // Create new entry
            const id_copy = self.allocator.dupe(u8, policy_id) catch {
                self.bus.err(PolicyErrorRecordFailed{ .policy_id = policy_id });
                return;
            };

            self.policy_statuses.put(self.allocator, id_copy, .{
                .hits = hits,
                .misses = misses,
                .transform_result = transform_result,
            }) catch {
                self.allocator.free(id_copy);
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

        // Free custom headers
        for (self.custom_headers) |h| {
            self.allocator.free(h.name);
            self.allocator.free(h.value);
        }
        self.allocator.free(self.custom_headers);

        self.http_client.deinit();
        self.allocator.free(self.id);
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

    const FetchResult = struct {
        parsed: std.json.Parsed(SyncResponse),
        response_body: []u8,
    };

    fn fetchAndNotify(self: *HttpProvider) !void {
        var span = self.bus.started(.debug, HTTPFetchStarted{});
        defer span.completed(HTTPFetchCompleted{});
        var result = try self.fetchPolicies();
        defer result.parsed.deinit();
        defer self.allocator.free(result.response_body);

        const response = result.parsed.value;

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
                .provider_id = self.id,
            });
        }

        self.bus.info(HttpPoliciesLoaded{
            .count = response.policies.items.len,
            .url = self.config_url,
            .sync_timestamp = response.sync_timestamp_unix_nano,
        });
    }

    fn fetchPolicies(self: *HttpProvider) !FetchResult {
        // Use arena allocator for all temporary structures during fetch.
        // This reduces fragmentation by freeing all temporary memory at once.
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const temp_allocator = arena.allocator();

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

        // Labels (empty - workspace.id is no longer required)
        const labels = [_]KeyValue{};

        // Build supported_policy_stages from service metadata
        // Different binaries support different stages (e.g., OTLP supports traces, Datadog does not)
        const supported_policy_stages = self.service.supported_stages;

        // Build policy_statuses from our tracked state
        var policy_statuses_list = std.ArrayListUnmanaged(PolicySyncStatus){};
        // No defer needed - arena handles cleanup

        // Get last successful hash (if any) - read under lock
        var last_hash: []const u8 = &.{};
        {
            self.sync_state_mutex.lock();
            defer self.sync_state_mutex.unlock();

            // Build PolicySyncStatus entries from tracked policy statuses
            var ps_it = self.policy_statuses.iterator();
            while (ps_it.next()) |entry| {
                const tr = entry.value_ptr.transform_result;
                // Convert TransformResult to TransformStageStatus: hits = applied, misses = attempted - applied
                try policy_statuses_list.append(temp_allocator, .{
                    .id = entry.key_ptr.*,
                    .match_hits = entry.value_ptr.hits,
                    .match_misses = entry.value_ptr.misses,
                    .errors = entry.value_ptr.errors,
                    .remove = if (tr.removes_attempted > 0)
                        TransformStageStatus{
                            .hits = @intCast(tr.removes_applied),
                            .misses = @intCast(tr.removes_attempted - tr.removes_applied),
                        }
                    else
                        null,
                    .redact = if (tr.redacts_attempted > 0)
                        TransformStageStatus{
                            .hits = @intCast(tr.redacts_applied),
                            .misses = @intCast(tr.redacts_attempted - tr.redacts_applied),
                        }
                    else
                        null,
                    .rename = if (tr.renames_attempted > 0)
                        TransformStageStatus{
                            .hits = @intCast(tr.renames_applied),
                            .misses = @intCast(tr.renames_attempted - tr.renames_applied),
                        }
                    else
                        null,
                    .add = if (tr.adds_attempted > 0)
                        TransformStageStatus{
                            .hits = @intCast(tr.adds_applied),
                            .misses = @intCast(tr.adds_attempted - tr.adds_applied),
                        }
                    else
                        null,
                });
            }

            last_hash = self.last_successful_hash orelse &.{};
        }

        // Create SyncRequest with the new structure
        const sync_request = SyncRequest{
            .client_metadata = ClientMetadata{
                .supported_policy_stages = .{ .items = @constCast(supported_policy_stages.ptr), .capacity = supported_policy_stages.len },
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
        const request_body = try sync_request.jsonEncode(.{}, temp_allocator);
        // No defer needed - arena handles cleanup

        // Prepare headers: content-type + custom headers
        const max_builtin_headers: usize = 1;
        const total_headers = max_builtin_headers + self.custom_headers.len;
        const headers_buffer = try temp_allocator.alloc(std.http.Header, total_headers);
        // No defer needed - arena handles cleanup

        var headers_count: usize = 0;

        headers_buffer[headers_count] = .{
            .name = "content-type",
            .value = "application/json",
        };
        headers_count += 1;

        // Add custom headers
        for (self.custom_headers) |h| {
            headers_buffer[headers_count] = .{
                .name = h.name,
                .value = h.value,
            };
            headers_count += 1;
        }

        const extra_headers = headers_buffer[0..headers_count];

        var body: std.Io.Writer.Allocating = .init(self.allocator);
        defer body.deinit();

        // Create request
        const result = try self.http_client.fetch(.{
            .location = .{ .url = self.config_url },
            .extra_headers = extra_headers,
            .method = .POST,
            .payload = request_body,
            .response_writer = &body.writer,
        });

        // Check status code
        if (result.status != .ok) {
            self.bus.err(HttpSyncRequestFailed{
                .url = self.config_url,
                .status = @intFromEnum(result.status),
            });
            return error.HttpRequestFailed;
        }

        // Read response body - take ownership to keep memory alive for parsed result
        const response_body = try body.toOwnedSlice();
        errdefer self.allocator.free(response_body);

        // Decode SyncResponse from JSON
        const parsed = SyncResponse.jsonDecode(response_body, .{}, self.allocator) catch |err| {
            // Log the error with a preview of the response body for debugging
            const preview_len = @min(response_body.len, 200);
            self.bus.err(HttpJsonDecodeFailed{
                .err = @errorName(err),
                .body_preview = response_body[0..preview_len],
            });
            return err;
        };

        return .{
            .parsed = parsed,
            .response_body = response_body,
        };
    }
};
