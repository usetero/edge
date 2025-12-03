const std = @import("std");
const policy_provider = @import("../../core/policy_provider.zig");
const policy_source = @import("../../core/policy_source.zig");
const parser = @import("../parser.zig");
const types = @import("../types.zig");
const proto = @import("proto");
const protobuf = @import("protobuf");

const PolicyCallback = policy_provider.PolicyCallback;
const PolicyUpdate = policy_provider.PolicyUpdate;
const SourceType = policy_source.SourceType;
const SyncRequest = proto.policy.SyncRequest;
const SyncResponse = proto.policy.SyncResponse;
const ClientMetadata = proto.policy.ClientMetadata;
const PolicySetSyncStatus = proto.policy.PolicySetSyncStatus;
const PolicySyncStatus = proto.policy.PolicySyncStatus;
const PolicyType = proto.policy.PolicyType;
const KeyValue = proto.common.KeyValue;
const AnyValue = proto.common.AnyValue;
const ServiceMetadata = types.ServiceMetadata;

/// Tracks errors for a specific policy (used internally before building PolicySyncStatus)
const PolicyErrorRecord = struct {
    messages: std.ArrayListUnmanaged([]const u8),

    fn deinit(self: *PolicyErrorRecord, allocator: std.mem.Allocator) void {
        for (self.messages.items) |msg| {
            allocator.free(msg);
        }
        self.messages.deinit(allocator);
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

    // Synced policy set tracking: maps policy_set_id -> SyncedPolicySetInfo
    // Used to report which policy sets we have synced to the server
    synced_policy_sets: std.StringHashMapUnmanaged(SyncedPolicySetInfo),

    // Policy error tracking: maps policy_id -> PolicyErrorRecord
    // Used to report errors encountered when applying policies
    policy_errors: std.StringHashMapUnmanaged(PolicyErrorRecord),

    // Mutex for thread-safe access to synced state
    sync_state_mutex: std.Thread.Mutex,

    /// Info about a synced policy set (hash and provider source)
    const SyncedPolicySetInfo = struct {
        hash: []const u8,
        provider: []const u8,
    };

    pub fn init(
        allocator: std.mem.Allocator,
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
            .synced_policy_sets = .{},
            .policy_errors = .{},
            .sync_state_mutex = .{},
        };

        return self;
    }

    /// Record a successfully synced policy set with its hash and provider source.
    /// This information will be sent in subsequent sync requests.
    pub fn recordSyncedPolicySet(self: *HttpProvider, policy_set_id: []const u8, hash: []const u8, provider: []const u8) !void {
        self.sync_state_mutex.lock();
        defer self.sync_state_mutex.unlock();

        // Remove old entry if exists
        if (self.synced_policy_sets.fetchRemove(policy_set_id)) |old| {
            self.allocator.free(old.key);
            self.allocator.free(old.value.hash);
            self.allocator.free(old.value.provider);
        }

        // Add new entry
        const id_copy = try self.allocator.dupe(u8, policy_set_id);
        errdefer self.allocator.free(id_copy);

        const hash_copy = try self.allocator.dupe(u8, hash);
        errdefer self.allocator.free(hash_copy);

        const provider_copy = try self.allocator.dupe(u8, provider);
        errdefer self.allocator.free(provider_copy);

        try self.synced_policy_sets.put(self.allocator, id_copy, .{
            .hash = hash_copy,
            .provider = provider_copy,
        });
    }

    /// Record an error for a specific policy.
    /// These errors will be sent in subsequent sync requests.
    /// Conforms to PolicyProvider interface (void return, logs errors internally).
    pub fn recordPolicyError(self: *HttpProvider, policy_id: []const u8, error_message: []const u8) void {
        self.sync_state_mutex.lock();
        defer self.sync_state_mutex.unlock();

        const msg_copy = self.allocator.dupe(u8, error_message) catch {
            std.log.err("Failed to record policy error for {s}: out of memory", .{policy_id});
            return;
        };

        if (self.policy_errors.getPtr(policy_id)) |record| {
            // Append to existing error list
            record.messages.append(self.allocator, msg_copy) catch {
                self.allocator.free(msg_copy);
                std.log.err("Failed to append policy error for {s}: out of memory", .{policy_id});
                return;
            };
        } else {
            // Create new entry
            const id_copy = self.allocator.dupe(u8, policy_id) catch {
                self.allocator.free(msg_copy);
                std.log.err("Failed to record policy error for {s}: out of memory", .{policy_id});
                return;
            };

            var record = PolicyErrorRecord{ .messages = .{} };
            record.messages.append(self.allocator, msg_copy) catch {
                self.allocator.free(msg_copy);
                self.allocator.free(id_copy);
                std.log.err("Failed to record policy error for {s}: out of memory", .{policy_id});
                return;
            };

            self.policy_errors.put(self.allocator, id_copy, record) catch {
                self.allocator.free(msg_copy);
                self.allocator.free(id_copy);
                record.deinit(self.allocator);
                std.log.err("Failed to record policy error for {s}: out of memory", .{policy_id});
                return;
            };
        }
    }

    /// Clear all recorded policy errors.
    /// Call this after errors have been successfully reported to the server.
    pub fn clearPolicyErrors(self: *HttpProvider) void {
        self.sync_state_mutex.lock();
        defer self.sync_state_mutex.unlock();

        var it = self.policy_errors.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.policy_errors.clearRetainingCapacity();
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

        // Free synced policy sets
        var ps_it = self.synced_policy_sets.iterator();
        while (ps_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.hash);
            self.allocator.free(entry.value_ptr.provider);
        }
        self.synced_policy_sets.deinit(self.allocator);

        // Free policy errors
        var pe_it = self.policy_errors.iterator();
        while (pe_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.policy_errors.deinit(self.allocator);

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
            self.last_sync_timestamp = response.sync_timestamp_unix_nano;

            // Extract policies from response
            if (response.policy_set) |policy_set| {
                if (self.callback) |cb| {
                    try cb.call(.{
                        .policies = policy_set.policies.items,
                        .source = .http,
                    });
                }

                // Record the synced policy set with its hash and source for future sync requests
                if (policy_set.id.len > 0 and policy_set.hash.len > 0) {
                    const source = if (policy_set.source.len > 0) policy_set.source else "http";
                    try self.recordSyncedPolicySet(policy_set.id, policy_set.hash, source);
                    std.log.debug("Recorded synced policy set: id={s}, hash={s}, source={s}", .{
                        policy_set.id,
                        policy_set.hash,
                        source,
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

        // Build policy_set_statuses from our tracked state
        // This combines synced_policy_sets and policy_errors into the new structure
        var policy_set_statuses_list = std.ArrayListUnmanaged(PolicySetSyncStatus){};
        defer policy_set_statuses_list.deinit(self.allocator);

        // Lock to read sync state
        self.sync_state_mutex.lock();
        defer self.sync_state_mutex.unlock();

        // Build PolicySetSyncStatus entries from synced policy sets
        var ps_it = self.synced_policy_sets.iterator();
        while (ps_it.next()) |entry| {
            const policy_set_id = entry.key_ptr.*;
            const info = entry.value_ptr.*;

            // Build policy_statuses for this policy set (includes errors)
            var policy_statuses = std.ArrayListUnmanaged(PolicySyncStatus){};

            // Add error entries for policies that belong to this set
            // Note: We track errors by policy_id, but the new proto groups them by policy_set
            // For now, we'll include all errors in each policy set status (server can filter)
            var pe_it = self.policy_errors.iterator();
            while (pe_it.next()) |pe_entry| {
                try policy_statuses.append(self.allocator, .{
                    .id = pe_entry.key_ptr.*,
                    .errors = pe_entry.value_ptr.messages,
                });
            }

            try policy_set_statuses_list.append(self.allocator, .{
                .id = policy_set_id,
                .hash = info.hash,
                .provider = info.provider,
                .policy_statuses = policy_statuses,
            });
        }

        // Create SyncRequest with the new structure
        const sync_request = SyncRequest{
            .client_metadata = ClientMetadata{
                .supported_policy_types = .{ .items = @constCast(&supported_policy_types), .capacity = supported_policy_types.len },
                .resource_attributes = .{ .items = @constCast(&resource_attributes), .capacity = resource_attributes.len },
                .labels = .{ .items = @constCast(&labels), .capacity = labels.len },
            },
            .full_sync = self.last_sync_timestamp == 0,
            .last_sync_timestamp_unix_nano = self.last_sync_timestamp,
            .policy_set_statuses = policy_set_statuses_list,
        };

        // Encode SyncRequest to JSON
        protobuf.json.pb_options.emit_oneof_field_name = false;
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
