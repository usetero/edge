const std = @import("std");
const policy_provider = @import("../../core/policy_provider.zig");
const policy_source = @import("../../core/policy_source.zig");
const parser = @import("../parser.zig");
const types = @import("../types.zig");

const PolicyCallback = policy_provider.PolicyCallback;
const PolicyUpdate = policy_provider.PolicyUpdate;
const SourceType = policy_source.SourceType;

/// HTTP-based policy provider that polls a remote endpoint
pub const HttpProvider = struct {
    allocator: std.mem.Allocator,
    http_client: std.http.Client,
    config_url: []const u8,
    poll_interval_ns: u64,
    callback: ?PolicyCallback,
    poll_thread: ?std.Thread,
    shutdown: std.atomic.Value(bool),
    last_etag: ?[]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        config_url: []const u8,
        poll_interval_seconds: u64,
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
            .shutdown = std.atomic.Value(bool).init(false),
            .last_etag = null,
        };

        return self;
    }

    pub fn subscribe(self: *HttpProvider, callback: PolicyCallback) !void {
        self.callback = callback;

        // Initial fetch and notify
        try self.fetchAndNotify();

        // Start polling
        self.poll_thread = try std.Thread.spawn(.{}, pollLoop, .{self});
    }

    pub fn deinit(self: *HttpProvider) void {
        self.shutdown.store(true, .release);

        if (self.poll_thread) |thread| {
            thread.join();
        }

        if (self.last_etag) |etag| {
            self.allocator.free(etag);
        }

        self.http_client.deinit();
        self.allocator.free(self.config_url);
        self.allocator.destroy(self);
    }

    fn pollLoop(self: *HttpProvider) void {
        while (!self.shutdown.load(.acquire)) {
            std.Thread.sleep(self.poll_interval_ns);

            self.fetchAndNotify() catch |err| {
                std.log.err("HTTP provider fetch failed from {s}: {}", .{ self.config_url, err });
            };
        }
    }

    fn fetchAndNotify(self: *HttpProvider) !void {
        std.log.debug("Fetching policies from HTTP: {s}", .{self.config_url});

        var new_etag: ?[]u8 = null;
        const maybe_config = try self.fetchConfig(&new_etag);

        if (maybe_config) |config| {
            defer freeConfig(self.allocator, config);

            // Update ETag
            if (self.last_etag) |old_etag| {
                self.allocator.free(old_etag);
            }
            self.last_etag = new_etag;

            if (self.callback) |cb| {
                try cb.call(.{
                    .policies = config.policies,
                    .source = .http,
                });
            }

            std.log.info("Loaded {} policies from {s}", .{ config.policies.len, self.config_url });
        } else {
            // 304 Not Modified
            std.log.debug("Policies unchanged (304 Not Modified)", .{});
        }
    }

    fn fetchConfig(self: *HttpProvider, out_etag: *?[]u8) !?*types.ProxyConfig {
        const uri = try std.Uri.parse(self.config_url);

        // Prepare extra headers if we have an ETag
        var etag_header: [1]std.http.Header = undefined;
        var extra_headers: []const std.http.Header = &.{};

        if (self.last_etag) |etag| {
            etag_header[0] = .{
                .name = "if-none-match",
                .value = etag,
            };
            extra_headers = &etag_header;
        }

        // Create request with conditional headers
        var req = try self.http_client.request(.POST, uri, .{
            .extra_headers = extra_headers,
        });
        defer req.deinit();

        // Send request
        try req.sendBodiless();

        // Receive response headers
        var response = try req.receiveHead(&.{});

        // Check for 304 Not Modified
        if (response.head.status == .not_modified) {
            return null;
        }

        // Check status code
        if (response.head.status != .ok) {
            std.log.err("HTTP request failed with status: {}", .{response.head.status});
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

        // Stream response to allocating writer (use large limit to read until end)
        _ = try body_reader.stream(&body_writer.writer, std.io.Limit.limited(std.math.maxInt(usize)));

        const json_bytes = body_writer.written();

        // Parse the JSON config
        return try parser.parseConfigBytes(self.allocator, json_bytes);
    }

    fn freeConfig(allocator: std.mem.Allocator, config: *const types.ProxyConfig) void {
        // Free policies
        for (config.policies) |*policy| {
            allocator.free(policy.name);
            for (policy.regexes.items) |regex| {
                allocator.free(regex);
            }
            policy.regexes.deinit(allocator);
        }
        allocator.free(config.policies);
        allocator.free(config.upstream_url);
        allocator.destroy(config);
    }
};
