const std = @import("std");
const types = @import("types.zig");
const parser = @import("parser.zig");

/// HTTP-based configuration manager that periodically polls a remote endpoint
pub const HttpConfigClient = struct {
    current: std.atomic.Value(*const types.ProxyConfig),
    allocator: std.mem.Allocator,
    http_client: std.http.Client,
    config_url: []const u8,
    poll_interval_ns: u64,
    poll_thread: ?std.Thread,
    shutdown: std.atomic.Value(bool),
    last_etag: ?[]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        config_url: []const u8,
        poll_interval_seconds: u64,
    ) !HttpConfigClient {
        // Initial fetch
        var http_client = std.http.Client{ .allocator = allocator };
        errdefer http_client.deinit();

        var initial_etag: ?[]u8 = null;
        const maybe_initial_config = try fetchConfig(allocator, &http_client, config_url, null, &initial_etag);

        // Initial fetch should never return null (no ETag to compare against)
        const initial_config = maybe_initial_config orelse return error.InitialFetchFailed;

        const url_copy = try allocator.dupe(u8, config_url);
        errdefer allocator.free(url_copy);

        return .{
            .current = std.atomic.Value(*const types.ProxyConfig).init(initial_config),
            .allocator = allocator,
            .http_client = http_client,
            .config_url = url_copy,
            .poll_interval_ns = poll_interval_seconds * std.time.ns_per_s,
            .poll_thread = null,
            .shutdown = std.atomic.Value(bool).init(false),
            .last_etag = initial_etag,
        };
    }

    pub fn deinit(self: *HttpConfigClient) void {
        self.shutdown.store(true, .release);

        if (self.poll_thread) |thread| {
            thread.join();
        }

        const config = self.current.load(.acquire);
        freeConfig(self.allocator, config);

        if (self.last_etag) |etag| {
            self.allocator.free(etag);
        }

        self.http_client.deinit();
        self.allocator.free(self.config_url);
    }

    pub fn get(self: *const HttpConfigClient) *const types.ProxyConfig {
        return self.current.load(.acquire);
    }

    pub fn startPolling(self: *HttpConfigClient) !void {
        self.poll_thread = try std.Thread.spawn(.{}, pollLoop, .{self});
    }

    fn pollLoop(self: *HttpConfigClient) void {
        while (!self.shutdown.load(.acquire)) {
            std.Thread.sleep(self.poll_interval_ns);

            self.fetchAndUpdate() catch |err| {
                std.log.err("Failed to fetch config from {s}: {}", .{ self.config_url, err });
                continue;
            };
        }
    }

    fn fetchAndUpdate(self: *HttpConfigClient) !void {
        std.log.debug("Fetching configuration from {s}...", .{self.config_url});

        var new_etag: ?[]u8 = null;
        const maybe_new_config = try fetchConfig(
            self.allocator,
            &self.http_client,
            self.config_url,
            self.last_etag,
            &new_etag,
        );

        // If we got 304 Not Modified, no update needed
        if (maybe_new_config == null) {
            std.log.debug("Configuration unchanged (304 Not Modified)", .{});
            return;
        }

        const new_config = maybe_new_config.?;

        // Update ETag
        if (self.last_etag) |old_etag| {
            self.allocator.free(old_etag);
        }
        self.last_etag = new_etag;

        const old_config = self.current.swap(new_config, .acq_rel);

        // TODO: Defer cleanup with grace period (RCU pattern)
        // For now, leak old config to avoid use-after-free
        _ = old_config;

        std.log.info("Configuration updated successfully from {s}", .{self.config_url});
    }

    fn fetchConfig(
        allocator: std.mem.Allocator,
        client: *std.http.Client,
        url: []const u8,
        last_etag: ?[]const u8,
        out_etag: *?[]u8,
    ) !?*types.ProxyConfig {
        const uri = try std.Uri.parse(url);

        // Prepare extra headers if we have an ETag
        var etag_header: [1]std.http.Header = undefined;
        var extra_headers: []const std.http.Header = &.{};

        if (last_etag) |etag| {
            etag_header[0] = .{
                .name = "if-none-match",
                .value = etag,
            };
            extra_headers = &etag_header;
        }

        // Create request with conditional headers
        var req = try client.request(.GET, uri, .{
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
                out_etag.* = try allocator.dupe(u8, header.value);
            }
        }

        // Read response body using allocating writer
        var body_writer = std.Io.Writer.Allocating.init(allocator);
        defer body_writer.deinit();

        // Buffer for streaming response
        var read_buffer: [4096]u8 = undefined;
        const body_reader = response.reader(&read_buffer);

        // Stream response to allocating writer (use large limit to read until end)
        _ = try body_reader.stream(&body_writer.writer, std.io.Limit.limited(std.math.maxInt(usize)));

        const json_bytes = body_writer.written();

        // Parse the JSON config
        return try parser.parseConfigBytes(allocator, json_bytes);
    }

    fn freeConfig(allocator: std.mem.Allocator, config: *const types.ProxyConfig) void {
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
