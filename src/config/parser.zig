const std = @import("std");
const types = @import("types.zig");
const policy = @import("../policy/root.zig");
const ProxyConfig = types.ProxyConfig;
const LogLevel = types.LogLevel;
const ProviderConfig = policy.ProviderConfig;
const ProviderType = policy.ProviderType;
const Header = policy.Header;

/// JSON schema for custom headers
const HeaderJson = struct {
    name: []const u8,
    value: []const u8,
};

/// JSON schema for policy provider configuration
const ProviderJson = struct {
    id: []const u8,
    type: []const u8,
    path: ?[]const u8 = null,
    url: ?[]const u8 = null,
    poll_interval: ?u64 = null,
    headers: ?[]HeaderJson = null,
};

/// JSON schema for service metadata
const ServiceJson = struct {
    name: ?[]const u8 = null,
    namespace: ?[]const u8 = null,
    version: ?[]const u8 = null,
};

/// JSON schema for configuration file
const ConfigJson = struct {
    listen_address: []const u8,
    listen_port: u16,
    upstream_url: []const u8,
    workspace_id: []const u8,
    log_level: []const u8,
    max_body_size: u32,
    max_upstream_retries: ?u8 = null,
    policy_providers: ?[]ProviderJson = null,
    service: ?ServiceJson = null,
};

/// Parse JSON configuration file into ProxyConfig
pub fn parseConfigFile(allocator: std.mem.Allocator, path: []const u8) !*ProxyConfig {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const contents = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(contents);

    return parseConfigBytes(allocator, contents);
}

/// Parse configuration from JSON bytes
pub fn parseConfigBytes(allocator: std.mem.Allocator, json_bytes: []const u8) !*ProxyConfig {
    // Parse JSON
    const parsed = try std.json.parseFromSlice(
        ConfigJson,
        allocator,
        json_bytes,
        .{ .allocate = .alloc_always },
    );
    defer parsed.deinit();

    const json_config = parsed.value;

    // Convert JSON to ProxyConfig
    var config = types.ProxyConfig.default();

    // Parse IP address
    config.listen_address = try parseIpv4(json_config.listen_address);
    config.listen_port = json_config.listen_port;

    // Allocate and copy upstream URL
    config.upstream_url = try allocator.dupe(u8, json_config.upstream_url);

    // Allocate and copy workspace ID
    config.workspace_id = try allocator.dupe(u8, json_config.workspace_id);

    // Parse log level
    config.log_level = try LogLevel.parse(json_config.log_level);

    // Copy remaining fields
    config.max_body_size = json_config.max_body_size;
    config.max_upstream_retries = json_config.max_upstream_retries orelse 10;

    // Parse policy providers if present
    if (json_config.policy_providers) |json_providers| {
        const providers = try parseProviders(allocator, json_providers);
        config.policy_providers = providers;
    }

    // Parse service metadata if present
    if (json_config.service) |service_json| {
        if (service_json.name) |name| {
            config.service.name = try allocator.dupe(u8, name);
        }
        if (service_json.namespace) |namespace| {
            config.service.namespace = try allocator.dupe(u8, namespace);
        }
        if (service_json.version) |version| {
            config.service.version = try allocator.dupe(u8, version);
        }
    }

    // Allocate and return config
    const config_ptr = try allocator.create(ProxyConfig);
    config_ptr.* = config;
    return config_ptr;
}

/// Parse provider configurations from JSON array
fn parseProviders(allocator: std.mem.Allocator, json_providers: []ProviderJson) ![]ProviderConfig {
    var providers = try allocator.alloc(ProviderConfig, json_providers.len);

    for (json_providers, 0..) |json_provider, i| {
        // Parse provider type
        const provider_type = try parseProviderType(json_provider.type);

        // Parse headers if present
        const headers = if (json_provider.headers) |json_headers|
            try parseHeaders(allocator, json_headers)
        else
            &[_]Header{};

        providers[i] = ProviderConfig{
            .id = try allocator.dupe(u8, json_provider.id),
            .type = provider_type,
            .path = if (json_provider.path) |p| try allocator.dupe(u8, p) else null,
            .url = if (json_provider.url) |u| try allocator.dupe(u8, u) else null,
            .poll_interval = json_provider.poll_interval,
            .headers = headers,
        };

        // Validate provider-specific required fields
        switch (provider_type) {
            .file => {
                if (providers[i].path == null) {
                    return error.FileProviderRequiresPath;
                }
            },
            .http => {
                if (providers[i].url == null) {
                    return error.HttpProviderRequiresUrl;
                }
            },
        }
    }

    return providers;
}

/// Parse headers from JSON array
fn parseHeaders(allocator: std.mem.Allocator, json_headers: []HeaderJson) ![]Header {
    const headers = try allocator.alloc(Header, json_headers.len);

    for (json_headers, 0..) |json_header, i| {
        headers[i] = Header{
            .name = try allocator.dupe(u8, json_header.name),
            .value = try allocator.dupe(u8, json_header.value),
        };
    }

    return headers;
}

/// Parse ProviderType from string
fn parseProviderType(s: []const u8) !ProviderType {
    if (std.mem.eql(u8, s, "file")) return .file;
    if (std.mem.eql(u8, s, "http")) return .http;
    return error.InvalidProviderType;
}

fn parseIpv4(s: []const u8) ![4]u8 {
    var result: [4]u8 = undefined;
    var iter = std.mem.splitScalar(u8, s, '.');
    var i: usize = 0;

    while (iter.next()) |octet| : (i += 1) {
        if (i >= 4) return error.InvalidIpv4;
        result[i] = try std.fmt.parseInt(u8, octet, 10);
    }

    if (i != 4) return error.InvalidIpv4;
    return result;
}

test "parseIpv4" {
    const addr = try parseIpv4("127.0.0.1");
    try std.testing.expectEqualSlices(u8, &[_]u8{ 127, 0, 0, 1 }, &addr);

    const addr2 = try parseIpv4("192.168.1.100");
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 100 }, &addr2);

    // Invalid: 256 causes overflow
    _ = parseIpv4("256.0.0.1") catch |err| {
        try std.testing.expect(err == error.Overflow or err == error.InvalidIpv4);
    };

    try std.testing.expectError(error.InvalidIpv4, parseIpv4("127.0.0"));
}

test "parseConfigFile with JSON" {
    const json_content =
        \\{
        \\  "listen_address": "127.0.0.1",
        \\  "listen_port": 8080,
        \\  "upstream_url": "http://127.0.0.1:80",
        \\  "workspace_id": "test-workspace-123",
        \\  "log_level": "info",
        \\  "max_body_size": 1048576
        \\}
    ;

    // Write temporary config file
    const tmp_path = "test_config.json";
    {
        const file = try std.fs.cwd().createFile(tmp_path, .{});
        defer file.close();
        try file.writeAll(json_content);
    }
    defer std.fs.cwd().deleteFile(tmp_path) catch {};

    // Parse config
    const config = try parseConfigFile(std.testing.allocator, tmp_path);
    defer {
        std.testing.allocator.free(config.upstream_url);
        std.testing.allocator.free(config.workspace_id);
        std.testing.allocator.destroy(config);
    }

    try std.testing.expectEqualSlices(u8, &[_]u8{ 127, 0, 0, 1 }, &config.listen_address);
    try std.testing.expectEqual(@as(u16, 8080), config.listen_port);
    try std.testing.expectEqualStrings("http://127.0.0.1:80", config.upstream_url);
    try std.testing.expectEqual(LogLevel.info, config.log_level);
    try std.testing.expectEqual(@as(u32, 1048576), config.max_body_size);
    try std.testing.expectEqual(@as(usize, 0), config.policy_providers.len);
}
