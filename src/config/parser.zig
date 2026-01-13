const std = @import("std");
const types = @import("types.zig");
const policy = @import("../policy/root.zig");
const env_subst = @import("env_subst.zig");
const ProxyConfig = types.ProxyConfig;
const LogLevel = types.LogLevel;
const ProviderConfig = policy.ProviderConfig;
const ProviderType = policy.ProviderType;
const Header = policy.Header;

/// Substitute environment variables in a string and duplicate it.
/// If no substitution was needed, duplicates the original string.
/// Returns an allocated string that must be freed by the caller.
fn substituteAndDupe(allocator: std.mem.Allocator, input: []const u8) ![]const u8 {
    const result = env_subst.substitute(allocator, input) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.UnclosedVariable => return error.UnclosedVariable,
        error.EmptyVariableName => return error.EmptyVariableName,
        error.InvalidVariableName => return error.InvalidVariableName,
    };

    if (result.was_substituted) {
        return result.value;
    } else {
        return allocator.dupe(u8, input);
    }
}

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
    logs_url: ?[]const u8 = null,
    metrics_url: ?[]const u8 = null,
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

    // Parse IP address (substitute env vars first)
    const listen_address_str = try substituteAndDupe(allocator, json_config.listen_address);
    defer allocator.free(listen_address_str);
    config.listen_address = try parseIpv4(listen_address_str);
    config.listen_port = json_config.listen_port;

    // Allocate and copy upstream URL (with env var substitution)
    config.upstream_url = try substituteAndDupe(allocator, json_config.upstream_url);

    // Allocate and copy optional Datadog-specific URLs (with env var substitution)
    if (json_config.logs_url) |logs_url| {
        config.logs_url = try substituteAndDupe(allocator, logs_url);
    }
    if (json_config.metrics_url) |metrics_url| {
        config.metrics_url = try substituteAndDupe(allocator, metrics_url);
    }

    // Allocate and copy workspace ID (with env var substitution)
    config.workspace_id = try substituteAndDupe(allocator, json_config.workspace_id);

    // Parse log level (substitute env vars first)
    const log_level_str = try substituteAndDupe(allocator, json_config.log_level);
    defer allocator.free(log_level_str);
    config.log_level = try LogLevel.parse(log_level_str);

    // Copy remaining fields
    config.max_body_size = json_config.max_body_size;
    config.max_upstream_retries = json_config.max_upstream_retries orelse 10;

    // Parse policy providers if present
    if (json_config.policy_providers) |json_providers| {
        const providers = try parseProviders(allocator, json_providers);
        config.policy_providers = providers;
    }

    // Parse service metadata if present (with env var substitution)
    if (json_config.service) |service_json| {
        if (service_json.name) |name| {
            config.service.name = try substituteAndDupe(allocator, name);
        }
        if (service_json.namespace) |namespace| {
            config.service.namespace = try substituteAndDupe(allocator, namespace);
        }
        if (service_json.version) |version| {
            config.service.version = try substituteAndDupe(allocator, version);
        }
    }

    // Allocate and return config
    const config_ptr = try allocator.create(ProxyConfig);
    config_ptr.* = config;
    return config_ptr;
}

/// Parse provider configurations from JSON array (with env var substitution)
fn parseProviders(allocator: std.mem.Allocator, json_providers: []ProviderJson) ![]ProviderConfig {
    var providers = try allocator.alloc(ProviderConfig, json_providers.len);

    for (json_providers, 0..) |json_provider, i| {
        // Parse provider type
        const provider_type = try parseProviderType(json_provider.type);

        // Parse headers if present (with env var substitution)
        const headers = if (json_provider.headers) |json_headers|
            try parseHeaders(allocator, json_headers)
        else
            &[_]Header{};

        providers[i] = ProviderConfig{
            .id = try substituteAndDupe(allocator, json_provider.id),
            .type = provider_type,
            .path = if (json_provider.path) |p| try substituteAndDupe(allocator, p) else null,
            .url = if (json_provider.url) |u| try substituteAndDupe(allocator, u) else null,
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

/// Parse headers from JSON array (with env var substitution)
fn parseHeaders(allocator: std.mem.Allocator, json_headers: []HeaderJson) ![]Header {
    const headers = try allocator.alloc(Header, json_headers.len);

    for (json_headers, 0..) |json_header, i| {
        headers[i] = Header{
            .name = try substituteAndDupe(allocator, json_header.name),
            .value = try substituteAndDupe(allocator, json_header.value),
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

test "substituteAndDupe: no variables returns copy" {
    const result = try substituteAndDupe(std.testing.allocator, "no variables");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("no variables", result);
}

test "substituteAndDupe: with unset variable" {
    const result = try substituteAndDupe(std.testing.allocator, "prefix_${UNSET_TEST_VAR}_suffix");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("prefix__suffix", result);
}

test "substituteAndDupe: invalid variable returns error" {
    try std.testing.expectError(error.UnclosedVariable, substituteAndDupe(std.testing.allocator, "${UNCLOSED"));
    try std.testing.expectError(error.EmptyVariableName, substituteAndDupe(std.testing.allocator, "${}"));
    try std.testing.expectError(error.InvalidVariableName, substituteAndDupe(std.testing.allocator, "${1VAR}"));
}

test "parseConfigBytes: env var substitution in upstream_url" {
    const json_content =
        \\{
        \\  "listen_address": "127.0.0.1",
        \\  "listen_port": 8080,
        \\  "upstream_url": "https://${UNSET_HOST_VAR}/api",
        \\  "workspace_id": "test-workspace",
        \\  "log_level": "info",
        \\  "max_body_size": 1048576
        \\}
    ;

    const config = try parseConfigBytes(std.testing.allocator, json_content);
    defer {
        std.testing.allocator.free(config.upstream_url);
        std.testing.allocator.free(config.workspace_id);
        std.testing.allocator.destroy(config);
    }

    // Unset variable becomes empty
    try std.testing.expectEqualStrings("https:///api", config.upstream_url);
}

test "parseConfigBytes: env var substitution in workspace_id" {
    const json_content =
        \\{
        \\  "listen_address": "127.0.0.1",
        \\  "listen_port": 8080,
        \\  "upstream_url": "http://localhost",
        \\  "workspace_id": "${UNSET_WORKSPACE_VAR}",
        \\  "log_level": "info",
        \\  "max_body_size": 1048576
        \\}
    ;

    const config = try parseConfigBytes(std.testing.allocator, json_content);
    defer {
        std.testing.allocator.free(config.upstream_url);
        std.testing.allocator.free(config.workspace_id);
        std.testing.allocator.destroy(config);
    }

    try std.testing.expectEqualStrings("", config.workspace_id);
}

test "parseConfigBytes: env var substitution in optional URLs" {
    const json_content =
        \\{
        \\  "listen_address": "127.0.0.1",
        \\  "listen_port": 8080,
        \\  "upstream_url": "http://localhost",
        \\  "logs_url": "https://${UNSET_LOGS_HOST}/logs",
        \\  "metrics_url": "https://${UNSET_METRICS_HOST}/metrics",
        \\  "workspace_id": "test",
        \\  "log_level": "info",
        \\  "max_body_size": 1048576
        \\}
    ;

    const config = try parseConfigBytes(std.testing.allocator, json_content);
    defer {
        std.testing.allocator.free(config.upstream_url);
        if (config.logs_url) |url| std.testing.allocator.free(url);
        if (config.metrics_url) |url| std.testing.allocator.free(url);
        std.testing.allocator.free(config.workspace_id);
        std.testing.allocator.destroy(config);
    }

    try std.testing.expectEqualStrings("https:///logs", config.logs_url.?);
    try std.testing.expectEqualStrings("https:///metrics", config.metrics_url.?);
}

test "parseConfigBytes: env var substitution in policy provider" {
    const json_content =
        \\{
        \\  "listen_address": "127.0.0.1",
        \\  "listen_port": 8080,
        \\  "upstream_url": "http://localhost",
        \\  "workspace_id": "test",
        \\  "log_level": "info",
        \\  "max_body_size": 1048576,
        \\  "policy_providers": [
        \\    {
        \\      "id": "provider-${UNSET_ID}",
        \\      "type": "http",
        \\      "url": "http://${UNSET_PROVIDER_HOST}/sync"
        \\    }
        \\  ]
        \\}
    ;

    const config = try parseConfigBytes(std.testing.allocator, json_content);
    defer {
        std.testing.allocator.free(config.upstream_url);
        std.testing.allocator.free(config.workspace_id);
        for (config.policy_providers) |provider| {
            std.testing.allocator.free(provider.id);
            if (provider.url) |url| std.testing.allocator.free(url);
        }
        std.testing.allocator.free(config.policy_providers);
        std.testing.allocator.destroy(config);
    }

    try std.testing.expectEqual(@as(usize, 1), config.policy_providers.len);
    try std.testing.expectEqualStrings("provider-", config.policy_providers[0].id);
    try std.testing.expectEqualStrings("http:///sync", config.policy_providers[0].url.?);
}

test "parseConfigBytes: env var substitution in headers" {
    const json_content =
        \\{
        \\  "listen_address": "127.0.0.1",
        \\  "listen_port": 8080,
        \\  "upstream_url": "http://localhost",
        \\  "workspace_id": "test",
        \\  "log_level": "info",
        \\  "max_body_size": 1048576,
        \\  "policy_providers": [
        \\    {
        \\      "id": "http-provider",
        \\      "type": "http",
        \\      "url": "http://localhost/sync",
        \\      "headers": [
        \\        {
        \\          "name": "Authorization",
        \\          "value": "Bearer ${UNSET_API_TOKEN}"
        \\        },
        \\        {
        \\          "name": "X-Custom-${UNSET_HEADER_NAME}",
        \\          "value": "custom-value"
        \\        }
        \\      ]
        \\    }
        \\  ]
        \\}
    ;

    const config = try parseConfigBytes(std.testing.allocator, json_content);
    defer {
        std.testing.allocator.free(config.upstream_url);
        std.testing.allocator.free(config.workspace_id);
        for (config.policy_providers) |provider| {
            std.testing.allocator.free(provider.id);
            if (provider.url) |url| std.testing.allocator.free(url);
            for (provider.headers) |header| {
                std.testing.allocator.free(header.name);
                std.testing.allocator.free(header.value);
            }
            if (provider.headers.len > 0) std.testing.allocator.free(provider.headers);
        }
        std.testing.allocator.free(config.policy_providers);
        std.testing.allocator.destroy(config);
    }

    const headers = config.policy_providers[0].headers;
    try std.testing.expectEqual(@as(usize, 2), headers.len);
    try std.testing.expectEqualStrings("Authorization", headers[0].name);
    try std.testing.expectEqualStrings("Bearer ", headers[0].value);
    try std.testing.expectEqualStrings("X-Custom-", headers[1].name);
    try std.testing.expectEqualStrings("custom-value", headers[1].value);
}

test "parseConfigBytes: env var substitution in service metadata" {
    const json_content =
        \\{
        \\  "listen_address": "127.0.0.1",
        \\  "listen_port": 8080,
        \\  "upstream_url": "http://localhost",
        \\  "workspace_id": "test",
        \\  "log_level": "info",
        \\  "max_body_size": 1048576,
        \\  "service": {
        \\    "name": "${UNSET_SERVICE_NAME}",
        \\    "namespace": "ns-${UNSET_NS}",
        \\    "version": "v${UNSET_VERSION}"
        \\  }
        \\}
    ;

    const config = try parseConfigBytes(std.testing.allocator, json_content);
    defer {
        std.testing.allocator.free(config.upstream_url);
        std.testing.allocator.free(config.workspace_id);
        std.testing.allocator.free(config.service.name);
        std.testing.allocator.free(config.service.namespace);
        std.testing.allocator.free(config.service.version);
        std.testing.allocator.destroy(config);
    }

    try std.testing.expectEqualStrings("", config.service.name);
    try std.testing.expectEqualStrings("ns-", config.service.namespace);
    try std.testing.expectEqualStrings("v", config.service.version);
}

test "parseConfigBytes: unclosed variable returns error" {
    const json_content =
        \\{
        \\  "listen_address": "127.0.0.1",
        \\  "listen_port": 8080,
        \\  "upstream_url": "http://${UNCLOSED",
        \\  "workspace_id": "test",
        \\  "log_level": "info",
        \\  "max_body_size": 1048576
        \\}
    ;

    try std.testing.expectError(error.UnclosedVariable, parseConfigBytes(std.testing.allocator, json_content));
}

test "parseConfigBytes: empty variable name returns error" {
    const json_content =
        \\{
        \\  "listen_address": "127.0.0.1",
        \\  "listen_port": 8080,
        \\  "upstream_url": "http://${}/path",
        \\  "workspace_id": "test",
        \\  "log_level": "info",
        \\  "max_body_size": 1048576
        \\}
    ;

    try std.testing.expectError(error.EmptyVariableName, parseConfigBytes(std.testing.allocator, json_content));
}

test "parseConfigBytes: escape sequence preserved" {
    const json_content =
        \\{
        \\  "listen_address": "127.0.0.1",
        \\  "listen_port": 8080,
        \\  "upstream_url": "http://localhost",
        \\  "workspace_id": "$${NOT_SUBSTITUTED}",
        \\  "log_level": "info",
        \\  "max_body_size": 1048576
        \\}
    ;

    const config = try parseConfigBytes(std.testing.allocator, json_content);
    defer {
        std.testing.allocator.free(config.upstream_url);
        std.testing.allocator.free(config.workspace_id);
        std.testing.allocator.destroy(config);
    }

    // $$ becomes $ - so $${VAR} becomes ${VAR} literal
    try std.testing.expectEqualStrings("${NOT_SUBSTITUTED}", config.workspace_id);
}

test "parseConfigBytes: file provider with env var in path" {
    const json_content =
        \\{
        \\  "listen_address": "127.0.0.1",
        \\  "listen_port": 8080,
        \\  "upstream_url": "http://localhost",
        \\  "workspace_id": "test",
        \\  "log_level": "info",
        \\  "max_body_size": 1048576,
        \\  "policy_providers": [
        \\    {
        \\      "id": "file-provider",
        \\      "type": "file",
        \\      "path": "${UNSET_CONFIG_DIR}/policies.json"
        \\    }
        \\  ]
        \\}
    ;

    const config = try parseConfigBytes(std.testing.allocator, json_content);
    defer {
        std.testing.allocator.free(config.upstream_url);
        std.testing.allocator.free(config.workspace_id);
        for (config.policy_providers) |provider| {
            std.testing.allocator.free(provider.id);
            if (provider.path) |path| std.testing.allocator.free(path);
        }
        std.testing.allocator.free(config.policy_providers);
        std.testing.allocator.destroy(config);
    }

    try std.testing.expectEqualStrings("/policies.json", config.policy_providers[0].path.?);
}

test "parseConfigBytes: multiple variables in same field" {
    const json_content =
        \\{
        \\  "listen_address": "127.0.0.1",
        \\  "listen_port": 8080,
        \\  "upstream_url": "https://${UNSET_USER}:${UNSET_PASS}@${UNSET_HOST}/api",
        \\  "workspace_id": "test",
        \\  "log_level": "info",
        \\  "max_body_size": 1048576
        \\}
    ;

    const config = try parseConfigBytes(std.testing.allocator, json_content);
    defer {
        std.testing.allocator.free(config.upstream_url);
        std.testing.allocator.free(config.workspace_id);
        std.testing.allocator.destroy(config);
    }

    try std.testing.expectEqualStrings("https://:@/api", config.upstream_url);
}
