const std = @import("std");
const types = @import("types.zig");
const ProxyConfig = types.ProxyConfig;
const LogLevel = types.LogLevel;
const Policy = types.Policy;
const PolicyType = types.PolicyType;
const TelemetryType = types.TelemetryType;
const Action = types.Action;
const ActionType = types.ActionType;

/// JSON schema for a policy
const PolicyJson = struct {
    name: []const u8,
    policy_type: []const u8,
    telemetry_type: []const u8,
    regexes: [][]const u8,
    action: []const u8,
};

/// JSON schema for a policies-only file
const PoliciesFileJson = struct {
    policies: []PolicyJson,
};

/// JSON schema for policy provider configuration
const ProviderJson = struct {
    type: []const u8,
    path: ?[]const u8 = null,
    url: ?[]const u8 = null,
    poll_interval: ?u64 = null,
};

/// JSON schema for configuration file
const ConfigJson = struct {
    listen_address: []const u8,
    listen_port: u16,
    upstream_url: []const u8,
    workspace_id: []const u8,
    log_level: []const u8,
    pretty_print_json: bool,
    max_body_size: u32,
    policy_providers: ?[]ProviderJson = null,
};

/// Parse JSON configuration file into ProxyConfig
pub fn parseConfigFile(allocator: std.mem.Allocator, path: []const u8) !*ProxyConfig {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const contents = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(contents);

    return parseConfigBytes(allocator, contents);
}

/// Parse policies-only JSON file
pub fn parsePoliciesFile(allocator: std.mem.Allocator, path: []const u8) ![]Policy {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const contents = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(contents);

    return parsePoliciesBytes(allocator, contents);
}

/// Parse policies from JSON bytes
pub fn parsePoliciesBytes(allocator: std.mem.Allocator, json_bytes: []const u8) ![]Policy {
    const parsed = try std.json.parseFromSlice(
        PoliciesFileJson,
        allocator,
        json_bytes,
        .{ .allocate = .alloc_always },
    );
    defer parsed.deinit();

    const json_policies = parsed.value;
    return parsePolicies(allocator, json_policies.policies);
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
    config.pretty_print_json = json_config.pretty_print_json;
    config.max_body_size = json_config.max_body_size;

    // Parse policy providers if present
    if (json_config.policy_providers) |json_providers| {
        const providers = try parseProviders(allocator, json_providers);
        config.policy_providers = providers;
    }

    // Allocate and return config
    const config_ptr = try allocator.create(ProxyConfig);
    config_ptr.* = config;
    return config_ptr;
}

/// Parse policies from JSON array
fn parsePolicies(allocator: std.mem.Allocator, json_policies: []PolicyJson) ![]Policy {
    var policies = try allocator.alloc(Policy, json_policies.len);

    for (json_policies, 0..) |json_policy, i| {
        // Parse policy type
        const policy_type = try parsePolicyType(json_policy.policy_type);

        // Parse telemetry type
        const telemetry_type = try parseTelemetryType(json_policy.telemetry_type);

        // Parse action
        const action = try parseAction(json_policy.action);

        // Allocate and copy name
        const name = try allocator.dupe(u8, json_policy.name);

        // Allocate and copy regexes into ArrayListUnmanaged
        var regexes = std.ArrayListUnmanaged([]const u8){};
        try regexes.ensureTotalCapacity(allocator, json_policy.regexes.len);
        for (json_policy.regexes) |regex| {
            const regex_copy = try allocator.dupe(u8, regex);
            regexes.appendAssumeCapacity(regex_copy);
        }

        policies[i] = Policy{
            .name = name,
            .policy_type = policy_type,
            .telemetry_type = telemetry_type,
            .regexes = regexes,
            .action = action,
        };
    }

    return policies;
}

/// Parse provider configurations from JSON array
fn parseProviders(allocator: std.mem.Allocator, json_providers: []ProviderJson) ![]types.ProviderConfig {
    var providers = try allocator.alloc(types.ProviderConfig, json_providers.len);

    for (json_providers, 0..) |json_provider, i| {
        // Parse provider type
        const provider_type = try parseProviderType(json_provider.type);

        providers[i] = types.ProviderConfig{
            .type = provider_type,
            .path = if (json_provider.path) |p| try allocator.dupe(u8, p) else null,
            .url = if (json_provider.url) |u| try allocator.dupe(u8, u) else null,
            .poll_interval = json_provider.poll_interval,
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

/// Parse ProviderType from string
fn parseProviderType(s: []const u8) !types.ProviderType {
    if (std.mem.eql(u8, s, "file")) return .file;
    if (std.mem.eql(u8, s, "http")) return .http;
    return error.InvalidProviderType;
}

/// Parse PolicyType from string
fn parsePolicyType(s: []const u8) !PolicyType {
    if (std.mem.eql(u8, s, "filter")) return .POLICY_TYPE_FILTER;
    if (std.mem.eql(u8, s, "transform")) return .POLICY_TYPE_TRANSFORM;
    if (std.mem.eql(u8, s, "redact")) return .POLICY_TYPE_REDACT;
    return error.InvalidPolicyType;
}

/// Parse TelemetryType from string
fn parseTelemetryType(s: []const u8) !TelemetryType {
    if (std.mem.eql(u8, s, "log")) return .TELEMETRY_TYPE_LOG;
    if (std.mem.eql(u8, s, "metric")) return .TELEMETRY_TYPE_METRIC;
    if (std.mem.eql(u8, s, "span")) return .TELEMETRY_TYPE_SPAN;
    return error.InvalidTelemetryType;
}

/// Parse Action from string
fn parseAction(s: []const u8) !Action {
    if (std.mem.eql(u8, s, "keep")) return .{ .type = .ACTION_TYPE_KEEP };
    if (std.mem.eql(u8, s, "drop")) return .{ .type = .ACTION_TYPE_DROP };
    return error.InvalidAction;
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
        \\  "log_level": "info",
        \\  "pretty_print_json": true,
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
        std.testing.allocator.destroy(config);
    }

    try std.testing.expectEqualSlices(u8, &[_]u8{ 127, 0, 0, 1 }, &config.listen_address);
    try std.testing.expectEqual(@as(u16, 8080), config.listen_port);
    try std.testing.expectEqualStrings("http://127.0.0.1:80", config.upstream_url);
    try std.testing.expectEqual(LogLevel.info, config.log_level);
    try std.testing.expectEqual(true, config.pretty_print_json);
    try std.testing.expectEqual(@as(u32, 1048576), config.max_body_size);
    try std.testing.expectEqual(@as(usize, 0), config.policies.len);
}

test "parseConfigFile with policies" {
    const json_content =
        \\{
        \\  "listen_address": "127.0.0.1",
        \\  "listen_port": 8080,
        \\  "upstream_url": "http://127.0.0.1:80",
        \\  "log_level": "info",
        \\  "pretty_print_json": true,
        \\  "max_body_size": 1048576,
        \\  "policies": [
        \\    {
        \\      "name": "drop-debug",
        \\      "policy_type": "filter",
        \\      "telemetry_type": "log",
        \\      "regexes": ["debug", "trace"],
        \\      "action": "drop"
        \\    },
        \\    {
        \\      "name": "keep-errors",
        \\      "policy_type": "filter",
        \\      "telemetry_type": "log",
        \\      "regexes": ["error"],
        \\      "action": "keep"
        \\    }
        \\  ]
        \\}
    ;

    // Write temporary config file
    const tmp_path = "test_config_policies.json";
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
        for (config.policies) |policy| {
            std.testing.allocator.free(policy.name);
            for (policy.regexes) |regex| {
                std.testing.allocator.free(regex);
            }
            std.testing.allocator.free(policy.regexes);
        }
        std.testing.allocator.free(config.policies);
        std.testing.allocator.destroy(config);
    }

    // Verify policies were parsed
    try std.testing.expectEqual(@as(usize, 2), config.policies.len);

    // Verify first policy
    try std.testing.expectEqualStrings("drop-debug", config.policies[0].name);
    try std.testing.expect(config.policies[0].policy_type == .filter);
    try std.testing.expect(config.policies[0].telemetry_type == .log);
    try std.testing.expectEqual(@as(usize, 2), config.policies[0].regexes.len);
    try std.testing.expectEqualStrings("debug", config.policies[0].regexes[0]);
    try std.testing.expectEqualStrings("trace", config.policies[0].regexes[1]);
    try std.testing.expect(config.policies[0].action == .drop);

    // Verify second policy
    try std.testing.expectEqualStrings("keep-errors", config.policies[1].name);
    try std.testing.expect(config.policies[1].policy_type == .filter);
    try std.testing.expect(config.policies[1].telemetry_type == .log);
    try std.testing.expectEqual(@as(usize, 1), config.policies[1].regexes.len);
    try std.testing.expectEqualStrings("error", config.policies[1].regexes[0]);
    try std.testing.expect(config.policies[1].action == .keep);
}

test "parsePolicyType" {
    try std.testing.expect(try parsePolicyType("filter") == .filter);
    try std.testing.expect(try parsePolicyType("transform") == .transform);
    try std.testing.expect(try parsePolicyType("redact") == .redact);
    try std.testing.expectError(error.InvalidPolicyType, parsePolicyType("invalid"));
}

test "parseTelemetryType" {
    try std.testing.expect(try parseTelemetryType("log") == .log);
    try std.testing.expect(try parseTelemetryType("metric") == .metric);
    try std.testing.expect(try parseTelemetryType("span") == .span);
    try std.testing.expectError(error.InvalidTelemetryType, parseTelemetryType("invalid"));
}

test "parseAction" {
    const keep_action = try parseAction("keep");
    const drop_action = try parseAction("drop");

    try std.testing.expect(keep_action == .keep);
    try std.testing.expect(drop_action == .drop);
    try std.testing.expectError(error.InvalidAction, parseAction("invalid"));
}
