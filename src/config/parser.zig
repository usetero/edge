const std = @import("std");
const types = @import("types.zig");
const ProxyConfig = types.ProxyConfig;
const LogLevel = types.LogLevel;
const Policy = types.Policy;
const PolicyType = types.PolicyType;
const TelemetryType = types.TelemetryType;
const FilterAction = types.FilterAction;
const FilterConfig = types.FilterConfig;
const Matcher = types.Matcher;
const MatchType = types.MatchType;

/// JSON schema for a matcher
const MatcherJson = struct {
    match_type: []const u8,
    key: []const u8 = "",
    regex: []const u8,
    negate: bool = false,
};

/// JSON schema for a policy
const PolicyJson = struct {
    id: ?[]const u8 = null,
    name: []const u8,
    description: ?[]const u8 = null,
    policy_type: []const u8,
    telemetry_types: [][]const u8,
    priority: i32 = 0,
    enabled: bool = true,
    // For filter policies
    matchers: ?[]MatcherJson = null,
    action: ?[]const u8 = null,
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

        // Parse telemetry types
        var telemetry_types = std.ArrayListUnmanaged(TelemetryType){};
        try telemetry_types.ensureTotalCapacity(allocator, json_policy.telemetry_types.len);
        for (json_policy.telemetry_types) |tt| {
            telemetry_types.appendAssumeCapacity(try parseTelemetryType(tt));
        }

        // Allocate and copy strings
        const id = if (json_policy.id) |id| try allocator.dupe(u8, id) else &.{};
        const name = try allocator.dupe(u8, json_policy.name);
        const description = if (json_policy.description) |desc| try allocator.dupe(u8, desc) else &.{};

        // Build config based on policy type
        var config: ?Policy.config_union = null;
        if (policy_type == .POLICY_TYPE_LOG_FILTER) {
            // Parse matchers
            var matchers = std.ArrayListUnmanaged(Matcher){};
            if (json_policy.matchers) |json_matchers| {
                try matchers.ensureTotalCapacity(allocator, json_matchers.len);
                for (json_matchers) |jm| {
                    matchers.appendAssumeCapacity(.{
                        .match_type = try parseMatchType(jm.match_type),
                        .key = if (jm.key.len > 0) try allocator.dupe(u8, jm.key) else &.{},
                        .regex = try allocator.dupe(u8, jm.regex),
                        .negate = jm.negate,
                    });
                }
            }
            // Parse action
            const action = if (json_policy.action) |a| try parseFilterAction(a) else .FILTER_ACTION_UNSPECIFIED;

            config = .{
                .filter = FilterConfig{
                    .matchers = matchers,
                    .action = action,
                },
            };
        }

        policies[i] = Policy{
            .id = id,
            .name = name,
            .description = description,
            .policy_type = policy_type,
            .telemetry_types = telemetry_types,
            .priority = json_policy.priority,
            .enabled = json_policy.enabled,
            .config = config,
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
    if (std.mem.eql(u8, s, "filter") or std.mem.eql(u8, s, "log_filter")) return .POLICY_TYPE_LOG_FILTER;
    if (std.mem.eql(u8, s, "redaction") or std.mem.eql(u8, s, "redact")) return .POLICY_TYPE_REDACTION;
    return error.InvalidPolicyType;
}

/// Parse TelemetryType from string
fn parseTelemetryType(s: []const u8) !TelemetryType {
    if (std.mem.eql(u8, s, "log") or std.mem.eql(u8, s, "logs")) return .TELEMETRY_TYPE_LOGS;
    return error.InvalidTelemetryType;
}

/// Parse FilterAction from string
fn parseFilterAction(s: []const u8) !FilterAction {
    if (std.mem.eql(u8, s, "keep")) return .FILTER_ACTION_KEEP;
    if (std.mem.eql(u8, s, "drop")) return .FILTER_ACTION_DROP;
    return error.InvalidAction;
}

/// Parse MatchType from string
fn parseMatchType(s: []const u8) !MatchType {
    if (std.mem.eql(u8, s, "log_body")) return .MATCH_TYPE_LOG_BODY;
    if (std.mem.eql(u8, s, "log_severity_text")) return .MATCH_TYPE_LOG_SEVERITY_TEXT;
    if (std.mem.eql(u8, s, "log_severity_number")) return .MATCH_TYPE_LOG_SEVERITY_NUMBER;
    if (std.mem.eql(u8, s, "log_attribute")) return .MATCH_TYPE_LOG_ATTRIBUTE;
    if (std.mem.eql(u8, s, "resource_attribute")) return .MATCH_TYPE_RESOURCE_ATTRIBUTE;
    if (std.mem.eql(u8, s, "scope_name")) return .MATCH_TYPE_SCOPE_NAME;
    if (std.mem.eql(u8, s, "scope_version")) return .MATCH_TYPE_SCOPE_VERSION;
    if (std.mem.eql(u8, s, "scope_attribute")) return .MATCH_TYPE_SCOPE_ATTRIBUTE;
    if (std.mem.eql(u8, s, "metric_name")) return .MATCH_TYPE_METRIC_NAME;
    if (std.mem.eql(u8, s, "metric_attribute")) return .MATCH_TYPE_METRIC_ATTRIBUTE;
    if (std.mem.eql(u8, s, "span_name")) return .MATCH_TYPE_SPAN_NAME;
    if (std.mem.eql(u8, s, "span_kind")) return .MATCH_TYPE_SPAN_KIND;
    if (std.mem.eql(u8, s, "span_status")) return .MATCH_TYPE_SPAN_STATUS;
    if (std.mem.eql(u8, s, "span_attribute")) return .MATCH_TYPE_SPAN_ATTRIBUTE;
    return error.InvalidMatchType;
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
        std.testing.allocator.free(config.workspace_id);
        std.testing.allocator.destroy(config);
    }

    try std.testing.expectEqualSlices(u8, &[_]u8{ 127, 0, 0, 1 }, &config.listen_address);
    try std.testing.expectEqual(@as(u16, 8080), config.listen_port);
    try std.testing.expectEqualStrings("http://127.0.0.1:80", config.upstream_url);
    try std.testing.expectEqual(LogLevel.info, config.log_level);
    try std.testing.expectEqual(true, config.pretty_print_json);
    try std.testing.expectEqual(@as(u32, 1048576), config.max_body_size);
    try std.testing.expectEqual(@as(usize, 0), config.policy_providers.len);
}

test "parsePolicyType" {
    try std.testing.expect(try parsePolicyType("filter") == .POLICY_TYPE_LOG_FILTER);
    try std.testing.expect(try parsePolicyType("log_filter") == .POLICY_TYPE_LOG_FILTER);
    try std.testing.expect(try parsePolicyType("redaction") == .POLICY_TYPE_REDACTION);
    try std.testing.expect(try parsePolicyType("redact") == .POLICY_TYPE_REDACTION);
    try std.testing.expectError(error.InvalidPolicyType, parsePolicyType("invalid"));
}

test "parseTelemetryType" {
    try std.testing.expect(try parseTelemetryType("log") == .TELEMETRY_TYPE_LOGS);
    try std.testing.expect(try parseTelemetryType("logs") == .TELEMETRY_TYPE_LOGS);
    try std.testing.expectError(error.InvalidTelemetryType, parseTelemetryType("invalid"));
}

test "parseFilterAction" {
    try std.testing.expect(try parseFilterAction("keep") == .FILTER_ACTION_KEEP);
    try std.testing.expect(try parseFilterAction("drop") == .FILTER_ACTION_DROP);
    try std.testing.expectError(error.InvalidAction, parseFilterAction("invalid"));
}
