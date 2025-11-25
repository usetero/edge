const std = @import("std");
const httpz_server = @import("proxy/httpz_server.zig");
const config_types = @import("config/types.zig");
const filter_mod = @import("filter.zig");
const proto = @import("proto");
const policy_registry_mod = @import("policy_registry.zig");
const policy_source_mod = @import("policy_source.zig");

const testing = std.testing;
const Policy = proto.policy.Policy;
const PolicyType = proto.policy.PolicyType;
const TelemetryType = proto.policy.TelemetryType;
const FilterAction = proto.policy.FilterAction;
const FilterConfig = proto.policy.FilterConfig;
const Matcher = proto.policy.Matcher;
const PolicyRegistry = policy_registry_mod.PolicyRegistry;
const SourceType = policy_source_mod.SourceType;

/// Test payload matching Datadog log ingestion format
const test_payload =
    \\[
    \\  {
    \\    "ddsource": "nginx",
    \\    "ddtags": "env:staging,version:5.1",
    \\    "hostname": "i-012345678",
    \\    "message": "2019-11-19T14:37:58,995 INFO [process.name][20081] Hello",
    \\    "service": "payment"
    \\  },
    \\  {
    \\    "ddsource": "nginx",
    \\    "ddtags": "env:staging,version:5.1",
    \\    "hostname": "i-012345679",
    \\    "message": "2019-11-19T14:37:58,995 INFO [process.name][20081] World",
    \\    "service": "payment"
    \\  }
    \\]
;

/// Test payload with error level message
const test_payload_with_error =
    \\[
    \\  {
    \\    "ddsource": "nginx",
    \\    "ddtags": "env:production,version:5.1",
    \\    "hostname": "i-012345680",
    \\    "message": "2019-11-19T14:37:58,995 ERROR [process.name][20081] Critical failure",
    \\    "service": "payment"
    \\  }
    \\]
;

/// Test payload with debug level message
const test_payload_with_debug =
    \\[
    \\  {
    \\    "ddsource": "nginx",
    \\    "ddtags": "env:development,version:5.1",
    \\    "hostname": "i-012345681",
    \\    "message": "2019-11-19T14:37:58,995 DEBUG [process.name][20081] Debug info",
    \\    "service": "payment"
    \\  }
    \\]
;

/// Helper to create a filter policy with matchers
fn createFilterPolicy(
    allocator: std.mem.Allocator,
    name: []const u8,
    patterns: []const []const u8,
    action: FilterAction,
) !Policy {
    var matchers = std.ArrayListUnmanaged(Matcher){};
    try matchers.ensureTotalCapacity(allocator, patterns.len);
    for (patterns) |pattern| {
        matchers.appendAssumeCapacity(.{
            .path = "$.message",
            .regex = pattern,
        });
    }

    var telemetry_types = std.ArrayListUnmanaged(TelemetryType){};
    try telemetry_types.append(allocator, .TELEMETRY_TYPE_LOGS);

    return Policy{
        .name = name,
        .policy_type = .POLICY_TYPE_LOG_FILTER,
        .telemetry_types = telemetry_types,
        .enabled = true,
        .config = .{
            .filter = FilterConfig{
                .matchers = matchers,
                .action = action,
            },
        },
    };
}

test "Filter evaluates Datadog log payload - no match keeps payload" {
    var registry = PolicyRegistry.init(testing.allocator);
    defer registry.deinit();

    // Add a filter that drops only ERROR logs
    const drop_errors = try createFilterPolicy(
        testing.allocator,
        "drop-errors",
        &.{"ERROR"},
        .FILTER_ACTION_DROP,
    );

    const policies = [_]Policy{drop_errors};
    try registry.updatePolicies(&policies, .file);

    var filter = filter_mod.FilterEvaluator.init(&registry);
    defer filter.deinit();

    // Test INFO payload should be kept (no match = keep)
    const result = try filter.evaluate(test_payload, .TELEMETRY_TYPE_LOGS);
    try testing.expect(result == filter_mod.FilterResult.keep);
}

test "Filter evaluates Datadog log payload - error match drops payload" {
    var registry = PolicyRegistry.init(testing.allocator);
    defer registry.deinit();

    // Add a filter that drops ERROR logs
    const drop_errors = try createFilterPolicy(
        testing.allocator,
        "drop-errors",
        &.{"ERROR"},
        .FILTER_ACTION_DROP,
    );

    const policies = [_]Policy{drop_errors};
    try registry.updatePolicies(&policies, .file);

    var filter = filter_mod.FilterEvaluator.init(&registry);
    defer filter.deinit();

    // Test ERROR payload should be dropped
    const result = try filter.evaluate(test_payload_with_error, .TELEMETRY_TYPE_LOGS);
    try testing.expect(result == filter_mod.FilterResult.drop);
}

test "Filter evaluates Datadog log payload - debug match drops payload" {
    var registry = PolicyRegistry.init(testing.allocator);
    defer registry.deinit();

    // Add a filter that drops DEBUG logs
    const drop_debug = try createFilterPolicy(
        testing.allocator,
        "drop-debug",
        &.{"DEBUG"},
        .FILTER_ACTION_DROP,
    );

    const policies = [_]Policy{drop_debug};
    try registry.updatePolicies(&policies, .file);

    var filter = filter_mod.FilterEvaluator.init(&registry);
    defer filter.deinit();

    // Test DEBUG payload should be dropped
    const result = try filter.evaluate(test_payload_with_debug, .TELEMETRY_TYPE_LOGS);
    try testing.expect(result == filter_mod.FilterResult.drop);
}

test "Filter with multiple policies - first match wins" {
    var registry = PolicyRegistry.init(testing.allocator);
    defer registry.deinit();

    // Add drop policy for ERROR (first)
    const drop_errors = try createFilterPolicy(
        testing.allocator,
        "drop-errors",
        &.{"ERROR"},
        .FILTER_ACTION_DROP,
    );

    // Add keep policy for all payment service (second)
    const keep_payment = try createFilterPolicy(
        testing.allocator,
        "keep-payment",
        &.{"payment"},
        .FILTER_ACTION_KEEP,
    );

    const policies = [_]Policy{ drop_errors, keep_payment };
    try registry.updatePolicies(&policies, .file);

    var filter = filter_mod.FilterEvaluator.init(&registry);
    defer filter.deinit();

    // ERROR payload matches first policy (drop), should drop despite matching second
    const result = try filter.evaluate(test_payload_with_error, .TELEMETRY_TYPE_LOGS);
    try testing.expect(result == filter_mod.FilterResult.drop);
}

test "Filter respects service tags in Datadog payload" {
    var registry = PolicyRegistry.init(testing.allocator);
    defer registry.deinit();

    // Drop logs from payment service
    const drop_payment = try createFilterPolicy(
        testing.allocator,
        "drop-payment-service",
        &.{"\"service\": \"payment\""},
        .FILTER_ACTION_DROP,
    );

    const policies = [_]Policy{drop_payment};
    try registry.updatePolicies(&policies, .file);

    var filter = filter_mod.FilterEvaluator.init(&registry);
    defer filter.deinit();

    // All test payloads have payment service
    try testing.expect(try filter.evaluate(test_payload, .TELEMETRY_TYPE_LOGS) == filter_mod.FilterResult.drop);
    try testing.expect(try filter.evaluate(test_payload_with_error, .TELEMETRY_TYPE_LOGS) == filter_mod.FilterResult.drop);
    try testing.expect(try filter.evaluate(test_payload_with_debug, .TELEMETRY_TYPE_LOGS) == filter_mod.FilterResult.drop);
}

test "Filter respects environment tags in Datadog payload" {
    var registry = PolicyRegistry.init(testing.allocator);
    defer registry.deinit();

    // Drop staging environment logs
    const drop_staging = try createFilterPolicy(
        testing.allocator,
        "drop-staging",
        &.{"env:staging"},
        .FILTER_ACTION_DROP,
    );

    const policies = [_]Policy{drop_staging};
    try registry.updatePolicies(&policies, .file);

    var filter = filter_mod.FilterEvaluator.init(&registry);
    defer filter.deinit();

    // Staging payloads should be dropped
    try testing.expect(try filter.evaluate(test_payload, .TELEMETRY_TYPE_LOGS) == filter_mod.FilterResult.drop);

    // Production payload should be kept
    try testing.expect(try filter.evaluate(test_payload_with_error, .TELEMETRY_TYPE_LOGS) == filter_mod.FilterResult.keep);

    // Development payload should be kept
    try testing.expect(try filter.evaluate(test_payload_with_debug, .TELEMETRY_TYPE_LOGS) == filter_mod.FilterResult.keep);
}

test "Filter matches on hostname in Datadog payload" {
    var registry = PolicyRegistry.init(testing.allocator);
    defer registry.deinit();

    // Drop logs from specific host
    const drop_host = try createFilterPolicy(
        testing.allocator,
        "drop-specific-host",
        &.{"i-012345680"},
        .FILTER_ACTION_DROP,
    );

    const policies = [_]Policy{drop_host};
    try registry.updatePolicies(&policies, .file);

    var filter = filter_mod.FilterEvaluator.init(&registry);
    defer filter.deinit();

    // Host i-012345680 should be dropped
    try testing.expect(try filter.evaluate(test_payload_with_error, .TELEMETRY_TYPE_LOGS) == filter_mod.FilterResult.drop);

    // Other hosts should be kept
    try testing.expect(try filter.evaluate(test_payload, .TELEMETRY_TYPE_LOGS) == filter_mod.FilterResult.keep);
    try testing.expect(try filter.evaluate(test_payload_with_debug, .TELEMETRY_TYPE_LOGS) == filter_mod.FilterResult.keep);
}

test "Filter complex scenario - multiple conditions" {
    var registry = PolicyRegistry.init(testing.allocator);
    defer registry.deinit();

    // Drop DEBUG logs
    const drop_debug = try createFilterPolicy(
        testing.allocator,
        "drop-debug",
        &.{"DEBUG"},
        .FILTER_ACTION_DROP,
    );

    // Keep ERROR logs (even though they might match other drop rules)
    const keep_errors = try createFilterPolicy(
        testing.allocator,
        "keep-errors",
        &.{"ERROR"},
        .FILTER_ACTION_KEEP,
    );

    // Drop staging environment
    const drop_staging = try createFilterPolicy(
        testing.allocator,
        "drop-staging",
        &.{"env:staging"},
        .FILTER_ACTION_DROP,
    );

    const policies = [_]Policy{ drop_debug, keep_errors, drop_staging };
    try registry.updatePolicies(&policies, .file);

    var filter = filter_mod.FilterEvaluator.init(&registry);
    defer filter.deinit();

    // Test scenarios:
    // 1. DEBUG log - matches first rule, dropped
    try testing.expect(try filter.evaluate(test_payload_with_debug, .TELEMETRY_TYPE_LOGS) == filter_mod.FilterResult.drop);

    // 2. ERROR log - matches second rule (keep), kept
    try testing.expect(try filter.evaluate(test_payload_with_error, .TELEMETRY_TYPE_LOGS) == filter_mod.FilterResult.keep);

    // 3. INFO staging log - matches third rule, dropped
    try testing.expect(try filter.evaluate(test_payload, .TELEMETRY_TYPE_LOGS) == filter_mod.FilterResult.drop);
}

test "Empty filter always keeps payload" {
    var registry = PolicyRegistry.init(testing.allocator);
    defer registry.deinit();

    var filter = filter_mod.FilterEvaluator.init(&registry);
    defer filter.deinit();

    // No policies - should default to keep
    try testing.expect(try filter.evaluate(test_payload, .TELEMETRY_TYPE_LOGS) == filter_mod.FilterResult.keep);
    try testing.expect(try filter.evaluate(test_payload_with_error, .TELEMETRY_TYPE_LOGS) == filter_mod.FilterResult.keep);
    try testing.expect(try filter.evaluate(test_payload_with_debug, .TELEMETRY_TYPE_LOGS) == filter_mod.FilterResult.keep);
}
