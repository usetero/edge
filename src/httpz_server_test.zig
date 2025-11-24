const std = @import("std");
const httpz_server = @import("proxy/httpz_server.zig");
const config_types = @import("config/types.zig");
const filter_mod = @import("filter.zig");
const policy_pb = @import("proto");
const policy_registry_mod = @import("policy_registry.zig");
const policy_source_mod = @import("policy_source.zig");

const testing = std.testing;
const Policy = policy_pb.Policy;
const PolicyType = policy_pb.PolicyType;
const TelemetryType = policy_pb.TelemetryType;
const Action = policy_pb.Action;
const ActionType = policy_pb.ActionType;
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

test "Filter evaluates Datadog log payload - no match keeps payload" {
    var registry = PolicyRegistry.init(testing.allocator);
    defer registry.deinit();

    // Add a filter that drops only ERROR logs
    var error_regexes = std.ArrayListUnmanaged([]const u8).empty;
    try error_regexes.append(testing.allocator, "ERROR");
    defer error_regexes.deinit(testing.allocator);

    const drop_errors = Policy{
        .name = "drop-errors",
        .policy_type = .POLICY_TYPE_FILTER,
        .telemetry_type = .TELEMETRY_TYPE_LOG,
        .regexes = error_regexes,
        .action = Action{ .type = .ACTION_TYPE_DROP },
    };

    const policies = [_]Policy{drop_errors};
    try registry.updatePolicies(&policies, .file);

    var filter = filter_mod.FilterEvaluator.init(&registry);
    defer filter.deinit();

    // Test INFO payload should be kept
    const result = try filter.evaluate(test_payload, .TELEMETRY_TYPE_LOG);
    try testing.expect(result == filter_mod.FilterResult.keep);
}

test "Filter evaluates Datadog log payload - error match drops payload" {
    var registry = PolicyRegistry.init(testing.allocator);
    defer registry.deinit();

    // Add a filter that drops ERROR logs
    var error_regexes = std.ArrayListUnmanaged([]const u8).empty;
    try error_regexes.append(testing.allocator, "ERROR");
    defer error_regexes.deinit(testing.allocator);

    const drop_errors = Policy{
        .name = "drop-errors",
        .policy_type = .POLICY_TYPE_FILTER,
        .telemetry_type = .TELEMETRY_TYPE_LOG,
        .regexes = error_regexes,
        .action = Action{ .type = .ACTION_TYPE_DROP },
    };

    const policies = [_]Policy{drop_errors};
    try registry.updatePolicies(&policies, .file);

    var filter = filter_mod.FilterEvaluator.init(&registry);
    defer filter.deinit();

    // Test ERROR payload should be dropped
    const result = try filter.evaluate(test_payload_with_error, .TELEMETRY_TYPE_LOG);
    try testing.expect(result == filter_mod.FilterResult.drop);
}

test "Filter evaluates Datadog log payload - debug match drops payload" {
    var registry = PolicyRegistry.init(testing.allocator);
    defer registry.deinit();

    // Add a filter that drops DEBUG logs
    var debug_regexes = std.ArrayListUnmanaged([]const u8).empty;
    try debug_regexes.append(testing.allocator, "DEBUG");
    defer debug_regexes.deinit(testing.allocator);

    const drop_debug = Policy{
        .name = "drop-debug",
        .policy_type = .POLICY_TYPE_FILTER,
        .telemetry_type = .TELEMETRY_TYPE_LOG,
        .regexes = debug_regexes,
        .action = Action{ .type = .ACTION_TYPE_DROP },
    };

    const policies = [_]Policy{drop_debug};
    try registry.updatePolicies(&policies, .file);

    var filter = filter_mod.FilterEvaluator.init(&registry);
    defer filter.deinit();

    // Test DEBUG payload should be dropped
    const result = try filter.evaluate(test_payload_with_debug, .TELEMETRY_TYPE_LOG);
    try testing.expect(result == filter_mod.FilterResult.drop);
}

test "Filter with multiple policies - first match wins" {
    var registry = PolicyRegistry.init(testing.allocator);
    defer registry.deinit();

    // Add drop policy for ERROR (first)
    var error_regexes = std.ArrayListUnmanaged([]const u8).empty;
    try error_regexes.append(testing.allocator, "ERROR");
    defer error_regexes.deinit(testing.allocator);

    // Add keep policy for all payment service (second)
    var payment_regexes = std.ArrayListUnmanaged([]const u8).empty;
    try payment_regexes.append(testing.allocator, "payment");
    defer payment_regexes.deinit(testing.allocator);

    const drop_errors = Policy{
        .name = "drop-errors",
        .policy_type = .POLICY_TYPE_FILTER,
        .telemetry_type = .TELEMETRY_TYPE_LOG,
        .regexes = error_regexes,
        .action = Action{ .type = .ACTION_TYPE_DROP },
    };

    const keep_payment = Policy{
        .name = "keep-payment",
        .policy_type = .POLICY_TYPE_FILTER,
        .telemetry_type = .TELEMETRY_TYPE_LOG,
        .regexes = payment_regexes,
        .action = Action{ .type = .ACTION_TYPE_KEEP },
    };

    const policies = [_]Policy{ drop_errors, keep_payment };
    try registry.updatePolicies(&policies, .file);

    var filter = filter_mod.FilterEvaluator.init(&registry);
    defer filter.deinit();

    // ERROR payload matches first policy (drop), should drop despite matching second
    const result = try filter.evaluate(test_payload_with_error, .TELEMETRY_TYPE_LOG);
    try testing.expect(result == filter_mod.FilterResult.drop);
}

test "Filter respects service tags in Datadog payload" {
    var registry = PolicyRegistry.init(testing.allocator);
    defer registry.deinit();

    // Drop logs from payment service
    var service_regexes = std.ArrayListUnmanaged([]const u8).empty;
    try service_regexes.append(testing.allocator, "\"service\": \"payment\"");
    defer service_regexes.deinit(testing.allocator);

    const drop_payment = Policy{
        .name = "drop-payment-service",
        .policy_type = .POLICY_TYPE_FILTER,
        .telemetry_type = .TELEMETRY_TYPE_LOG,
        .regexes = service_regexes,
        .action = Action{ .type = .ACTION_TYPE_DROP },
    };

    const policies = [_]Policy{drop_payment};
    try registry.updatePolicies(&policies, .file);

    var filter = filter_mod.FilterEvaluator.init(&registry);
    defer filter.deinit();

    // All test payloads have payment service
    try testing.expect(try filter.evaluate(test_payload, .TELEMETRY_TYPE_LOG) == filter_mod.FilterResult.drop);
    try testing.expect(try filter.evaluate(test_payload_with_error, .TELEMETRY_TYPE_LOG) == filter_mod.FilterResult.drop);
    try testing.expect(try filter.evaluate(test_payload_with_debug, .TELEMETRY_TYPE_LOG) == filter_mod.FilterResult.drop);
}

test "Filter respects environment tags in Datadog payload" {
    var registry = PolicyRegistry.init(testing.allocator);
    defer registry.deinit();

    // Drop staging environment logs
    var env_regexes = std.ArrayListUnmanaged([]const u8).empty;
    try env_regexes.append(testing.allocator, "env:staging");
    defer env_regexes.deinit(testing.allocator);

    const drop_staging = Policy{
        .name = "drop-staging",
        .policy_type = .POLICY_TYPE_FILTER,
        .telemetry_type = .TELEMETRY_TYPE_LOG,
        .regexes = env_regexes,
        .action = Action{ .type = .ACTION_TYPE_DROP },
    };

    const policies = [_]Policy{drop_staging};
    try registry.updatePolicies(&policies, .file);

    var filter = filter_mod.FilterEvaluator.init(&registry);
    defer filter.deinit();

    // Staging payloads should be dropped
    try testing.expect(try filter.evaluate(test_payload, .TELEMETRY_TYPE_LOG) == filter_mod.FilterResult.drop);

    // Production payload should be kept
    try testing.expect(try filter.evaluate(test_payload_with_error, .TELEMETRY_TYPE_LOG) == filter_mod.FilterResult.keep);

    // Development payload should be kept
    try testing.expect(try filter.evaluate(test_payload_with_debug, .TELEMETRY_TYPE_LOG) == filter_mod.FilterResult.keep);
}

test "Filter matches on hostname in Datadog payload" {
    var registry = PolicyRegistry.init(testing.allocator);
    defer registry.deinit();

    // Drop logs from specific host
    var host_regexes = std.ArrayListUnmanaged([]const u8).empty;
    try host_regexes.append(testing.allocator, "i-012345680");
    defer host_regexes.deinit(testing.allocator);

    const drop_host = Policy{
        .name = "drop-specific-host",
        .policy_type = .POLICY_TYPE_FILTER,
        .telemetry_type = .TELEMETRY_TYPE_LOG,
        .regexes = host_regexes,
        .action = Action{ .type = .ACTION_TYPE_DROP },
    };

    const policies = [_]Policy{drop_host};
    try registry.updatePolicies(&policies, .file);

    var filter = filter_mod.FilterEvaluator.init(&registry);
    defer filter.deinit();

    // Host i-012345680 should be dropped
    try testing.expect(try filter.evaluate(test_payload_with_error, .TELEMETRY_TYPE_LOG) == filter_mod.FilterResult.drop);

    // Other hosts should be kept
    try testing.expect(try filter.evaluate(test_payload, .TELEMETRY_TYPE_LOG) == filter_mod.FilterResult.keep);
    try testing.expect(try filter.evaluate(test_payload_with_debug, .TELEMETRY_TYPE_LOG) == filter_mod.FilterResult.keep);
}

test "Filter complex scenario - multiple conditions" {
    var registry = PolicyRegistry.init(testing.allocator);
    defer registry.deinit();

    // Drop DEBUG logs
    var debug_regexes = std.ArrayListUnmanaged([]const u8).empty;
    try debug_regexes.append(testing.allocator, "DEBUG");
    defer debug_regexes.deinit(testing.allocator);

    // Keep ERROR logs (even though they might match other drop rules)
    var error_regexes = std.ArrayListUnmanaged([]const u8).empty;
    try error_regexes.append(testing.allocator, "ERROR");
    defer error_regexes.deinit(testing.allocator);

    // Drop staging environment
    var staging_regexes = std.ArrayListUnmanaged([]const u8).empty;
    try staging_regexes.append(testing.allocator, "env:staging");
    defer staging_regexes.deinit(testing.allocator);

    const drop_debug = Policy{
        .name = "drop-debug",
        .policy_type = .POLICY_TYPE_FILTER,
        .telemetry_type = .TELEMETRY_TYPE_LOG,
        .regexes = debug_regexes,
        .action = Action{ .type = .ACTION_TYPE_DROP },
    };

    const keep_errors = Policy{
        .name = "keep-errors",
        .policy_type = .POLICY_TYPE_FILTER,
        .telemetry_type = .TELEMETRY_TYPE_LOG,
        .regexes = error_regexes,
        .action = Action{ .type = .ACTION_TYPE_KEEP },
    };

    const drop_staging = Policy{
        .name = "drop-staging",
        .policy_type = .POLICY_TYPE_FILTER,
        .telemetry_type = .TELEMETRY_TYPE_LOG,
        .regexes = staging_regexes,
        .action = Action{ .type = .ACTION_TYPE_DROP },
    };

    const policies = [_]Policy{ drop_debug, keep_errors, drop_staging };
    try registry.updatePolicies(&policies, .file);

    var filter = filter_mod.FilterEvaluator.init(&registry);
    defer filter.deinit();

    // Test scenarios:
    // 1. DEBUG log - matches first rule, dropped
    try testing.expect(try filter.evaluate(test_payload_with_debug, .TELEMETRY_TYPE_LOG) == filter_mod.FilterResult.drop);

    // 2. ERROR log - matches second rule (keep), kept
    try testing.expect(try filter.evaluate(test_payload_with_error, .TELEMETRY_TYPE_LOG) == filter_mod.FilterResult.keep);

    // 3. INFO staging log - matches third rule, dropped
    try testing.expect(try filter.evaluate(test_payload, .TELEMETRY_TYPE_LOG) == filter_mod.FilterResult.drop);
}

test "Empty filter always keeps payload" {
    var registry = PolicyRegistry.init(testing.allocator);
    defer registry.deinit();

    var filter = filter_mod.FilterEvaluator.init(&registry);
    defer filter.deinit();

    // No policies - should default to keep
    try testing.expect(try filter.evaluate(test_payload, .TELEMETRY_TYPE_LOG) == filter_mod.FilterResult.keep);
    try testing.expect(try filter.evaluate(test_payload_with_error, .TELEMETRY_TYPE_LOG) == filter_mod.FilterResult.keep);
    try testing.expect(try filter.evaluate(test_payload_with_debug, .TELEMETRY_TYPE_LOG) == filter_mod.FilterResult.keep);
}
