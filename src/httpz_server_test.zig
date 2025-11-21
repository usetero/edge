const std = @import("std");
const httpz_server = @import("proxy/httpz_server.zig");
const config_types = @import("config/types.zig");
const filter_mod = @import("core/filter.zig");
const policy_mod = @import("core/policy.zig");

const testing = std.testing;

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
    var filter = filter_mod.FilterEvaluator.init(testing.allocator);
    defer filter.deinit();

    // Add a filter that drops only ERROR logs
    const error_patterns = [_][]const u8{"ERROR"};
    const drop_errors = policy_mod.Policy.init(
        "drop-errors",
        .filter,
        .log,
        &error_patterns,
        policy_mod.Action.init(.drop),
    );
    try filter.addPolicy(drop_errors);

    // Test INFO payload should be kept
    const result = try filter.evaluate(test_payload, .log);
    try testing.expect(result == filter_mod.FilterResult.keep);
}

test "Filter evaluates Datadog log payload - error match drops payload" {
    var filter = filter_mod.FilterEvaluator.init(testing.allocator);
    defer filter.deinit();

    // Add a filter that drops ERROR logs
    const error_patterns = [_][]const u8{"ERROR"};
    const drop_errors = policy_mod.Policy.init(
        "drop-errors",
        .filter,
        .log,
        &error_patterns,
        policy_mod.Action.init(.drop),
    );
    try filter.addPolicy(drop_errors);

    // Test ERROR payload should be dropped
    const result = try filter.evaluate(test_payload_with_error, .log);
    try testing.expect(result == filter_mod.FilterResult.drop);
}

test "Filter evaluates Datadog log payload - debug match drops payload" {
    var filter = filter_mod.FilterEvaluator.init(testing.allocator);
    defer filter.deinit();

    // Add a filter that drops DEBUG logs
    const debug_patterns = [_][]const u8{"DEBUG"};
    const drop_debug = policy_mod.Policy.init(
        "drop-debug",
        .filter,
        .log,
        &debug_patterns,
        policy_mod.Action.init(.drop),
    );
    try filter.addPolicy(drop_debug);

    // Test DEBUG payload should be dropped
    const result = try filter.evaluate(test_payload_with_debug, .log);
    try testing.expect(result == filter_mod.FilterResult.drop);
}

test "Filter with multiple policies - first match wins" {
    var filter = filter_mod.FilterEvaluator.init(testing.allocator);
    defer filter.deinit();

    // Add drop policy for ERROR (first)
    const error_patterns = [_][]const u8{"ERROR"};
    const drop_errors = policy_mod.Policy.init(
        "drop-errors",
        .filter,
        .log,
        &error_patterns,
        policy_mod.Action.init(.drop),
    );
    try filter.addPolicy(drop_errors);

    // Add keep policy for all payment service (second)
    const payment_patterns = [_][]const u8{"payment"};
    const keep_payment = policy_mod.Policy.init(
        "keep-payment",
        .filter,
        .log,
        &payment_patterns,
        policy_mod.Action.init(.keep),
    );
    try filter.addPolicy(keep_payment);

    // ERROR payload matches first policy (drop), should drop despite matching second
    const result = try filter.evaluate(test_payload_with_error, .log);
    try testing.expect(result == filter_mod.FilterResult.drop);
}

test "Filter respects service tags in Datadog payload" {
    var filter = filter_mod.FilterEvaluator.init(testing.allocator);
    defer filter.deinit();

    // Drop logs from payment service
    const service_patterns = [_][]const u8{"\"service\": \"payment\""};
    const drop_payment = policy_mod.Policy.init(
        "drop-payment-service",
        .filter,
        .log,
        &service_patterns,
        policy_mod.Action.init(.drop),
    );
    try filter.addPolicy(drop_payment);

    // All test payloads have payment service
    try testing.expect(try filter.evaluate(test_payload, .log) == filter_mod.FilterResult.drop);
    try testing.expect(try filter.evaluate(test_payload_with_error, .log) == filter_mod.FilterResult.drop);
    try testing.expect(try filter.evaluate(test_payload_with_debug, .log) == filter_mod.FilterResult.drop);
}

test "Filter respects environment tags in Datadog payload" {
    var filter = filter_mod.FilterEvaluator.init(testing.allocator);
    defer filter.deinit();

    // Drop staging environment logs
    const env_patterns = [_][]const u8{"env:staging"};
    const drop_staging = policy_mod.Policy.init(
        "drop-staging",
        .filter,
        .log,
        &env_patterns,
        policy_mod.Action.init(.drop),
    );
    try filter.addPolicy(drop_staging);

    // Staging payloads should be dropped
    try testing.expect(try filter.evaluate(test_payload, .log) == filter_mod.FilterResult.drop);

    // Production payload should be kept
    try testing.expect(try filter.evaluate(test_payload_with_error, .log) == filter_mod.FilterResult.keep);

    // Development payload should be kept
    try testing.expect(try filter.evaluate(test_payload_with_debug, .log) == filter_mod.FilterResult.keep);
}

test "Filter matches on hostname in Datadog payload" {
    var filter = filter_mod.FilterEvaluator.init(testing.allocator);
    defer filter.deinit();

    // Drop logs from specific host
    const host_patterns = [_][]const u8{"i-012345680"};
    const drop_host = policy_mod.Policy.init(
        "drop-specific-host",
        .filter,
        .log,
        &host_patterns,
        policy_mod.Action.init(.drop),
    );
    try filter.addPolicy(drop_host);

    // Host i-012345680 should be dropped
    try testing.expect(try filter.evaluate(test_payload_with_error, .log) == filter_mod.FilterResult.drop);

    // Other hosts should be kept
    try testing.expect(try filter.evaluate(test_payload, .log) == filter_mod.FilterResult.keep);
    try testing.expect(try filter.evaluate(test_payload_with_debug, .log) == filter_mod.FilterResult.keep);
}

test "Filter complex scenario - multiple conditions" {
    var filter = filter_mod.FilterEvaluator.init(testing.allocator);
    defer filter.deinit();

    // Drop DEBUG logs
    const debug_patterns = [_][]const u8{"DEBUG"};
    try filter.addPolicy(policy_mod.Policy.init(
        "drop-debug",
        .filter,
        .log,
        &debug_patterns,
        policy_mod.Action.init(.drop),
    ));

    // Keep ERROR logs (even though they might match other drop rules)
    const error_patterns = [_][]const u8{"ERROR"};
    try filter.addPolicy(policy_mod.Policy.init(
        "keep-errors",
        .filter,
        .log,
        &error_patterns,
        policy_mod.Action.init(.keep),
    ));

    // Drop staging environment
    const staging_patterns = [_][]const u8{"env:staging"};
    try filter.addPolicy(policy_mod.Policy.init(
        "drop-staging",
        .filter,
        .log,
        &staging_patterns,
        policy_mod.Action.init(.drop),
    ));

    // Test scenarios:
    // 1. DEBUG log - matches first rule, dropped
    try testing.expect(try filter.evaluate(test_payload_with_debug, .log) == filter_mod.FilterResult.drop);

    // 2. ERROR log - matches second rule (keep), kept
    try testing.expect(try filter.evaluate(test_payload_with_error, .log) == filter_mod.FilterResult.keep);

    // 3. INFO staging log - matches third rule, dropped
    try testing.expect(try filter.evaluate(test_payload, .log) == filter_mod.FilterResult.drop);
}

test "Empty filter always keeps payload" {
    var filter = filter_mod.FilterEvaluator.init(testing.allocator);
    defer filter.deinit();

    // No policies - should default to keep
    try testing.expect(try filter.evaluate(test_payload, .log) == filter_mod.FilterResult.keep);
    try testing.expect(try filter.evaluate(test_payload_with_error, .log) == filter_mod.FilterResult.keep);
    try testing.expect(try filter.evaluate(test_payload_with_debug, .log) == filter_mod.FilterResult.keep);
}
