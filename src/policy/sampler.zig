//! Stateless percentage-based sampling for telemetry policies.
//!
//! Uses a hash of the input to make deterministic keep/drop decisions.
//! The same input always produces the same result, ensuring consistent
//! sampling across distributed systems (e.g., all spans of a trace are
//! either kept or dropped together when using trace_id as input).
//!
//! ## Design Principles
//!
//! - Stateless: No mutable state, purely functional
//! - Deterministic: Same input always produces same result
//! - Uniform distribution: Uses splitmix64 for good avalanche properties
//!
//! ## Usage
//!
//! ```zig
//! const sampler = Sampler{ .percentage = 50 };
//! if (sampler.shouldKeep(trace_id)) {
//!     // Keep this trace
//! }
//! ```

const std = @import("std");
const testing = std.testing;

/// Stateless percentage-based sampler.
///
/// Uses a hash of the input to make deterministic keep/drop decisions.
/// The same input always produces the same result, ensuring consistent
/// sampling across distributed systems (e.g., all spans of a trace are
/// either kept or dropped together when using trace_id as input).
pub const Sampler = struct {
    /// Percentage of items to keep (0-100).
    /// Values > 100 are treated as 100.
    percentage: u8,

    pub fn init(percentage: u8) Sampler {
        return Sampler{ .percentage = percentage };
    }

    /// Decide whether to keep based on hash of input.
    ///
    /// Deterministic: same input always produces same result.
    /// Distribution: approximately `percentage`% of inputs will return true.
    pub fn shouldKeep(self: Sampler, hash_input: u64) bool {
        if (self.percentage == 0) return false;
        if (self.percentage >= 100) return true;

        const hash = mixHash(hash_input);
        const bucket = @as(u8, @truncate(hash % 100));
        return bucket < self.percentage;
    }

    /// splitmix64 hash mixing function.
    /// Provides good avalanche properties to ensure uniform distribution
    /// even for sequential or poorly-distributed inputs.
    fn mixHash(x: u64) u64 {
        var h = x +% 0x9e3779b97f4a7c15;
        h = (h ^ (h >> 30)) *% 0xbf58476d1ce4e5b9;
        h = (h ^ (h >> 27)) *% 0x94d049bb133111eb;
        return h ^ (h >> 31);
    }
};

// =============================================================================
// Tests
// =============================================================================

test "Sampler: zero percentage always rejects" {
    const sampler = Sampler{ .percentage = 0 };

    // Test with various inputs
    try testing.expect(!sampler.shouldKeep(0));
    try testing.expect(!sampler.shouldKeep(1));
    try testing.expect(!sampler.shouldKeep(std.math.maxInt(u64)));
    try testing.expect(!sampler.shouldKeep(0xDEADBEEF));

    // Test sequential inputs
    for (0..1000) |i| {
        try testing.expect(!sampler.shouldKeep(i));
    }
}

test "Sampler: 100 percentage always accepts" {
    const sampler = Sampler{ .percentage = 100 };

    try testing.expect(sampler.shouldKeep(0));
    try testing.expect(sampler.shouldKeep(1));
    try testing.expect(sampler.shouldKeep(std.math.maxInt(u64)));
    try testing.expect(sampler.shouldKeep(0xDEADBEEF));

    for (0..1000) |i| {
        try testing.expect(sampler.shouldKeep(i));
    }
}

test "Sampler: over 100 percentage treated as 100" {
    const sampler = Sampler{ .percentage = 255 };

    for (0..1000) |i| {
        try testing.expect(sampler.shouldKeep(i));
    }
}

test "Sampler: deterministic for same input" {
    const sampler = Sampler{ .percentage = 50 };

    // Same input should always produce same result
    const inputs = [_]u64{ 0, 1, 42, 12345, 0xDEADBEEF, std.math.maxInt(u64) };

    for (inputs) |input| {
        const first_result = sampler.shouldKeep(input);
        // Check 100 times
        for (0..100) |_| {
            try testing.expectEqual(first_result, sampler.shouldKeep(input));
        }
    }
}

test "Sampler: different percentages are independent" {
    const low = Sampler{ .percentage = 10 };
    const high = Sampler{ .percentage = 90 };

    // An input accepted by low should definitely be accepted by high
    // (since low samples a subset of what high samples - both use same hash)
    for (0..1000) |i| {
        if (low.shouldKeep(i)) {
            try testing.expect(high.shouldKeep(i));
        }
    }
}

test "Sampler: approximate distribution for 50%" {
    const sampler = Sampler{ .percentage = 50 };
    var kept: u32 = 0;
    const total: u32 = 10000;

    for (0..total) |i| {
        if (sampler.shouldKeep(i)) kept += 1;
    }

    // Should be roughly 50% (within 5% tolerance for statistical significance)
    const ratio = @as(f64, @floatFromInt(kept)) / @as(f64, @floatFromInt(total));
    try testing.expect(ratio > 0.45 and ratio < 0.55);
}

test "Sampler: approximate distribution for 10%" {
    const sampler = Sampler{ .percentage = 10 };
    var kept: u32 = 0;
    const total: u32 = 10000;

    for (0..total) |i| {
        if (sampler.shouldKeep(i)) kept += 1;
    }

    const ratio = @as(f64, @floatFromInt(kept)) / @as(f64, @floatFromInt(total));
    try testing.expect(ratio > 0.07 and ratio < 0.13);
}

test "Sampler: approximate distribution for 90%" {
    const sampler = Sampler{ .percentage = 90 };
    var kept: u32 = 0;
    const total: u32 = 10000;

    for (0..total) |i| {
        if (sampler.shouldKeep(i)) kept += 1;
    }

    const ratio = @as(f64, @floatFromInt(kept)) / @as(f64, @floatFromInt(total));
    try testing.expect(ratio > 0.87 and ratio < 0.93);
}

test "Sampler: 1% edge case" {
    const sampler = Sampler{ .percentage = 1 };
    var kept: u32 = 0;
    const total: u32 = 100000;

    for (0..total) |i| {
        if (sampler.shouldKeep(i)) kept += 1;
    }

    const ratio = @as(f64, @floatFromInt(kept)) / @as(f64, @floatFromInt(total));
    try testing.expect(ratio > 0.005 and ratio < 0.015);
}

test "Sampler: 99% edge case" {
    const sampler = Sampler{ .percentage = 99 };
    var kept: u32 = 0;
    const total: u32 = 100000;

    for (0..total) |i| {
        if (sampler.shouldKeep(i)) kept += 1;
    }

    const ratio = @as(f64, @floatFromInt(kept)) / @as(f64, @floatFromInt(total));
    try testing.expect(ratio > 0.985 and ratio < 0.995);
}

test "Sampler: hash avalanche - sequential inputs distribute well" {
    // Verify that sequential inputs don't cluster
    const sampler = Sampler{ .percentage = 50 };

    // Count runs of same decision
    var max_run: u32 = 0;
    var current_run: u32 = 1;
    var last_decision = sampler.shouldKeep(0);

    for (1..10000) |i| {
        const decision = sampler.shouldKeep(i);
        if (decision == last_decision) {
            current_run += 1;
            if (current_run > max_run) max_run = current_run;
        } else {
            current_run = 1;
        }
        last_decision = decision;
    }

    // With good distribution, max run should be reasonable
    // For true 50/50, expected max run in 10000 samples is ~13
    // Allow up to 30 to account for variance
    try testing.expect(max_run < 30);
}

test "Sampler: combined usage with RateLimiter" {
    const rate_limiter = @import("rate_limiter.zig");

    // Simulate using both: first sample, then rate limit
    const sampler = Sampler{ .percentage = 50 };
    var limiter = rate_limiter.RateLimiter.initPerSecond(5);

    var kept: u32 = 0;

    for (0..100) |i| {
        // First check sampling, then rate limit
        if (sampler.shouldKeep(i) and limiter.shouldKeep()) {
            kept += 1;
        }
    }

    // Should keep at most 5 (rate limit)
    try testing.expectEqual(@as(u32, 5), kept);
}
