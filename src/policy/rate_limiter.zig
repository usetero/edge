//! Lock-free rate limiting for telemetry policies.
//!
//! Uses atomic operations for thread-safe access without locks.
//! Designed to be embedded directly in policy structs (24 bytes).
//!
//! ## Design Principles
//!
//! - Lock-free: All operations use atomics, no mutexes
//! - Predictable memory: Fixed size, no allocations
//! - Embeddable: 24 bytes, embed directly in policy structs
//!
//! ## Usage
//!
//! ```zig
//! var limiter = RateLimiter.initPerSecond(100);
//! if (limiter.shouldKeep()) {
//!     // Under rate limit
//! }
//! ```

const std = @import("std");
const testing = std.testing;

/// Lock-free rate limiter for a single policy.
///
/// Designed to be embedded directly in policy structs (24 bytes).
/// Uses atomic operations for thread-safe access without locks.
///
/// Window reset happens inline on first request after expiry via CAS,
/// eliminating the need for a background reset task.
///
/// ## Memory Ordering
///
/// - `window_start`: acquire/release to synchronize window boundaries
/// - `count`: monotonic for increment (relaxed ordering acceptable for counters)
///
/// ## Race Conditions
///
/// At window boundaries, there's a brief race where:
/// 1. Multiple threads may attempt reset simultaneously (CAS ensures only one wins)
/// 2. Threads may increment the old counter after reset (acceptable over-admission)
///
/// The maximum over-admission is bounded by `limit + num_concurrent_threads - 1`.
pub const RateLimiter = struct {
    /// Current request count in this window.
    count: std.atomic.Value(u32) = .init(0),

    /// Window start timestamp in milliseconds since epoch.
    window_start: std.atomic.Value(i64) = .init(0),

    /// Maximum requests allowed per window.
    limit: u32,

    /// Window duration in milliseconds.
    window_ms: u32,

    /// For testing: injectable time source
    time_source: *const fn () i64 = &defaultTimeSource,

    fn defaultTimeSource() i64 {
        return std.time.milliTimestamp();
    }

    /// Initialize a rate limiter with custom window duration.
    pub fn init(limit: u32, window_ms: u32) RateLimiter {
        return initWithTimeSource(limit, window_ms, &defaultTimeSource);
    }

    /// Initialize with injectable time source (for testing).
    pub fn initWithTimeSource(
        limit: u32,
        window_ms: u32,
        time_source: *const fn () i64,
    ) RateLimiter {
        const now = time_source();
        var limiter = RateLimiter{
            .limit = limit,
            .window_ms = window_ms,
            .time_source = time_source,
        };
        limiter.window_start.store(now, .release);
        return limiter;
    }

    /// Initialize a rate limiter with per-second window.
    pub fn initPerSecond(limit: u32) RateLimiter {
        return init(limit, 1000);
    }

    /// Initialize a rate limiter with per-minute window.
    pub fn initPerMinute(limit: u32) RateLimiter {
        return init(limit, 60_000);
    }

    /// Check if request should be allowed. Increments counter atomically.
    ///
    /// Returns true if under the rate limit, false if limit exceeded.
    /// Automatically resets window when expired.
    ///
    /// This is the only public method - checking and incrementing are atomic.
    pub fn shouldKeep(self: *RateLimiter) bool {
        const now = self.time_source();

        // Fast path: check if window might be expired
        const window_start = self.window_start.load(.acquire);
        const elapsed = now - window_start;

        if (elapsed >= self.window_ms) {
            // Window expired - try to reset
            self.tryResetWindow(window_start, now);
        }

        // Increment and check limit
        // fetchAdd returns previous value, so if prev < limit, we're allowed
        const prev = self.count.fetchAdd(1, .monotonic);
        return prev < self.limit;
    }

    /// Attempt to reset the window. Only one thread wins the CAS race.
    fn tryResetWindow(self: *RateLimiter, expected_start: i64, now: i64) void {
        // CAS to claim the reset - only one thread succeeds
        const result = self.window_start.cmpxchgStrong(
            expected_start,
            now,
            .acq_rel,
            .acquire,
        );

        if (result == null) {
            // We won the race, reset the counter
            self.count.store(0, .release);
        }
        // If CAS failed, another thread already reset - that's fine
    }

    /// Get current count (for testing/debugging only).
    pub fn currentCount(self: *const RateLimiter) u32 {
        return self.count.load(.acquire);
    }

    /// Get window start (for testing/debugging only).
    pub fn currentWindowStart(self: *const RateLimiter) i64 {
        return self.window_start.load(.acquire);
    }

    /// Force reset (for testing only).
    pub fn reset(self: *RateLimiter) void {
        self.count.store(0, .release);
        self.window_start.store(self.time_source(), .release);
    }
};

// =============================================================================
// Test Helpers
// =============================================================================

/// Thread-safe mock time source for testing.
/// Uses atomic value that can be advanced from any thread.
const MockTime = struct {
    value: std.atomic.Value(i64),

    fn init(start: i64) MockTime {
        return .{ .value = std.atomic.Value(i64).init(start) };
    }

    fn get(self: *const MockTime) i64 {
        return self.value.load(.acquire);
    }

    fn set(self: *MockTime, time: i64) void {
        self.value.store(time, .release);
    }

    fn advance(self: *MockTime, delta: i64) void {
        _ = self.value.fetchAdd(delta, .acq_rel);
    }
};

// =============================================================================
// Tests - Basic Functionality
// =============================================================================

test "RateLimiter: init sets correct values" {
    var limiter = RateLimiter.init(100, 1000);

    try testing.expectEqual(@as(u32, 100), limiter.limit);
    try testing.expectEqual(@as(u32, 1000), limiter.window_ms);
    try testing.expectEqual(@as(u32, 0), limiter.currentCount());
}

test "RateLimiter: initPerSecond convenience" {
    const limiter = RateLimiter.initPerSecond(50);

    try testing.expectEqual(@as(u32, 50), limiter.limit);
    try testing.expectEqual(@as(u32, 1000), limiter.window_ms);
}

test "RateLimiter: initPerMinute convenience" {
    const limiter = RateLimiter.initPerMinute(1000);

    try testing.expectEqual(@as(u32, 1000), limiter.limit);
    try testing.expectEqual(@as(u32, 60_000), limiter.window_ms);
}

test "RateLimiter: allows requests under limit" {
    var limiter = RateLimiter.initPerSecond(5);

    for (0..5) |_| {
        try testing.expect(limiter.shouldKeep());
    }

    try testing.expectEqual(@as(u32, 5), limiter.currentCount());
}

test "RateLimiter: blocks at limit" {
    var limiter = RateLimiter.initPerSecond(3);

    try testing.expect(limiter.shouldKeep()); // 1
    try testing.expect(limiter.shouldKeep()); // 2
    try testing.expect(limiter.shouldKeep()); // 3
    try testing.expect(!limiter.shouldKeep()); // 4 - blocked

    try testing.expectEqual(@as(u32, 4), limiter.currentCount());
}

test "RateLimiter: limit of 1" {
    var limiter = RateLimiter.initPerSecond(1);

    try testing.expect(limiter.shouldKeep());
    try testing.expect(!limiter.shouldKeep());
    try testing.expect(!limiter.shouldKeep());
}

test "RateLimiter: limit of 0 blocks everything" {
    var limiter = RateLimiter.initPerSecond(0);

    try testing.expect(!limiter.shouldKeep());
    try testing.expect(!limiter.shouldKeep());
}

test "RateLimiter: high limit" {
    var limiter = RateLimiter.initPerSecond(1_000_000);

    for (0..10000) |_| {
        try testing.expect(limiter.shouldKeep());
    }
}

test "RateLimiter: reset clears count" {
    var limiter = RateLimiter.initPerSecond(5);

    _ = limiter.shouldKeep();
    _ = limiter.shouldKeep();
    try testing.expectEqual(@as(u32, 2), limiter.currentCount());

    limiter.reset();
    try testing.expectEqual(@as(u32, 0), limiter.currentCount());

    // Should allow again
    try testing.expect(limiter.shouldKeep());
}

// =============================================================================
// Tests - Window Expiry (using injectable time)
// =============================================================================

test "RateLimiter: window expiry resets count" {
    var mock_time: i64 = 1000;
    const mockTime = struct {
        var time_ptr: *i64 = undefined;
        fn get() i64 {
            return time_ptr.*;
        }
    };
    mockTime.time_ptr = &mock_time;

    var limiter = RateLimiter.initWithTimeSource(3, 100, &mockTime.get);

    // Use up limit
    try testing.expect(limiter.shouldKeep());
    try testing.expect(limiter.shouldKeep());
    try testing.expect(limiter.shouldKeep());
    try testing.expect(!limiter.shouldKeep());

    // Advance time past window
    mock_time = 1150;

    // Should allow again
    try testing.expect(limiter.shouldKeep());
    try testing.expectEqual(@as(u32, 1), limiter.currentCount());
}

test "RateLimiter: window expiry exactly at boundary" {
    var mock_time: i64 = 0;
    const mockTime = struct {
        var time_ptr: *i64 = undefined;
        fn get() i64 {
            return time_ptr.*;
        }
    };
    mockTime.time_ptr = &mock_time;

    var limiter = RateLimiter.initWithTimeSource(2, 100, &mockTime.get);

    _ = limiter.shouldKeep();
    _ = limiter.shouldKeep();
    try testing.expect(!limiter.shouldKeep());

    // Exactly at window boundary
    mock_time = 100;
    try testing.expect(limiter.shouldKeep());
}

test "RateLimiter: multiple window rollovers" {
    var mock_time: i64 = 0;
    const mockTime = struct {
        var time_ptr: *i64 = undefined;
        fn get() i64 {
            return time_ptr.*;
        }
    };
    mockTime.time_ptr = &mock_time;

    var limiter = RateLimiter.initWithTimeSource(2, 100, &mockTime.get);

    // Window 1
    try testing.expect(limiter.shouldKeep());
    try testing.expect(limiter.shouldKeep());
    try testing.expect(!limiter.shouldKeep());

    // Window 2
    mock_time = 100;
    try testing.expect(limiter.shouldKeep());
    try testing.expect(limiter.shouldKeep());
    try testing.expect(!limiter.shouldKeep());

    // Window 3
    mock_time = 200;
    try testing.expect(limiter.shouldKeep());
    try testing.expect(limiter.shouldKeep());
    try testing.expect(!limiter.shouldKeep());

    // Skip to window 10
    mock_time = 900;
    try testing.expect(limiter.shouldKeep());
}

test "RateLimiter: time going backwards handled gracefully" {
    var mock_time: i64 = 1000;
    const mockTime = struct {
        var time_ptr: *i64 = undefined;
        fn get() i64 {
            return time_ptr.*;
        }
    };
    mockTime.time_ptr = &mock_time;

    var limiter = RateLimiter.initWithTimeSource(3, 100, &mockTime.get);

    _ = limiter.shouldKeep();
    _ = limiter.shouldKeep();

    // Time goes backwards (NTP adjustment, etc.)
    mock_time = 500;

    // Should still work - elapsed will be negative, won't trigger reset
    try testing.expect(limiter.shouldKeep());
    try testing.expect(!limiter.shouldKeep());

    // When time catches up, normal operation resumes
    mock_time = 1100;
    try testing.expect(limiter.shouldKeep());
}

test "RateLimiter: very short window with mock time" {
    var mock_time: i64 = 0;
    const mockTime = struct {
        var time_ptr: *i64 = undefined;
        fn get() i64 {
            return time_ptr.*;
        }
    };
    mockTime.time_ptr = &mock_time;

    var limiter = RateLimiter.initWithTimeSource(5, 1, &mockTime.get); // 1ms window

    // Should allow 5, then block
    for (0..5) |_| {
        try testing.expect(limiter.shouldKeep());
    }
    try testing.expect(!limiter.shouldKeep());

    // Advance time past window
    mock_time = 2;
    try testing.expect(limiter.shouldKeep());
}

test "RateLimiter: very long window" {
    var mock_time: i64 = 0;
    const mockTime = struct {
        var time_ptr: *i64 = undefined;
        fn get() i64 {
            return time_ptr.*;
        }
    };
    mockTime.time_ptr = &mock_time;

    // 1 hour window
    var limiter = RateLimiter.initWithTimeSource(100, 3_600_000, &mockTime.get);

    for (0..100) |_| {
        try testing.expect(limiter.shouldKeep());
    }
    try testing.expect(!limiter.shouldKeep());

    // Advance 30 minutes - still blocked
    mock_time = 1_800_000;
    try testing.expect(!limiter.shouldKeep());

    // Advance to 1 hour - reset
    mock_time = 3_600_000;
    try testing.expect(limiter.shouldKeep());
}

// =============================================================================
// Tests - Concurrent Access
// =============================================================================

test "RateLimiter: concurrent increments respect limit" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;

    // Use a high limit that won't expire during test
    var limiter = RateLimiter.initPerSecond(1000);
    var kept = std.atomic.Value(u32).init(0);

    const thread_count = 8;
    const iterations_per_thread = 200;
    var threads: [thread_count]std.Thread = undefined;

    for (&threads) |*t| {
        t.* = try std.Thread.spawn(.{}, struct {
            fn run(lim: *RateLimiter, k: *std.atomic.Value(u32)) void {
                for (0..iterations_per_thread) |_| {
                    if (lim.shouldKeep()) {
                        _ = k.fetchAdd(1, .monotonic);
                    }
                }
            }
        }.run, .{ &limiter, &kept });
    }

    for (&threads) |*t| {
        t.join();
    }

    // Should keep exactly 1000 (the limit)
    const kept_count = kept.load(.acquire);
    try testing.expectEqual(@as(u32, 1000), kept_count);
}

test "RateLimiter: concurrent access with window reset" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;

    // Shared mock time that threads will advance
    var mock_time = MockTime.init(0);
    const getMockTime = struct {
        var time: *MockTime = undefined;
        fn get() i64 {
            return time.get();
        }
    };
    getMockTime.time = &mock_time;

    var limiter = RateLimiter.initWithTimeSource(10, 100, &getMockTime.get);
    var total_kept = std.atomic.Value(u32).init(0);
    var windows_processed = std.atomic.Value(u32).init(0);

    const thread_count = 4;
    var threads: [thread_count]std.Thread = undefined;

    for (&threads) |*t| {
        t.* = try std.Thread.spawn(.{}, struct {
            fn run(
                lim: *RateLimiter,
                k: *std.atomic.Value(u32),
                w: *std.atomic.Value(u32),
                mt: *MockTime,
            ) void {
                // Each thread processes multiple "windows"
                for (0..5) |_| {
                    // Try to get through limit
                    for (0..20) |_| {
                        if (lim.shouldKeep()) {
                            _ = k.fetchAdd(1, .monotonic);
                        }
                    }
                    _ = w.fetchAdd(1, .monotonic);
                    // Advance time (all threads do this, but that's fine)
                    mt.advance(100);
                }
            }
        }.run, .{ &limiter, &total_kept, &windows_processed, &mock_time });
    }

    for (&threads) |*t| {
        t.join();
    }

    // Each window allows 10, we have 5 windows per thread, 4 threads
    // Due to races at window boundaries, we allow some variance
    const kept = total_kept.load(.acquire);
    // Should be roughly 10 * 5 = 50 (per logical window advance)
    // But with concurrent advances and races, bounds are wider
    try testing.expect(kept >= 40); // At least got a reasonable amount
    try testing.expect(kept <= 200); // Didn't explode
}

test "RateLimiter: no data races under contention" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;

    var limiter = RateLimiter.initPerSecond(1000);
    var iterations = std.atomic.Value(u32).init(0);

    const thread_count = 8;
    var threads: [thread_count]std.Thread = undefined;

    for (&threads) |*t| {
        t.* = try std.Thread.spawn(.{}, struct {
            fn run(lim: *RateLimiter, iters: *std.atomic.Value(u32)) void {
                for (0..1000) |_| {
                    _ = lim.shouldKeep();
                    _ = iters.fetchAdd(1, .monotonic);
                }
            }
        }.run, .{ &limiter, &iterations });
    }

    for (&threads) |*t| {
        t.join();
    }

    // All iterations should complete
    try testing.expectEqual(@as(u32, thread_count * 1000), iterations.load(.acquire));

    // Count should be exactly thread_count * 1000
    try testing.expectEqual(@as(u32, thread_count * 1000), limiter.currentCount());
}

test "RateLimiter: CAS race at window boundary" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;

    // Test that CAS correctly handles multiple threads trying to reset
    var mock_time = MockTime.init(0);
    const getMockTime = struct {
        var time: *MockTime = undefined;
        fn get() i64 {
            return time.get();
        }
    };
    getMockTime.time = &mock_time;

    var limiter = RateLimiter.initWithTimeSource(5, 100, &getMockTime.get);
    var reset_count = std.atomic.Value(u32).init(0);

    // Exhaust limit
    for (0..5) |_| {
        _ = limiter.shouldKeep();
    }

    // Advance time to trigger reset
    mock_time.set(100);

    // Spawn threads that all try to trigger reset simultaneously
    const thread_count = 8;
    var threads: [thread_count]std.Thread = undefined;

    for (&threads) |*t| {
        t.* = try std.Thread.spawn(.{}, struct {
            fn run(lim: *RateLimiter, rc: *std.atomic.Value(u32)) void {
                const before = lim.currentWindowStart();
                _ = lim.shouldKeep();
                const after = lim.currentWindowStart();
                // If window changed, we observed a reset
                if (after != before) {
                    _ = rc.fetchAdd(1, .monotonic);
                }
            }
        }.run, .{ &limiter, &reset_count });
    }

    for (&threads) |*t| {
        t.join();
    }

    // Window should have been reset (new start time)
    try testing.expectEqual(@as(i64, 100), limiter.currentWindowStart());

    // Count should be thread_count (all threads incremented after reset)
    try testing.expectEqual(@as(u32, thread_count), limiter.currentCount());
}

// =============================================================================
// Tests - Edge Cases
// =============================================================================

test "RateLimiter: max u32 limit" {
    var limiter = RateLimiter.initPerSecond(std.math.maxInt(u32));

    for (0..10000) |_| {
        try testing.expect(limiter.shouldKeep());
    }
}

test "RateLimiter: count overflow protection" {
    var limiter = RateLimiter.initPerSecond(5);

    // Exhaust limit
    for (0..5) |_| {
        _ = limiter.shouldKeep();
    }

    // Hammer it many times past limit
    for (0..10000) |_| {
        try testing.expect(!limiter.shouldKeep());
    }

    // Count will be high but shouldKeep still works correctly
    try testing.expect(limiter.currentCount() > 5);
}

test "RateLimiter: window_ms of 0 always resets" {
    var mock_time: i64 = 0;
    const mockTime = struct {
        var time_ptr: *i64 = undefined;
        fn get() i64 {
            return time_ptr.*;
        }
    };
    mockTime.time_ptr = &mock_time;

    // Edge case: 0ms window means always expired
    var limiter = RateLimiter.initWithTimeSource(2, 0, &mockTime.get);

    // First two should be allowed (reset happens, then increment)
    try testing.expect(limiter.shouldKeep());
    try testing.expect(limiter.shouldKeep());
    // Third triggers reset again since elapsed >= 0 is always true
    try testing.expect(limiter.shouldKeep());
}

test "RateLimiter: i64 time overflow edge case" {
    var mock_time: i64 = std.math.maxInt(i64) - 50;
    const mockTime = struct {
        var time_ptr: *i64 = undefined;
        fn get() i64 {
            return time_ptr.*;
        }
    };
    mockTime.time_ptr = &mock_time;

    var limiter = RateLimiter.initWithTimeSource(3, 100, &mockTime.get);

    try testing.expect(limiter.shouldKeep());
    try testing.expect(limiter.shouldKeep());
    try testing.expect(limiter.shouldKeep());
    try testing.expect(!limiter.shouldKeep());

    // Would overflow if we add 100, but subtraction handles this
    // This is technically undefined behavior territory, but practically
    // we won't hit i64 max milliseconds (292 million years)
}
