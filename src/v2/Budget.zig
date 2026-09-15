//! Checked core-capacity formula (proposal §8). Every term is checked
//! arithmetic; a ceiling that cannot hold one fully reserved request is refused.
const std = @import("std");

pub const Error = error{ Overflow, CeilingBelowOneRequest, MemoryBudgetExceeded };

pub const Inputs = struct {
    /// N: connection slots, each with head/read capacity.
    connections: u32,
    head_bytes: u32,
    /// Admitted requests whose input, candidate output and response may all be
    /// reserved at once (a retry may still need the output while a response lands).
    inflight_requests: u32,
    max_body_bytes: u32,
    max_output_bytes: u32,
    max_response_bytes: u32,
    /// Owned request metadata and copied head bytes, derived from real layouts.
    request_overhead_bytes: u64 = 0,
    /// P processing workers with a fixed workspace each.
    processing_workers: u16,
    processing_workspace_bytes: u64,
    /// F forwarders: lane storage plus the reserved stack per forwarder.
    forwarders: u16,
    lane_bytes: u64,
    forwarder_stack_bytes: u64,
    /// Bounded DNS/control storage.
    control_bytes: u64,
    /// Operator-promised ceiling for the core terms above.
    ceiling_bytes: u64,
};

pub const Terms = struct {
    connections: u64,
    per_request: u64,
    bodies: u64,
    processing: u64,
    forwarding: u64,
    control: u64,
    total: u64,
};

/// Derive core capacity; the caller logs the terms and refuses to start on error.
pub fn core(inputs: Inputs) Error!Terms {
    const per_request = try sum(&.{
        inputs.max_body_bytes, inputs.max_output_bytes, inputs.max_response_bytes, inputs.request_overhead_bytes,
    });
    if (per_request > inputs.ceiling_bytes) return error.CeilingBelowOneRequest;
    const connections = try std.math.mul(u64, inputs.connections, inputs.head_bytes);
    const bodies = try std.math.mul(u64, inputs.inflight_requests, per_request);
    const processing = try std.math.mul(u64, inputs.processing_workers, inputs.processing_workspace_bytes);
    const per_forwarder = try std.math.add(u64, inputs.lane_bytes, inputs.forwarder_stack_bytes);
    const forwarding = try std.math.mul(u64, inputs.forwarders, per_forwarder);
    const total = try sum(&.{ connections, bodies, processing, forwarding, inputs.control_bytes });
    if (total > inputs.ceiling_bytes) return error.MemoryBudgetExceeded;
    return .{
        .connections = connections,
        .per_request = per_request,
        .bodies = bodies,
        .processing = processing,
        .forwarding = forwarding,
        .control = inputs.control_bytes,
        .total = total,
    };
}

fn sum(terms: []const u64) error{Overflow}!u64 {
    var total: u64 = 0;
    for (terms) |term| total = try std.math.add(u64, total, term);
    return total;
}

const MiB = 1024 * 1024;

const proposal_example: Inputs = .{
    .connections = 4 * 256,
    .head_bytes = 20 * 1024,
    .inflight_requests = 64,
    .max_body_bytes = 1536 * 1024,
    .max_output_bytes = 1536 * 1024,
    .max_response_bytes = 16 * MiB,
    .processing_workers = 4,
    .processing_workspace_bytes = 2 * MiB,
    .forwarders = 32,
    .lane_bytes = 64 * 1024,
    .forwarder_stack_bytes = 256 * 1024,
    .control_bytes = MiB,
    .ceiling_bytes = 2048 * MiB,
};

test "v2 budget reserves input, output and response overlap per admitted request" {
    const terms = try core(proposal_example);
    // 1.5 + 1.5 + 16 MiB: a 2 x max_body slot cannot hold the response.
    try std.testing.expectEqual(@as(u64, 19 * MiB), terms.per_request);
    try std.testing.expectEqual(@as(u64, 64 * 19 * MiB), terms.bodies);
    try std.testing.expectEqual(@as(u64, 1024 * 20 * 1024), terms.connections);
    try std.testing.expectEqual(@as(u64, 8 * MiB), terms.processing);
    // Thirty-two 256 KiB stacks alone are 8 MiB before lane storage.
    try std.testing.expectEqual(@as(u64, 32 * (64 + 256) * 1024), terms.forwarding);
    const expected = terms.connections + terms.bodies + terms.processing + terms.forwarding + MiB;
    try std.testing.expectEqual(expected, terms.total);
    try std.testing.expect(terms.total > 1024 * MiB);
}

test "v2 budget reports overflow instead of wrapping" {
    var inputs = proposal_example;
    inputs.ceiling_bytes = std.math.maxInt(u64);
    inputs.inflight_requests = std.math.maxInt(u32);
    inputs.max_response_bytes = std.math.maxInt(u32);
    try std.testing.expectError(error.Overflow, core(inputs));
    inputs = proposal_example;
    inputs.ceiling_bytes = std.math.maxInt(u64);
    inputs.control_bytes = std.math.maxInt(u64);
    try std.testing.expectError(error.Overflow, core(inputs));
}

test "v2 budget refuses a ceiling that cannot hold one request" {
    var inputs = proposal_example;
    inputs.ceiling_bytes = 18 * MiB;
    try std.testing.expectError(error.CeilingBelowOneRequest, core(inputs));
}

test "v2 budget enforces the total ceiling including fixed costs" {
    var inputs = proposal_example;
    const terms = try core(inputs);
    inputs.ceiling_bytes = terms.total - 1;
    try std.testing.expectError(error.MemoryBudgetExceeded, core(inputs));
    inputs.ceiling_bytes = terms.total;
    try std.testing.expectEqual(terms, try core(inputs));
}
