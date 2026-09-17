//! Recovers a request whose only fault is a `content-encoding` value that
//! std's head parser refuses.
//!
//! `std.http.Server.Request.Head.parse` maps the value through
//! `http.ContentEncoding.fromString`, an exact-match table of seven spellings
//! (std/http.zig:283). Anything else fails the whole head with
//! `HttpTransferEncodingUnsupported`, and `Server.receiveHead` flattens that to
//! `HttpHeadersInvalid` (std/http/Server.zig:53), so the sender gets 400. Two
//! real senders hit that:
//!
//!   * `Content-Encoding: GZIP`. RFC 9110 §8.4.1 makes content codings
//!     case-insensitive, and the table is keyed on lowercase bytes.
//!   * `Content-Encoding: br`, or any codec we do not decode. The router
//!     plans `forward_raw` for those (service/datadog.zig), so the batch
//!     should reach the intake untouched rather than be refused.
//!
//! 400 is one of the four statuses the Datadog agent treats as permanent, so
//! either case discards the batch instead of retrying it. That is lost data.
//!
//! The repair rewrites the value in a copy of the head and re-parses:
//! a known coding is lowercased, and an unknown one becomes `identity` so the
//! parse succeeds and the body passes through unread. The caller keeps
//! `encoding`, the value the sender really sent, for the router's decision and
//! for the headers it forwards.
const std = @import("std");

const Head = std.http.Server.Request.Head;

pub const Error = error{
    /// The head has some other fault, so a 400 is the right answer.
    NotRepairable,
    OutOfMemory,
};

/// Why a head needed repair, for telemetry.
pub const Reason = enum {
    /// A known coding, spelled with capitals.
    encoding_case,
    /// A coding std cannot name. The body forwards unread.
    encoding_unknown,
};

pub const Repaired = struct {
    head: Head,
    /// The rewritten head. `head` points into this, so it must outlive the
    /// request; the per-request arena owns it.
    head_buffer: []const u8,
    /// The value the sender sent, duped out of the receive buffer, which the
    /// body read overwrites. For the log line only.
    encoding: []const u8,
    /// What the router must decide on, and what the relay must forward.
    ///
    /// A known coding forwards in the spelling every parser takes, which is
    /// the same coding: case carries no meaning (RFC 9110 §8.4.1). A coding we
    /// cannot name forwards exactly as it arrived, because only the receiver
    /// can decode it. Points into `head_buffer`.
    forward: []const u8,
    reason: Reason,
};

/// The longest value worth considering. A content coding is a token, and the
/// longest std knows is `x-compress` at ten bytes.
const max_value_len = 32;

/// `head` is the raw head, its terminator included.
pub fn repair(head: []const u8, arena: std.mem.Allocator) Error!Repaired {
    if (head.len == 0 or head[head.len - 1] != '\n') return error.NotRepairable;

    const value_span = findEncodingValue(head) orelse return error.NotRepairable;
    const original = head[value_span.start..value_span.end];
    if (original.len == 0 or original.len > max_value_len) return error.NotRepairable;

    var lower_buf: [max_value_len]u8 = undefined;
    const lowered = std.ascii.lowerString(lower_buf[0..original.len], original);

    // A coding std knows, spelled differently: give it the spelling it takes.
    // One it does not know: `identity`, which leaves the body untouched, and
    // the caller forwards the real value instead.
    const reason: Reason = if (std.http.ContentEncoding.fromString(lowered) != null)
        .encoding_case
    else
        .encoding_unknown;
    const replacement = switch (reason) {
        .encoding_case => lowered,
        .encoding_unknown => "identity",
    };
    // Nothing to gain from re-parsing the same bytes.
    if (std.mem.eql(u8, replacement, original)) return error.NotRepairable;

    const rewritten = try std.mem.concat(arena, u8, &.{
        head[0..value_span.start],
        replacement,
        head[value_span.end..],
    });
    const parsed = Head.parse(rewritten) catch return error.NotRepairable;
    return .{
        .head = parsed,
        .head_buffer = rewritten,
        .encoding = try arena.dupe(u8, original),
        .forward = switch (reason) {
            .encoding_case => rewritten[value_span.start..][0..replacement.len],
            .encoding_unknown => try arena.dupe(u8, original),
        },
        .reason = reason,
    };
}

const Span = struct { start: usize, end: usize };

/// Locates the value of the first `content-encoding` header, trimmed of
/// surrounding spaces, as offsets into `head`.
///
/// std's parser takes the first one and refuses a second, so the first is the
/// one that decided the outcome.
fn findEncodingValue(head: []const u8) ?Span {
    // Skip the request line: a target may contain anything.
    var offset = (std.mem.indexOf(u8, head, "\n") orelse return null) + 1;
    while (offset < head.len) {
        const line_end = if (std.mem.findScalar(u8, head[offset..], '\n')) |i| offset + i else head.len;
        const line = std.mem.trimEnd(u8, head[offset..line_end], "\r");
        if (line.len == 0) return null; // end of the headers
        if (std.mem.findScalar(u8, line, ':')) |colon| {
            const name = line[0..colon];
            if (std.ascii.eqlIgnoreCase(name, "content-encoding")) {
                const raw = line[colon + 1 ..];
                const trimmed = std.mem.trim(u8, raw, " \t");
                const start = offset + colon + 1 + (std.mem.indexOf(u8, raw, trimmed) orelse 0);
                return .{ .start = start, .end = start + trimmed.len };
            }
        }
        offset = line_end + 1;
    }
    return null;
}

const testing = std.testing;

fn headWith(comptime encoding: []const u8) []const u8 {
    return "POST /api/v2/logs HTTP/1.1\r\nHost: x\r\ncontent-encoding: " ++
        encoding ++ "\r\ncontent-length: 3\r\n\r\n";
}

test "an uppercase coding is repaired to the spelling std takes" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const raw = headWith("GZIP");
    try testing.expectError(error.HttpTransferEncodingUnsupported, Head.parse(raw));

    const fixed = try repair(raw, arena.allocator());
    try testing.expectEqual(Reason.encoding_case, fixed.reason);
    try testing.expectEqual(std.http.ContentEncoding.gzip, fixed.head.transfer_compression);
    try testing.expectEqualStrings("GZIP", fixed.encoding);
    // Forwarded in the spelling every parser takes, the same coding either way.
    try testing.expectEqualStrings("gzip", fixed.forward);
    try testing.expectEqual(@as(?u64, 3), fixed.head.content_length);
}

test "an unknown coding becomes identity, and the sender's value survives" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const fixed = try repair(headWith("br"), arena.allocator());
    try testing.expectEqual(Reason.encoding_unknown, fixed.reason);
    try testing.expectEqual(std.http.ContentEncoding.identity, fixed.head.transfer_compression);
    try testing.expectEqualStrings("br", fixed.encoding);
    // Only the receiver can decode it, so it forwards exactly as it arrived.
    try testing.expectEqualStrings("br", fixed.forward);
    // The body must pass through unread, so the framing has to survive too.
    try testing.expectEqual(@as(?u64, 3), fixed.head.content_length);
    try testing.expectEqualStrings("/api/v2/logs", fixed.head.target);
}

test "the rewritten head still carries every other header" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const raw = "POST /api/v2/logs HTTP/1.1\r\ncontent-encoding: BR\r\n" ++
        "dd-api-key: secret\r\ncontent-length: 0\r\n\r\n";
    const fixed = try repair(raw, arena.allocator());

    var seen_key = false;
    var seen_encoding: []const u8 = "";
    // What `Request.iterateHeaders` walks, without a `Server` to assert on:
    // it is this iterator over the same bytes.
    var it: std.http.HeaderIterator = .init(fixed.head_buffer);
    while (it.next()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "dd-api-key")) seen_key = true;
        if (std.ascii.eqlIgnoreCase(header.name, "content-encoding")) seen_encoding = header.value;
    }
    try testing.expect(seen_key);
    // The caller puts the sender's value back before it forwards these.
    try testing.expectEqualStrings("identity", seen_encoding);
}

test "a head with another fault is left for the 400" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    // No content-encoding at all: whatever failed, this is not it.
    try testing.expectError(error.NotRepairable, repair(
        "POST / HTTP/1.1\r\ncontent-length: zero\r\n\r\n",
        arena.allocator(),
    ));
    // A coding std already accepts: the fault is elsewhere in the head.
    try testing.expectError(error.NotRepairable, repair(headWith("gzip"), arena.allocator()));
    // Two codings. std refuses double compression, and so do we.
    try testing.expectError(error.NotRepairable, repair(
        "POST / HTTP/1.1\r\ncontent-encoding: GZIP\r\ncontent-encoding: gzip\r\n\r\n",
        arena.allocator(),
    ));
    // Truncated: no terminator, so the bytes are not a head yet.
    try testing.expectError(error.NotRepairable, repair(
        "POST / HTTP/1.1\r\ncontent-encoding: GZIP",
        arena.allocator(),
    ));
    // An empty value.
    try testing.expectError(error.NotRepairable, repair(headWith(""), arena.allocator()));
}

test "spacing around the value does not matter" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const fixed = try repair(headWith("  GZIP  "), arena.allocator());
    try testing.expectEqual(std.http.ContentEncoding.gzip, fixed.head.transfer_compression);
    try testing.expectEqualStrings("GZIP", fixed.encoding);
}
