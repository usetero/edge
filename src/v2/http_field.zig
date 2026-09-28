//! Shared byte-level field syntax for heads and trailers; never folds or decodes.

const std = @import("std");

/// These describe the original representation and become stale after a rewrite.
pub fn representationField(name: []const u8) bool {
    for ([_][]const u8{ "etag", "last-modified", "content-md5", "digest", "content-digest", "repr-digest" }) |field| {
        if (std.ascii.eqlIgnoreCase(name, field)) return true;
    }
    return false;
}

/// Refuse critical late overrides in both ingress and outbound planning. The
/// writer must also apply Connection nominations from the original head.
pub fn forbiddenTrailer(name: []const u8) bool {
    const names = [_][]const u8{
        "content-length",   "transfer-encoding", "host",              "connection",          "trailer",
        "te",               "upgrade",           "keep-alive",        "proxy-connection",    "content-encoding",
        "content-type",     "content-range",     "authorization",     "proxy-authorization", "proxy-authenticate",
        "www-authenticate", "expect",            "cache-control",     "max-forwards",        "range",
        "if-match",         "if-none-match",     "if-modified-since", "if-unmodified-since", "if-range",
    };
    for (names) |forbidden| if (std.ascii.eqlIgnoreCase(name, forbidden)) return true;
    return false;
}

pub const Span = struct {
    start: u32,
    len: u32,

    /// The owner must supply original head/trailer bytes or an identical copy, kept alive
    /// for the returned borrow. Bounds do not establish byte identity.
    pub fn slice(self: Span, bytes: []const u8) []const u8 {
        std.debug.assert(self.start <= bytes.len);
        std.debug.assert(self.len <= bytes.len - self.start);
        return bytes[self.start..][0..self.len];
    }
};

pub const Field = struct { name: Span, value: Span };

/// Match against every original Connection value, before any metadata is removed.
/// Validated heads bound both token syntax and total scanning work.
pub fn nominated(name: []const u8, bytes: []const u8, fields: []const Field) bool {
    for (fields) |field| {
        if (!std.ascii.eqlIgnoreCase(field.name.slice(bytes), "connection")) continue;
        var tokens = std.mem.splitScalar(u8, field.value.slice(bytes), ',');
        while (tokens.next()) |part| {
            if (std.ascii.eqlIgnoreCase(name, std.mem.trim(u8, part, " \t"))) return true;
        }
    }
    return false;
}

/// Strict CRLF boundaries shared by complete request/response head validation.
/// The caller bounds bytes to u32 and keeps the cursor within that slice.
pub fn nextLine(bytes: []const u8, cursor: *usize) !Span {
    const start = cursor.*;
    const newline = std.mem.findScalar(u8, bytes[start..], '\n') orelse return error.IncompleteHead;
    if (newline == 0 or bytes[start + newline - 1] != '\r') return error.InvalidLineEnding;
    const line = bytes[start..][0 .. newline - 1];
    if (std.mem.findScalar(u8, line, '\r') != null) return error.InvalidLineEnding;
    cursor.* = start + newline + 1;
    return .{ .start = @intCast(start), .len = @intCast(line.len) };
}

/// A length is decimal digits only, never a signed number or comma list.
pub fn contentLength(value: []const u8) !u64 {
    if (value.len == 0) return error.InvalidContentLength;
    var result: u64 = 0;
    for (value) |byte| {
        if (byte < '0' or byte > '9') return error.InvalidContentLength;
        const scaled = @mulWithOverflow(result, 10);
        const added = @addWithOverflow(scaled[0], byte - '0');
        if (scaled[1] != 0 or added[1] != 0) return error.InvalidContentLength;
        result = added[0];
    }
    return result;
}

/// Validate the entire list, including tokens after close. Empty list members
/// are ignored; the enclosing head-byte limit bounds their scan cost.
pub fn connectionClose(value: []const u8) !bool {
    var close = false;
    var tokens = std.mem.splitScalar(u8, value, ',');
    while (tokens.next()) |part| {
        const token = std.mem.trim(u8, part, " \t");
        if (token.len == 0) continue;
        if (!validToken(token)) return error.InvalidConnection;
        if (std.ascii.eqlIgnoreCase(token, "close")) close = true;
    }
    return close;
}

/// Validate a field line excluding CRLF; offsets refer to the supplied storage.
pub fn parse(bytes: []const u8, line: Span) !Field {
    const raw = line.slice(bytes);
    const colon = std.mem.findScalar(u8, raw, ':') orelse return error.InvalidFieldName;
    if (!validToken(raw[0..colon])) return error.InvalidFieldName;
    const value = std.mem.trim(u8, raw[colon + 1 ..], " \t");
    for (value) |byte| {
        if ((byte < 0x20 and byte != '\t') or byte == 0x7f) return error.InvalidFieldValue;
    }
    return .{
        .name = .{ .start = line.start, .len = @intCast(colon) },
        .value = .{ .start = @intCast(@intFromPtr(value.ptr) - @intFromPtr(bytes.ptr)), .len = @intCast(value.len) },
    };
}

/// HTTP token syntax shared by methods, field names and chunk extensions.
pub fn validToken(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |byte| {
        if (std.ascii.isAlphanumeric(byte)) continue;
        switch (byte) {
            '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => {},
            else => return false,
        }
    }
    return true;
}
