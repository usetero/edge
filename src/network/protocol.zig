const std = @import("std");

pub const Protocol = enum {
    unknown,
    http1,
    http2,
};

/// Detect HTTP protocol version from first bytes
pub fn detect(data: []const u8) Protocol {
    if (data.len < 3) return .unknown;

    // HTTP/2 connection preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    if (std.mem.startsWith(u8, data, "PRI * HTTP/2")) {
        return .http2;
    }

    // HTTP/1.x methods
    if (std.mem.startsWith(u8, data, "GET ") or
        std.mem.startsWith(u8, data, "POST ") or
        std.mem.startsWith(u8, data, "PUT ") or
        std.mem.startsWith(u8, data, "DELETE ") or
        std.mem.startsWith(u8, data, "HEAD ") or
        std.mem.startsWith(u8, data, "OPTIONS ") or
        std.mem.startsWith(u8, data, "PATCH ") or
        std.mem.startsWith(u8, data, "CONNECT ") or
        std.mem.startsWith(u8, data, "TRACE "))
    {
        return .http1;
    }

    // HTTP/1.x response
    if (std.mem.startsWith(u8, data, "HTTP/1.")) {
        return .http1;
    }

    return .unknown;
}

test "detect - HTTP/1.1 GET" {
    const data = "GET /api HTTP/1.1\r\n";
    try std.testing.expectEqual(Protocol.http1, detect(data));
}

test "detect - HTTP/1.1 POST" {
    const data = "POST /users HTTP/1.1\r\n";
    try std.testing.expectEqual(Protocol.http1, detect(data));
}

test "detect - HTTP/2 preface" {
    const data = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    try std.testing.expectEqual(Protocol.http2, detect(data));
}

test "detect - unknown" {
    const data = "INVALID";
    try std.testing.expectEqual(Protocol.unknown, detect(data));
}
