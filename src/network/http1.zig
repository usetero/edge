const std = @import("std");
const http = std.http;

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const Request = struct {
    method: http.Method,
    target: []const u8,
    version: http.Version,
    headers: []Header,
    body: []const u8,
    /// The raw bytes of the entire request (including headers and body)
    raw: []const u8,

    pub fn getHeader(self: Request, name: []const u8) ?[]const u8 {
        for (self.headers) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, name)) {
                return header.value;
            }
        }
        return null;
    }

    pub fn getContentLength(self: Request) ?usize {
        const value = self.getHeader("Content-Length") orelse return null;
        return std.fmt.parseInt(usize, value, 10) catch null;
    }

    pub fn isChunked(self: Request) bool {
        const encoding = self.getHeader("Transfer-Encoding") orelse return false;
        return std.mem.indexOf(u8, encoding, "chunked") != null;
    }

    pub fn isJson(self: Request) bool {
        const content_type = self.getHeader("Content-Type") orelse return false;
        return std.mem.indexOf(u8, content_type, "application/json") != null;
    }
};

pub const Response = struct {
    version: http.Version,
    status: http.Status,
    headers: []Header,
    body: []const u8,
    /// The raw bytes of the entire response (including headers and body)
    raw: []const u8,

    pub fn getHeader(self: Response, name: []const u8) ?[]const u8 {
        for (self.headers) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, name)) {
                return header.value;
            }
        }
        return null;
    }

    pub fn getContentLength(self: Response) ?usize {
        const value = self.getHeader("Content-Length") orelse return null;
        return std.fmt.parseInt(usize, value, 10) catch null;
    }

    pub fn isChunked(self: Response) bool {
        const encoding = self.getHeader("Transfer-Encoding") orelse return false;
        return std.mem.indexOf(u8, encoding, "chunked") != null;
    }

    pub fn isJson(self: Response) bool {
        const content_type = self.getHeader("Content-Type") orelse return false;
        return std.mem.indexOf(u8, content_type, "application/json") != null;
    }
};

pub const Parser = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Parser {
        return .{ .allocator = allocator };
    }

    pub fn parseRequest(self: Parser, data: []const u8) !Request {
        var headers = std.ArrayList(Header){};
        errdefer headers.deinit(self.allocator);

        // Find end of headers (double CRLF)
        const header_end = std.mem.indexOf(u8, data, "\r\n\r\n") orelse
            std.mem.indexOf(u8, data, "\n\n") orelse
            return error.InvalidRequest;

        const headers_section = data[0..header_end];
        const body_start = if (std.mem.indexOf(u8, data[header_end..], "\r\n\r\n")) |_|
            header_end + 4
        else if (std.mem.indexOf(u8, data[header_end..], "\n\n")) |_|
            header_end + 2
        else
            header_end;

        var lines = std.mem.splitAny(u8, headers_section, "\r\n");

        // Parse request line: METHOD PATH VERSION
        const request_line = lines.next() orelse return error.InvalidRequest;
        var parts = std.mem.splitScalar(u8, request_line, ' ');

        const method_str = parts.next() orelse return error.InvalidRequest;
        const target = parts.next() orelse return error.InvalidRequest;
        const version_str = parts.next() orelse return error.InvalidRequest;

        // Parse method using std.http.Method
        const method = std.meta.stringToEnum(http.Method, method_str) orelse
            return error.UnknownHttpMethod;

        // Parse version using std.http.Version
        const version: http.Version = if (std.mem.eql(u8, version_str, "HTTP/1.0"))
            .@"HTTP/1.0"
        else if (std.mem.eql(u8, version_str, "HTTP/1.1"))
            .@"HTTP/1.1"
        else
            return error.HttpVersionNotSupported;

        // Parse headers
        while (lines.next()) |line| {
            if (line.len == 0) continue;

            const colon_idx = std.mem.indexOf(u8, line, ":") orelse continue;
            const name = std.mem.trim(u8, line[0..colon_idx], " \t");
            const value = std.mem.trim(u8, line[colon_idx + 1 ..], " \t");

            try headers.append(self.allocator, .{ .name = name, .value = value });
        }

        return .{
            .method = method,
            .target = target,
            .version = version,
            .headers = try headers.toOwnedSlice(self.allocator),
            .body = data[body_start..],
            .raw = data,
        };
    }

    pub fn parseResponse(self: Parser, data: []const u8) !Response {
        var headers = std.ArrayList(Header){};
        errdefer headers.deinit(self.allocator);

        // Find end of headers
        const header_end = std.mem.indexOf(u8, data, "\r\n\r\n") orelse
            std.mem.indexOf(u8, data, "\n\n") orelse
            return error.InvalidResponse;

        const headers_section = data[0..header_end];
        const body_start = if (std.mem.indexOf(u8, data[header_end..], "\r\n\r\n")) |_|
            header_end + 4
        else if (std.mem.indexOf(u8, data[header_end..], "\n\n")) |_|
            header_end + 2
        else
            header_end;

        var lines = std.mem.splitAny(u8, headers_section, "\r\n");

        // Parse status line: VERSION STATUS_CODE STATUS_TEXT
        const status_line = lines.next() orelse return error.InvalidResponse;
        var parts = std.mem.splitScalar(u8, status_line, ' ');

        const version_str = parts.next() orelse return error.InvalidResponse;
        const status_code_str = parts.next() orelse return error.InvalidResponse;

        // Parse version
        const version: http.Version = if (std.mem.eql(u8, version_str, "HTTP/1.0"))
            .@"HTTP/1.0"
        else if (std.mem.eql(u8, version_str, "HTTP/1.1"))
            .@"HTTP/1.1"
        else
            return error.HttpVersionNotSupported;

        // Parse status code
        const status_code = try std.fmt.parseInt(u16, status_code_str, 10);
        const status = @as(http.Status, @enumFromInt(status_code));

        // Parse headers
        while (lines.next()) |line| {
            if (line.len == 0) continue;

            const colon_idx = std.mem.indexOf(u8, line, ":") orelse continue;
            const name = std.mem.trim(u8, line[0..colon_idx], " \t");
            const value = std.mem.trim(u8, line[colon_idx + 1 ..], " \t");

            try headers.append(self.allocator, .{ .name = name, .value = value });
        }

        return .{
            .version = version,
            .status = status,
            .headers = try headers.toOwnedSlice(self.allocator),
            .body = data[body_start..],
            .raw = data,
        };
    }
};

test "parseRequest - simple GET" {
    const data = "GET /api/users HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";

    var parser = Parser.init(std.testing.allocator);
    const req = try parser.parseRequest(data);
    defer std.testing.allocator.free(req.headers);

    try std.testing.expectEqual(http.Method.GET, req.method);
    try std.testing.expectEqualStrings("/api/users", req.target);
    try std.testing.expectEqual(http.Version.@"HTTP/1.1", req.version);
    try std.testing.expectEqual(@as(usize, 2), req.headers.len);
}

test "parseRequest - with body" {
    const data = "POST /api/users HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"name\":\"test\"}";

    var parser = Parser.init(std.testing.allocator);
    const req = try parser.parseRequest(data);
    defer std.testing.allocator.free(req.headers);

    try std.testing.expectEqual(http.Method.POST, req.method);
    try std.testing.expectEqualStrings("{\"name\":\"test\"}", req.body);
    try std.testing.expect(req.isJson());
}

test "parseResponse" {
    const data = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}";

    var parser = Parser.init(std.testing.allocator);
    const resp = try parser.parseResponse(data);
    defer std.testing.allocator.free(resp.headers);

    try std.testing.expectEqual(@as(u16, 200), @intFromEnum(resp.status));
    try std.testing.expectEqualStrings("{\"status\":\"ok\"}", resp.body);
}
