const std = @import("std");
const types = @import("types.zig");
const ProxyConfig = types.ProxyConfig;
const LogLevel = types.LogLevel;

/// Parse a simple key=value configuration file format
pub fn parseConfigFile(allocator: std.mem.Allocator, path: []const u8) !*ProxyConfig {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const stat = try file.stat();
    const contents = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(contents);

    var config = types.ProxyConfig.default();
    config.last_modified = @intCast(stat.mtime);

    var line_iter = std.mem.splitScalar(u8, contents, '\n');
    var line_num: usize = 0;

    while (line_iter.next()) |line| {
        line_num += 1;
        const trimmed = std.mem.trim(u8, line, " \t\r");

        // Skip empty lines and comments
        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        // Skip section headers [section]
        if (trimmed[0] == '[') continue;

        // Parse key=value
        var kv_iter = std.mem.splitScalar(u8, trimmed, '=');
        const key = std.mem.trim(u8, kv_iter.next() orelse continue, " \t");
        const value = std.mem.trim(u8, kv_iter.next() orelse {
            std.log.warn("Line {}: missing value for key '{s}'", .{ line_num, key });
            continue;
        }, " \t\"");

        try parseKeyValue(&config, key, value, line_num);
    }

    const config_ptr = try allocator.create(ProxyConfig);
    config_ptr.* = config;
    return config_ptr;
}

fn parseKeyValue(config: *ProxyConfig, key: []const u8, value: []const u8, line_num: usize) !void {
    if (std.mem.eql(u8, key, "listen_address")) {
        config.listen_address = try parseIpv4(value);
    } else if (std.mem.eql(u8, key, "listen_port")) {
        config.listen_port = try std.fmt.parseInt(u16, value, 10);
    } else if (std.mem.eql(u8, key, "upstream_address")) {
        config.upstream_address = try parseIpv4(value);
    } else if (std.mem.eql(u8, key, "upstream_port")) {
        config.upstream_port = try std.fmt.parseInt(u16, value, 10);
    } else if (std.mem.eql(u8, key, "max_concurrent_connections")) {
        config.max_concurrent_connections = try std.fmt.parseInt(u32, value, 10);
    } else if (std.mem.eql(u8, key, "thread_pool_size")) {
        config.thread_pool_size = try std.fmt.parseInt(u16, value, 10);
    } else if (std.mem.eql(u8, key, "enable_http1")) {
        config.enable_http1 = try parseBool(value);
    } else if (std.mem.eql(u8, key, "enable_http2")) {
        config.enable_http2 = try parseBool(value);
    } else if (std.mem.eql(u8, key, "log_level")) {
        config.log_level = try LogLevel.parse(value);
    } else if (std.mem.eql(u8, key, "pretty_print_json")) {
        config.pretty_print_json = try parseBool(value);
    } else if (std.mem.eql(u8, key, "max_body_size")) {
        config.max_body_size = try std.fmt.parseInt(u32, value, 10);
    } else {
        std.log.warn("Line {}: unknown config key '{s}'", .{ line_num, key });
    }
}

fn parseIpv4(s: []const u8) ![4]u8 {
    var result: [4]u8 = undefined;
    var iter = std.mem.splitScalar(u8, s, '.');
    var i: usize = 0;

    while (iter.next()) |octet| : (i += 1) {
        if (i >= 4) return error.InvalidIpv4;
        result[i] = try std.fmt.parseInt(u8, octet, 10);
    }

    if (i != 4) return error.InvalidIpv4;
    return result;
}

fn parseBool(s: []const u8) !bool {
    if (std.mem.eql(u8, s, "true")) return true;
    if (std.mem.eql(u8, s, "false")) return false;
    return error.InvalidBoolean;
}

test "parseIpv4" {
    const addr = try parseIpv4("127.0.0.1");
    try std.testing.expectEqualSlices(u8, &[_]u8{ 127, 0, 0, 1 }, &addr);

    const addr2 = try parseIpv4("192.168.1.100");
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 100 }, &addr2);

    try std.testing.expectError(error.InvalidIpv4, parseIpv4("256.0.0.1"));
    try std.testing.expectError(error.InvalidIpv4, parseIpv4("127.0.0"));
}

test "parseBool" {
    try std.testing.expectEqual(true, try parseBool("true"));
    try std.testing.expectEqual(false, try parseBool("false"));
    try std.testing.expectError(error.InvalidBoolean, parseBool("yes"));
}
