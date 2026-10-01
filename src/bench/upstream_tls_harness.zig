//! Driver for bench/matrix/tests/test_b28_tls_body.py.
//! Uses the production pooled and retry clients against a local TLS intake.
const std = @import("std");
const upstream = @import("upstream");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 3) return error.ExpectedUrlAndCertificate;
    const uri = try std.Uri.parse(args[1]);
    var manager = upstream.UpstreamManager.init(init.io, init.gpa, 1);
    defer manager.deinit();
    const payload = try init.gpa.alloc(u8, 1024 * 1024 + 512);
    defer init.gpa.free(payload);
    for (payload, 0..) |*byte, i| byte.* = @truncate(i);

    for ([_]*std.http.Client{ &manager.http_client, &manager.retry_client }) |client| {
        // Trust only this run's temporary certificate, without changing the
        // machine's trust store or disabling certificate verification.
        client.now = std.Io.Timestamp.now(init.io, .real);
        try client.ca_bundle.addCertsFromFilePathAbsolute(init.gpa, init.io, client.now.?, args[2]);
        // Sweep every byte around a TLS record boundary: ordinary round batch
        // sizes miss the narrow window where flush used to discard the tail.
        for (16300..16700) |len| try send(client, uri, payload[0..len], false);
        // Exercise repeated records and the socket-to-socket pump buffer too.
        for ([_]usize{ 32768, 262144, 524288, 1048576 }) |base| {
            for (0..64) |offset| try send(client, uri, payload[0 .. base + offset], true);
        }
    }
}

fn send(client: *std.http.Client, uri: std.Uri, payload: []const u8, streamed: bool) !void {
    var request = try client.request(.POST, uri, .{ .redirect_behavior = .unhandled });
    defer request.deinit();
    request.transfer_encoding = .{ .content_length = payload.len };
    var buffer: [512 * 1024]u8 = undefined;
    // Match exchange.sendBody's buffered and streamed write paths.
    const write_buffer = if (streamed) buffer[0..] else buffer[0 .. 20 * 1024];
    var body = try request.sendBodyUnflushed(write_buffer);
    if (streamed) {
        var reader: std.Io.Reader = .fixed(payload);
        try reader.streamExact(&body.writer, payload.len);
    } else {
        try body.writer.writeAll(payload);
    }
    try body.end();
    try request.connection.?.flush();
    var response = try request.receiveHead(&.{});
    if (response.head.status != .accepted) {
        std.debug.print("TLS body mismatch: sent={d}, status={d}, streamed={}\n", .{
            payload.len, @intFromEnum(response.head.status), streamed,
        });
        return error.UpstreamBodyMismatch;
    }
    _ = try response.reader(&buffer).discardRemaining();
}
