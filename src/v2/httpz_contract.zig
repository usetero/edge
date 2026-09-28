//! Characterize the pinned httpz transport hooks before committing to v2 framing.
//! These are dependency boundary probes, not a serving runtime or throughput test.

const std = @import("std");
const httpz = @import("httpz");
const Poller = @import("os/Poller.zig");

test "httpz lazy Content-Length dispatches before body and delegates size enforcement" {
    var fixture = httpz.testing.init(.{ .request = .{
        .lazy_read_size = 0,
        .max_body_size = 64,
        .buffer_size = 512,
    } });
    defer fixture.deinit();
    const state = &fixture.conn.req_state;
    state.reset();
    var source: std.Io.Reader = .fixed("POST / HTTP/1.1\r\nContent-Length: 1024\r\n\r\nabc");

    try std.testing.expect(try state.parse(fixture.conn, &source));
    try std.testing.expectEqual(1024, state.body_len);
    try std.testing.expectEqual(1021, state.unread_body);
    try std.testing.expectEqual(.static, state.body.?.type);
    try std.testing.expectEqualStrings("abc", state.body.?.data);
}

test "httpz lazy reads still buffer chunked bodies before dispatch" {
    var fixture = httpz.testing.init(.{ .request = .{
        .lazy_read_size = 0,
        .max_body_size = 64,
        .buffer_size = 512,
    } });
    defer fixture.deinit();
    const state = &fixture.conn.req_state;
    state.reset();
    var head: std.Io.Reader = .fixed("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n");

    // The desired head-only dispatch assertion failed against this pin. Preserve
    // that observed boundary; passing this probe does not satisfy v2 admission.
    try std.testing.expect(!try state.parse(fixture.conn, &head));
    try std.testing.expect(state.body != null);
    try std.testing.expectEqual(512, state.chunked.?.raw.len);
    var body: std.Io.Reader = .fixed("3\r\nabc\r\n0\r\n\r\n");
    try std.testing.expect(try state.parse(fixture.conn, &body));
    try std.testing.expectEqualStrings("abc", state.body.?.data[0..state.body_len]);
}

test "httpz coalesced Content-Length request and following head are rejected" {
    var fixture = httpz.testing.init(.{ .request = .{ .lazy_read_size = 0, .buffer_size = 512 } });
    defer fixture.deinit();
    fixture.conn.req_state.reset();
    var source: std.Io.Reader = .fixed("POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabcGET /next HTTP/1.1\r\n\r\n");
    try std.testing.expectError(error.InvalidContentLength, fixture.conn.req_state.parse(fixture.conn, &source));
}

test "httpz emits Continue before rejecting an oversized body" {
    var fixture = httpz.testing.init(.{ .request = .{ .max_body_size = 64, .buffer_size = 512 } });
    defer fixture.deinit();
    fixture.conn.req_state.reset();
    var source: std.Io.Reader = .fixed("POST / HTTP/1.1\r\nContent-Length: 1024\r\nExpect: 100-continue\r\n\r\n");
    try std.testing.expectError(error.BodyTooBig, fixture.conn.req_state.parse(fixture.conn, &source));

    // The public test helper supplies a socket-pair peer; no server loop runs here.
    var reader = fixture._ctx.client.reader(std.testing.io, &.{});
    var received: [25]u8 = undefined;
    try reader.interface.readSliceAll(&received);
    try std.testing.expectEqualStrings("HTTP/1.1 100 Continue\r\n\r\n", &received);
}

test "httpz disown keeps socket alive but requestDone still resets request storage" {
    var fixture = httpz.testing.init(.{});
    defer fixture.deinit();
    var poller = try Poller.init();
    defer poller.deinit();
    // Supply the real registration that disown removes. This does not simulate
    // httpz's worker scheduling: that call path is also audited in the report.
    fixture.conn.loop = poller.fd;
    try poller.addListener(fixture.conn.stream.socket.handle, 1);
    try fixture.res.disown();
    try std.testing.expectEqual(.disown, fixture.conn.handover);
    try std.testing.expect(fixture.conn.req_state.url != null);
    try std.testing.expect(fixture.conn.req_arena.queryCapacity() > 0);
    try fixture.conn.requestDone(0, false);
    // req/res themselves lived in that arena. Never dereference them after this.
    try std.testing.expectEqual(null, fixture.conn.req_state.url);
    try std.testing.expectEqual(0, fixture.conn.req_arena.queryCapacity());
    try fixture.conn.writeAll("ok");
    var reader = fixture._ctx.client.reader(std.testing.io, &.{});
    var received: [2]u8 = undefined;
    try reader.interface.readSliceAll(&received);
    try std.testing.expectEqualStrings("ok", &received);
}
