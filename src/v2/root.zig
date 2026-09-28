//! Edge v2 foundations, kept separate until the delivery gates permit cutover.

test {
    _ = @import("Processing.zig");
    _ = @import("Routes.zig");
    _ = @import("Origin.zig");
    _ = @import("Relay.zig");
    _ = @import("os/connect.zig");
    _ = @import("httpz_contract.zig");
    _ = @import("HeadScanner.zig");
    _ = @import("RequestHead.zig");
    _ = @import("BodyFramer.zig");
    _ = @import("RequestIngress.zig");
    _ = @import("RequestWire.zig");
    _ = @import("ResponseHead.zig");
    _ = @import("ResponseIngress.zig");
    _ = @import("Response.zig");
    _ = @import("ResponseWire.zig");
    _ = @import("compatibility.zig");
    _ = @import("PolicyStore.zig");
    _ = @import("ProviderSet.zig");
    _ = @import("Budget.zig");
    _ = @import("UpstreamWatch.zig");
    _ = @import("StackProbe.zig");
    _ = @import("RequestTable.zig");
    _ = @import("WorkChannel.zig");
    _ = @import("Readiness.zig");
    _ = @import("Connections.zig");
    _ = @import("AcceptChannel.zig");
    _ = @import("Acceptor.zig");
}
