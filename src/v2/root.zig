//! Edge v2 foundations, kept separate until the delivery gates permit cutover.

test {
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
