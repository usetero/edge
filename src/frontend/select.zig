//! Comptime frontend selection (PLAN-FRONTEND-SWAP.md §2). The build option
//! `-Dfrontend=httpz|stdio` resolves here during semantic analysis: the
//! unselected frontend is never analyzed or codegen'd, every call into the
//! selected one is direct (no vtable), and `Engine.server` is a concrete
//! type. Both frontends expose the same shape — init(ctx, lifecycle, addr,
//! port) / run / stopAccepting / deinit — checked by the compile of
//! runtime/app.zig against either selection (CI builds both).
const build_options = @import("build_options");
const stdio_server = @import("stdio/server.zig");
const httpz_server = @import("httpz/server.zig");

pub const Server = switch (build_options.frontend) {
    .stdio => stdio_server.HttpServer,
    .httpz => httpz_server.HttpServer,
};
