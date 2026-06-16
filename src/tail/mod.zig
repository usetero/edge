pub const types = @import("types.zig");
pub const io = @import("io.zig");
pub const framer = @import("framer.zig");
pub const eval_context = @import("eval_context.zig");
pub const eval_parse = @import("eval_parse.zig");
pub const eval_stream = @import("eval_stream.zig");
pub const watch = @import("watch.zig");
pub const read_scheduler = @import("read_scheduler.zig");
pub const checkpoint = @import("checkpoint/mod.zig");
pub const runtime = @import("runtime.zig");

// Without this block the whole tail subtree's tests are dark — root.zig's
// `_ = @import("tail/mod.zig")` only reaches tests that are re-referenced
// here (discovered during Phase 6; the checkpoint/lane tests had bit-rotted
// unnoticed).
test {
    _ = types;
    _ = io;
    _ = framer;
    _ = eval_context;
    _ = eval_parse;
    _ = eval_stream;
    _ = watch;
    _ = read_scheduler;
    _ = runtime;
    _ = @import("checkpoint/types.zig");
    _ = @import("checkpoint/queue.zig");
    _ = @import("checkpoint/store.zig");
    _ = @import("checkpoint/wal.zig");
    _ = @import("checkpoint/snapshot.zig");
    _ = @import("checkpoint/lane.zig");
    _ = @import("read_scheduler/common.zig");
    _ = @import("read_scheduler/poll.zig");
    _ = @import("watch_backend/poll.zig");
}
