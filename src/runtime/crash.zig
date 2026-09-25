//! What the edge prints when it crashes on a signal.
//!
//! With `std_options.enable_segfault_handler` set, std installs a handler for
//! SIGSEGV, SIGBUS, SIGILL and SIGFPE, and calls `root.debug.handleSegfault`.
//! Every entry point exports `debug` from here. It names the build, then hands
//! over to std, which prints the fault address and a stack trace unwound from
//! the faulting instruction, then aborts.
const std = @import("std");
const build_options = @import("build_options");

var distribution: []const u8 = "unknown";

/// Names the running distribution in the crash report. Call it at startup.
pub fn setDistribution(name: []const u8) void {
    distribution = name;
}

pub const debug = struct {
    pub fn handleSegfault(addr: ?usize, name: []const u8, context: ?std.debug.CpuContextPtr) noreturn {
        std.debug.print("\nedge {s} crashed (distribution {s}, frontend {s}, commit {s})\n", .{
            build_options.version,
            distribution,
            @tagName(build_options.frontend),
            build_options.commit,
        });
        std.debug.defaultHandleSegfault(addr, name, context);
    }
};
