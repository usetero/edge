const std = @import("std");
const types = @import("types.zig");

/// Execute log filter on request body
/// Config data is long-lived (loaded at startup)
/// Reads body and checks for filter patterns
pub fn execute(config: types.LogFilterConfig, ctx: types.RequestContext) !types.HandlerResult {
    const body = ctx.body orelse return .{
        .action = .continue_pipeline,
        .context = ctx,
    };

    // Check if route matches
    if (!config.route.matches(ctx.path, ctx.content_type)) {
        return .{
            .action = .continue_pipeline,
            .context = ctx,
        };
    }

    // Scan body for filter patterns
    // This is hot path - optimize for sequential memory access
    for (config.filter_patterns) |pattern| {
        if (std.mem.indexOf(u8, body, pattern)) |_| {
            std.log.info("log_filter: found pattern '{s}' in request body, action={s}", .{
                pattern,
                @tagName(config.action),
            });

            var result_ctx = ctx;

            switch (config.action) {
                .reject => {
                    result_ctx.should_forward = false;
                    return .{
                        .action = .reject,
                        .context = result_ctx,
                    };
                },
                .continue_pipeline => {
                    // Mark as detected but continue
                    return .{
                        .action = .continue_pipeline,
                        .context = result_ctx,
                    };
                },
            }
        }
    }

    // No patterns matched, continue
    return .{
        .action = .continue_pipeline,
        .context = ctx,
    };
}
