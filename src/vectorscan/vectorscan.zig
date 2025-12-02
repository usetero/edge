const std = @import("std");

const c = @cImport({
    @cInclude("hs/hs.h");
});

pub const Error = error{
    CompileError,
    ScanError,
};

pub const Match = struct {
    id: u32,
    from: usize,
    to: usize,
};

/// Compile a single pattern for block scanning.
pub fn compile(
    pattern: []const u8,
    flags: c.hs_compile_flag,
) !*c.hs_database_t {
    var db: *c.hs_database_t = undefined;
    var comp_err: *c.hs_compile_error_t = undefined;

    const mode = c.HS_MODE_BLOCK;

    const rc = c.hs_compile(
        pattern.ptr,
        flags,
        mode,
        null,
        &db,
        &comp_err,
    );

    if (rc != c.HS_SUCCESS) {
        if (comp_err != null) {
            std.debug.print("VectorScan compile error: {s}\n", .{comp_err.*.message});
            c.hs_free_compile_error(comp_err);
        }
        return Error.CompileError;
    }

    return db;
}

/// Free a VectorScan database
pub fn freeDatabase(db: *c.hs_database_t) void {
    _ = c.hs_free_database(db);
}

/// Scratch allocator creation
pub fn allocScratch(db: *c.hs_database_t) !*c.hs_scratch_t {
    var scratch: *c.hs_scratch_t = undefined;
    if (c.hs_alloc_scratch(db, &scratch) != c.HS_SUCCESS) return Error.CompileError;
    return scratch;
}

/// Free scratch space
pub fn freeScratch(s: *c.hs_scratch_t) void {
    _ = c.hs_free_scratch(s);
}

/// Scan input and return all matches
pub fn scan(
    db: *c.hs_database_t,
    scratch: *c.hs_scratch_t,
    input: []const u8,
    matches: *std.ArrayList(Match),
) !void {
    const ctx = matches;

    const rc = c.hs_scan(
        db,
        input.ptr,
        input.len,
        0,
        scratch,
        matchHandler,
        @ptrCast(?*anyopaque, ctx),
    );

    if (rc != c.HS_SUCCESS) return Error.ScanError;
}

/// C callback → Zig
export fn matchHandler(
    id: c.uint,
    from: c.uint64_t,
    to: c.uint64_t,
    flags: c.uint,
    ctx: ?*anyopaque,
) callconv(.C) c.int {
    _ = flags;

    const matches = @ptrCast(*std.ArrayList(Match), ctx.?);
    matches.append(.{
        .id = id,
        .from = @intCast(usize, from),
        .to = @intCast(usize, to),
    }) catch return 1;

    return 0;
}

test "VectorScan compiles and matches patterns" {
    var gpa = std.testing.allocator;

    const db = try vs.compile("hello");
    defer vs.freeDatabase(db);

    const scratch = try vs.allocScratch(db);
    defer vs.freeScratch(scratch);

    var matches = std.ArrayList(vs.Match).init(gpa);
    defer matches.deinit();

    try vs.scan(db, scratch, "why hello there", &matches);

    try std.testing.expect(matches.items.len == 1);
    try std.testing.expect(matches.items[0].from == 4);
}

test "VectorScan sees no matches" {
    var gpa = std.testing.allocator;

    const db = try vs.compile("hello");
    defer vs.freeDatabase(db);

    const scratch = try vs.allocScratch(db);
    defer vs.freeScratch(scratch);

    var matches = std.ArrayList(vs.Match).init(gpa);
    defer matches.deinit();

    try vs.scan(db, scratch, "no greeting here", &matches);

    try std.testing.expect(matches.items.len == 0);
}
