//! Zig bindings for Vectorscan/Hyperscan - High-performance regex matching library
//!
//! This module provides idiomatic Zig wrappers around the Vectorscan C API,
//! offering RAII-style resource management and type-safe interfaces.
//!
//! ## Quick Start
//! ```zig
//! const hs = @import("hyperscan");
//!
//! // Single pattern matching
//! var db = try hs.Database.compile("hello\\s+world", .{});
//! defer db.deinit();
//!
//! var scratch = try hs.Scratch.init(&db);
//! defer scratch.deinit();
//!
//! var scanner = db.scanner(&scratch);
//! for (scanner.scan("say hello world!")) |match| {
//!     std.debug.print("Match at {}-{}\n", .{match.start, match.end});
//! }
//! ```
//!
//! ## Multi-pattern matching
//! ```zig
//! var db = try hs.Database.compileMulti(allocator, &.{
//!     .{ .expression = "error", .id = 1 },
//!     .{ .expression = "warn", .id = 2 },
//!     .{ .expression = "info", .id = 3 },
//! }, .{});
//! ```

const std = @import("std");

// =============================================================================
// C Bindings
// =============================================================================

const c = struct {
    // Opaque types
    const hs_database_t = opaque {};
    const hs_scratch_t = opaque {};
    const hs_stream_t = opaque {};

    const hs_compile_error_t = extern struct {
        message: [*:0]const u8,
        expression: c_int,
    };

    // Error codes
    const HS_SUCCESS: c_int = 0;
    const HS_INVALID: c_int = -1;
    const HS_NOMEM: c_int = -2;
    const HS_SCAN_TERMINATED: c_int = -3;
    const HS_COMPILER_ERROR: c_int = -4;
    const HS_DB_VERSION_ERROR: c_int = -5;
    const HS_DB_PLATFORM_ERROR: c_int = -6;
    const HS_DB_MODE_ERROR: c_int = -7;
    const HS_BAD_ALIGN: c_int = -8;
    const HS_BAD_ALLOC: c_int = -9;
    const HS_SCRATCH_IN_USE: c_int = -10;
    const HS_ARCH_ERROR: c_int = -11;
    const HS_INSUFFICIENT_SPACE: c_int = -12;
    const HS_UNKNOWN_ERROR: c_int = -13;

    // Compile flags
    const HS_FLAG_CASELESS: c_uint = 1;
    const HS_FLAG_DOTALL: c_uint = 2;
    const HS_FLAG_MULTILINE: c_uint = 4;
    const HS_FLAG_SINGLEMATCH: c_uint = 8;
    const HS_FLAG_ALLOWEMPTY: c_uint = 16;
    const HS_FLAG_UTF8: c_uint = 32;
    const HS_FLAG_UCP: c_uint = 64;
    const HS_FLAG_PREFILTER: c_uint = 128;
    const HS_FLAG_SOM_LEFTMOST: c_uint = 256;

    // Mode flags
    const HS_MODE_BLOCK: c_uint = 1;
    const HS_MODE_STREAM: c_uint = 2;
    const HS_MODE_VECTORED: c_uint = 4;
    const HS_MODE_SOM_HORIZON_LARGE: c_uint = 1 << 24;
    const HS_MODE_SOM_HORIZON_MEDIUM: c_uint = 1 << 25;
    const HS_MODE_SOM_HORIZON_SMALL: c_uint = 1 << 26;

    // Callback type
    const match_event_handler = *const fn (
        id: c_uint,
        from: c_ulonglong,
        to: c_ulonglong,
        flags: c_uint,
        context: ?*anyopaque,
    ) callconv(.c) c_int;

    // Compilation functions
    extern fn hs_compile(
        expression: [*:0]const u8,
        flags: c_uint,
        mode: c_uint,
        platform: ?*anyopaque,
        db: *?*hs_database_t,
        compile_error: *?*hs_compile_error_t,
    ) c_int;

    extern fn hs_compile_multi(
        expressions: [*]const [*:0]const u8,
        flags: ?[*]const c_uint,
        ids: ?[*]const c_uint,
        elements: c_uint,
        mode: c_uint,
        platform: ?*anyopaque,
        db: *?*hs_database_t,
        compile_error: *?*hs_compile_error_t,
    ) c_int;

    extern fn hs_compile_lit(
        expression: [*]const u8,
        flags: c_uint,
        len: usize,
        mode: c_uint,
        platform: ?*anyopaque,
        db: *?*hs_database_t,
        compile_error: *?*hs_compile_error_t,
    ) c_int;

    extern fn hs_compile_lit_multi(
        expressions: [*]const [*]const u8,
        flags: ?[*]const c_uint,
        ids: ?[*]const c_uint,
        lens: [*]const usize,
        elements: c_uint,
        mode: c_uint,
        platform: ?*anyopaque,
        db: *?*hs_database_t,
        compile_error: *?*hs_compile_error_t,
    ) c_int;

    extern fn hs_free_compile_error(compile_error: ?*hs_compile_error_t) c_int;

    // Database functions
    extern fn hs_free_database(db: ?*hs_database_t) c_int;
    extern fn hs_database_size(db: ?*const hs_database_t, size: *usize) c_int;
    extern fn hs_database_info(db: ?*const hs_database_t, info: *?[*:0]u8) c_int;
    extern fn hs_serialize_database(db: ?*const hs_database_t, bytes: *?[*]u8, length: *usize) c_int;
    extern fn hs_deserialize_database(bytes: [*]const u8, length: usize, db: *?*hs_database_t) c_int;

    // Scratch functions
    extern fn hs_alloc_scratch(db: ?*const hs_database_t, scratch: *?*hs_scratch_t) c_int;
    extern fn hs_free_scratch(scratch: ?*hs_scratch_t) c_int;
    extern fn hs_clone_scratch(src: ?*const hs_scratch_t, dest: *?*hs_scratch_t) c_int;
    extern fn hs_scratch_size(scratch: ?*const hs_scratch_t, size: *usize) c_int;

    // Block scanning
    extern fn hs_scan(
        db: ?*const hs_database_t,
        data: [*]const u8,
        length: c_uint,
        flags: c_uint,
        scratch: ?*hs_scratch_t,
        onEvent: ?match_event_handler,
        context: ?*anyopaque,
    ) c_int;

    // Vectored scanning
    extern fn hs_scan_vector(
        db: ?*const hs_database_t,
        data: [*]const [*]const u8,
        length: [*]const c_uint,
        count: c_uint,
        flags: c_uint,
        scratch: ?*hs_scratch_t,
        onEvent: ?match_event_handler,
        context: ?*anyopaque,
    ) c_int;

    // Stream functions
    extern fn hs_open_stream(db: ?*const hs_database_t, flags: c_uint, stream: *?*hs_stream_t) c_int;
    extern fn hs_scan_stream(
        stream: ?*hs_stream_t,
        data: [*]const u8,
        length: c_uint,
        flags: c_uint,
        scratch: ?*hs_scratch_t,
        onEvent: ?match_event_handler,
        context: ?*anyopaque,
    ) c_int;
    extern fn hs_close_stream(
        stream: ?*hs_stream_t,
        scratch: ?*hs_scratch_t,
        onEvent: ?match_event_handler,
        context: ?*anyopaque,
    ) c_int;
    extern fn hs_reset_stream(
        stream: ?*hs_stream_t,
        flags: c_uint,
        scratch: ?*hs_scratch_t,
        onEvent: ?match_event_handler,
        context: ?*anyopaque,
    ) c_int;

    // Utility
    extern fn hs_version() [*:0]const u8;
    extern fn hs_valid_platform() c_int;
};

// =============================================================================
// Error Handling
// =============================================================================

/// Errors that can occur during Hyperscan operations
pub const Error = error{
    /// Invalid parameter passed to function
    Invalid,
    /// Memory allocation failed
    OutOfMemory,
    /// Pattern compilation failed
    CompileError,
    /// Database version mismatch
    DatabaseVersionError,
    /// Database platform mismatch
    DatabasePlatformError,
    /// Database mode mismatch (e.g., using streaming API with block database)
    DatabaseModeError,
    /// Memory alignment error
    BadAlignment,
    /// Allocator returned misaligned memory
    BadAlloc,
    /// Scratch space already in use
    ScratchInUse,
    /// Unsupported CPU architecture
    ArchitectureError,
    /// Buffer too small
    InsufficientSpace,
    /// Unknown internal error
    UnknownError,
};

/// Compile-specific error with detailed message
pub const CompileErrorDetails = struct {
    message: []const u8,
    /// Expression index that caused the error (-1 if not expression-specific)
    expression_index: i32,
};

fn mapError(code: c_int) Error {
    return switch (code) {
        c.HS_INVALID => error.Invalid,
        c.HS_NOMEM => error.OutOfMemory,
        c.HS_COMPILER_ERROR => error.CompileError,
        c.HS_DB_VERSION_ERROR => error.DatabaseVersionError,
        c.HS_DB_PLATFORM_ERROR => error.DatabasePlatformError,
        c.HS_DB_MODE_ERROR => error.DatabaseModeError,
        c.HS_BAD_ALIGN => error.BadAlignment,
        c.HS_BAD_ALLOC => error.BadAlloc,
        c.HS_SCRATCH_IN_USE => error.ScratchInUse,
        c.HS_ARCH_ERROR => error.ArchitectureError,
        c.HS_INSUFFICIENT_SPACE => error.InsufficientSpace,
        else => error.UnknownError,
    };
}

// =============================================================================
// Compile Flags
// =============================================================================

/// Flags that modify pattern matching behavior
pub const Flags = packed struct(c_uint) {
    /// Case-insensitive matching
    caseless: bool = false,
    /// Dot (.) matches newlines
    dotall: bool = false,
    /// ^ and $ match at newlines
    multiline: bool = false,
    /// Only report first match per pattern
    single_match: bool = false,
    /// Allow patterns that match empty strings
    allow_empty: bool = false,
    /// Treat pattern as UTF-8
    utf8: bool = false,
    /// Use Unicode character properties
    ucp: bool = false,
    /// Compile in prefilter mode
    prefilter: bool = false,
    /// Report start of match (leftmost)
    som_leftmost: bool = false,

    _padding: u23 = 0,

    /// Combine multiple flags
    pub fn with(self: Flags, other: Flags) Flags {
        return @bitCast(@as(c_uint, @bitCast(self)) | @as(c_uint, @bitCast(other)));
    }
};

// =============================================================================
// Database Mode
// =============================================================================

/// Database compilation mode
pub const Mode = enum(c_uint) {
    /// Block mode - scan complete data in single call
    block = c.HS_MODE_BLOCK,
    /// Stream mode - scan data incrementally
    stream = c.HS_MODE_STREAM,
    /// Vectored mode - scan non-contiguous data blocks
    vectored = c.HS_MODE_VECTORED,

    /// Add start-of-match tracking with large horizon
    pub fn withSomLarge(self: Mode) c_uint {
        return @intFromEnum(self) | c.HS_MODE_SOM_HORIZON_LARGE;
    }

    /// Add start-of-match tracking with medium horizon
    pub fn withSomMedium(self: Mode) c_uint {
        return @intFromEnum(self) | c.HS_MODE_SOM_HORIZON_MEDIUM;
    }

    /// Add start-of-match tracking with small horizon
    pub fn withSomSmall(self: Mode) c_uint {
        return @intFromEnum(self) | c.HS_MODE_SOM_HORIZON_SMALL;
    }
};

// =============================================================================
// Match Result
// =============================================================================

/// A single match result from scanning
pub const Match = struct {
    /// Pattern ID (0 for single-pattern databases)
    id: u32,
    /// Start offset of match (only valid if SOM flag was used)
    start: u64,
    /// End offset of match (exclusive)
    end: u64,
};

// =============================================================================
// Pattern Definition
// =============================================================================

/// A pattern with optional ID and flags for multi-pattern compilation
pub const Pattern = struct {
    /// The regex pattern string
    expression: []const u8,
    /// Unique identifier for this pattern (returned in match callbacks)
    id: u32 = 0,
    /// Pattern-specific flags
    flags: Flags = .{},
};

// =============================================================================
// Database
// =============================================================================

/// A compiled pattern database
///
/// Databases are immutable after compilation and can be shared across threads.
/// Each thread needs its own Scratch space for scanning.
pub const Database = struct {
    handle: *c.hs_database_t,

    const Self = @This();

    /// Compile options
    pub const CompileOptions = struct {
        flags: Flags = .{},
        mode: Mode = .block,
    };

    /// Compile a single regex pattern
    pub fn compile(pattern: []const u8, options: CompileOptions) Error!Self {
        return compileWithDetails(pattern, options) catch |err| switch (err) {
            error.CompileErrorWithDetails => error.CompileError,
            else => |e| e,
        };
    }

    /// Error type that includes compile details
    pub const CompileWithDetailsError = Error || error{CompileErrorWithDetails};

    /// Compile a single regex pattern, storing error details on failure
    pub fn compileWithDetails(
        pattern: []const u8,
        options: CompileOptions,
    ) CompileWithDetailsError!Self {
        // Pattern must be null-terminated for C API
        var pattern_buf: [4096]u8 = undefined;
        if (pattern.len >= pattern_buf.len) return error.Invalid;

        @memcpy(pattern_buf[0..pattern.len], pattern);
        pattern_buf[pattern.len] = 0;

        var db: ?*c.hs_database_t = null;
        var comp_err: ?*c.hs_compile_error_t = null;

        const rc = c.hs_compile(
            @ptrCast(&pattern_buf),
            @bitCast(options.flags),
            @intFromEnum(options.mode),
            null,
            &db,
            &comp_err,
        );

        if (rc != c.HS_SUCCESS) {
            if (comp_err) |err| {
                _ = c.hs_free_compile_error(err);
            }
            if (rc == c.HS_COMPILER_ERROR) {
                return error.CompileErrorWithDetails;
            }
            return mapError(rc);
        }

        return .{ .handle = db.? };
    }

    /// Compile multiple patterns into a single database
    ///
    /// The allocator is used for temporary storage during compilation and
    /// is not retained after this function returns.
    pub fn compileMulti(
        allocator: std.mem.Allocator,
        patterns: []const Pattern,
        options: CompileOptions,
    ) (Error || std.mem.Allocator.Error)!Self {
        if (patterns.len == 0) return error.Invalid;
        if (patterns.len > std.math.maxInt(c_uint)) return error.Invalid;

        // Allocate temporary arrays for C API
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const alloc = arena.allocator();

        const expressions = try alloc.alloc([*:0]const u8, patterns.len);
        const flags = try alloc.alloc(c_uint, patterns.len);
        const ids = try alloc.alloc(c_uint, patterns.len);
        const pattern_bufs = try alloc.alloc([4096]u8, patterns.len);

        for (patterns, 0..) |pat, i| {
            if (pat.expression.len >= 4096) return error.Invalid;
            @memcpy(pattern_bufs[i][0..pat.expression.len], pat.expression);
            pattern_bufs[i][pat.expression.len] = 0;
            expressions[i] = @ptrCast(&pattern_bufs[i]);
            flags[i] = @bitCast(options.flags.with(pat.flags));
            ids[i] = pat.id;
        }

        var db: ?*c.hs_database_t = null;
        var comp_err: ?*c.hs_compile_error_t = null;

        const rc = c.hs_compile_multi(
            expressions.ptr,
            flags.ptr,
            ids.ptr,
            @intCast(patterns.len),
            @intFromEnum(options.mode),
            null,
            &db,
            &comp_err,
        );

        if (rc != c.HS_SUCCESS) {
            if (comp_err) |err| {
                _ = c.hs_free_compile_error(err);
            }
            return mapError(rc);
        }

        return .{ .handle = db.? };
    }

    /// Compile a literal (non-regex) pattern for exact matching
    pub fn compileLiteral(pattern: []const u8, options: CompileOptions) Error!Self {
        var db: ?*c.hs_database_t = null;
        var comp_err: ?*c.hs_compile_error_t = null;

        const rc = c.hs_compile_lit(
            pattern.ptr,
            @bitCast(options.flags),
            pattern.len,
            @intFromEnum(options.mode),
            null,
            &db,
            &comp_err,
        );

        if (rc != c.HS_SUCCESS) {
            if (comp_err) |err| {
                _ = c.hs_free_compile_error(err);
            }
            return mapError(rc);
        }

        return .{ .handle = db.? };
    }

    /// Compile multiple literal patterns
    ///
    /// The allocator is used for temporary storage during compilation and
    /// is not retained after this function returns.
    pub fn compileLiteralMulti(
        allocator: std.mem.Allocator,
        patterns: []const Pattern,
        options: CompileOptions,
    ) (Error || std.mem.Allocator.Error)!Self {
        if (patterns.len == 0) return error.Invalid;
        if (patterns.len > std.math.maxInt(c_uint)) return error.Invalid;

        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const alloc = arena.allocator();

        const expressions = try alloc.alloc([*]const u8, patterns.len);
        const flags = try alloc.alloc(c_uint, patterns.len);
        const ids = try alloc.alloc(c_uint, patterns.len);
        const lens = try alloc.alloc(usize, patterns.len);

        for (patterns, 0..) |pat, i| {
            expressions[i] = pat.expression.ptr;
            flags[i] = @bitCast(options.flags.with(pat.flags));
            ids[i] = pat.id;
            lens[i] = pat.expression.len;
        }

        var db: ?*c.hs_database_t = null;
        var comp_err: ?*c.hs_compile_error_t = null;

        const rc = c.hs_compile_lit_multi(
            expressions.ptr,
            flags.ptr,
            ids.ptr,
            lens.ptr,
            @intCast(patterns.len),
            @intFromEnum(options.mode),
            null,
            &db,
            &comp_err,
        );

        if (rc != c.HS_SUCCESS) {
            if (comp_err) |err| {
                _ = c.hs_free_compile_error(err);
            }
            return mapError(rc);
        }

        return .{ .handle = db.? };
    }

    /// Deserialize a database from bytes
    pub fn deserialize(bytes: []const u8) Error!Self {
        var db: ?*c.hs_database_t = null;
        const rc = c.hs_deserialize_database(bytes.ptr, bytes.len, &db);
        if (rc != c.HS_SUCCESS) return mapError(rc);
        return .{ .handle = db.? };
    }

    /// Free the database
    pub fn deinit(self: *Self) void {
        _ = c.hs_free_database(self.handle);
        self.handle = undefined;
    }

    /// Get the size of the database in bytes
    pub fn size(self: *const Self) Error!usize {
        var sz: usize = 0;
        const rc = c.hs_database_size(self.handle, &sz);
        if (rc != c.HS_SUCCESS) return mapError(rc);
        return sz;
    }

    /// Serialize the database to bytes
    pub fn serialize(self: *const Self, allocator: std.mem.Allocator) (Error || std.mem.Allocator.Error)![]u8 {
        var bytes: ?[*]u8 = null;
        var length: usize = 0;

        const rc = c.hs_serialize_database(self.handle, &bytes, &length);
        if (rc != c.HS_SUCCESS) return mapError(rc);

        // Copy to Zig-managed memory
        const result = try allocator.alloc(u8, length);
        @memcpy(result, bytes.?[0..length]);

        // Free C-allocated memory (uses libc free)
        std.c.free(bytes.?);

        return result;
    }

    /// Scan data for matches using block mode
    ///
    /// Returns an iterator over matches. The scratch space must remain valid
    /// for the duration of iteration.
    pub fn scan(self: *const Self, scratch: *Scratch, data: []const u8) BlockScanner {
        return BlockScanner.init(self, scratch, data);
    }

    /// Scan and call a callback for each match
    ///
    /// This is more efficient than the iterator when you don't need to
    /// collect matches or when early termination is desired.
    pub fn scanWithCallback(
        self: *const Self,
        scratch: *Scratch,
        data: []const u8,
        context: anytype,
        comptime callback: fn (@TypeOf(context), Match) bool,
    ) Error!bool {
        const Context = @TypeOf(context);
        const Wrapper = struct {
            fn handler(
                id: c_uint,
                from: c_ulonglong,
                to: c_ulonglong,
                _: c_uint,
                ctx: ?*anyopaque,
            ) callconv(.c) c_int {
                const match = Match{
                    .id = id,
                    .start = from,
                    .end = to,
                };
                const user_ctx: Context = @ptrCast(@alignCast(ctx));
                // Return 1 to stop scanning, 0 to continue
                return if (callback(user_ctx, match)) 0 else 1;
            }
        };

        const rc = c.hs_scan(
            self.handle,
            data.ptr,
            @intCast(data.len),
            0,
            scratch.handle,
            Wrapper.handler,
            @ptrCast(@alignCast(context)),
        );

        if (rc == c.HS_SCAN_TERMINATED) return false;
        if (rc != c.HS_SUCCESS) return mapError(rc);
        return true;
    }

    /// Check if any pattern matches (short-circuit on first match)
    pub fn matches(self: *const Self, scratch: *Scratch, data: []const u8) Error!bool {
        var found = false;

        const rc = c.hs_scan(
            self.handle,
            data.ptr,
            @intCast(data.len),
            0,
            scratch.handle,
            struct {
                fn handler(_: c_uint, _: c_ulonglong, _: c_ulonglong, _: c_uint, ctx: ?*anyopaque) callconv(.c) c_int {
                    const ptr: *bool = @ptrCast(@alignCast(ctx));
                    ptr.* = true;
                    return 1; // Stop scanning
                }
            }.handler,
            &found,
        );

        if (rc == c.HS_SCAN_TERMINATED) return true;
        if (rc != c.HS_SUCCESS) return mapError(rc);
        return found;
    }

    /// Find the first matching pattern and return its ID
    /// Returns null if no pattern matches
    pub fn findFirstMatch(self: *const Self, scratch: *Scratch, data: []const u8) Error!?u32 {
        const Context = struct {
            found: bool = false,
            pattern_id: u32 = 0,
        };
        var ctx = Context{};

        const rc = c.hs_scan(
            self.handle,
            data.ptr,
            @intCast(data.len),
            0,
            scratch.handle,
            struct {
                fn handler(id: c_uint, _: c_ulonglong, _: c_ulonglong, _: c_uint, context: ?*anyopaque) callconv(.c) c_int {
                    const ptr: *Context = @ptrCast(@alignCast(context));
                    ptr.found = true;
                    ptr.pattern_id = id;
                    return 1; // Stop scanning after first match
                }
            }.handler,
            &ctx,
        );

        if (rc == c.HS_SCAN_TERMINATED) return ctx.pattern_id;
        if (rc != c.HS_SUCCESS) return mapError(rc);
        if (ctx.found) return ctx.pattern_id;
        return null;
    }

    /// Open a stream for incremental scanning (streaming mode only)
    pub fn openStream(self: *const Self) Error!Stream {
        var stream: ?*c.hs_stream_t = null;
        const rc = c.hs_open_stream(self.handle, 0, &stream);
        if (rc != c.HS_SUCCESS) return mapError(rc);
        return .{ .handle = stream.?, .database = self };
    }
};

// =============================================================================
// Scratch Space
// =============================================================================

/// Per-thread scratch space for scanning operations
///
/// Each thread performing scans needs its own scratch space. Scratch spaces
/// can be reused across multiple scan calls but not concurrently.
pub const Scratch = struct {
    handle: *c.hs_scratch_t,

    const Self = @This();

    /// Allocate scratch space for the given database
    pub fn init(db: *const Database) Error!Self {
        var scratch: ?*c.hs_scratch_t = null;
        const rc = c.hs_alloc_scratch(db.handle, &scratch);
        if (rc != c.HS_SUCCESS) return mapError(rc);
        return .{ .handle = scratch.? };
    }

    /// Allocate scratch space for multiple databases
    ///
    /// The resulting scratch can be used with any of the provided databases.
    pub fn initMulti(databases: []const *const Database) Error!Self {
        var scratch: ?*c.hs_scratch_t = null;
        for (databases) |db| {
            const rc = c.hs_alloc_scratch(db.handle, &scratch);
            if (rc != c.HS_SUCCESS) {
                if (scratch) |s| _ = c.hs_free_scratch(s);
                return mapError(rc);
            }
        }
        return .{ .handle = scratch.? };
    }

    /// Free the scratch space
    pub fn deinit(self: *Self) void {
        _ = c.hs_free_scratch(self.handle);
        self.handle = undefined;
    }

    /// Clone this scratch space
    pub fn clone(self: *const Self) Error!Self {
        var new_scratch: ?*c.hs_scratch_t = null;
        const rc = c.hs_clone_scratch(self.handle, &new_scratch);
        if (rc != c.HS_SUCCESS) return mapError(rc);
        return .{ .handle = new_scratch.? };
    }

    /// Get the size of the scratch space in bytes
    pub fn size(self: *const Self) Error!usize {
        var sz: usize = 0;
        const rc = c.hs_scratch_size(self.handle, &sz);
        if (rc != c.HS_SUCCESS) return mapError(rc);
        return sz;
    }
};

// =============================================================================
// Block Scanner (Iterator)
// =============================================================================

/// Iterator for block-mode scanning
pub const BlockScanner = struct {
    database: *const Database,
    scratch: *Scratch,
    data: []const u8,
    matches_buf: [64]Match = undefined,
    matches_len: usize = 0,
    match_index: usize = 0,
    scan_complete: bool = false,
    scan_error: ?Error = null,

    const Self = @This();

    fn init(database: *const Database, scratch: *Scratch, data: []const u8) Self {
        return .{
            .database = database,
            .scratch = scratch,
            .data = data,
        };
    }

    /// Get the next match, or null if no more matches
    pub fn next(self: *Self) ?Match {
        // Return buffered matches first
        if (self.match_index < self.matches_len) {
            const match = self.matches_buf[self.match_index];
            self.match_index += 1;
            return match;
        }

        // If scan is complete, no more matches
        if (self.scan_complete) return null;

        // Perform the scan
        self.matches_len = 0;
        self.match_index = 0;

        const rc = c.hs_scan(
            self.database.handle,
            self.data.ptr,
            @intCast(self.data.len),
            0,
            self.scratch.handle,
            matchCallback,
            self,
        );

        self.scan_complete = true;

        if (rc != c.HS_SUCCESS and rc != c.HS_SCAN_TERMINATED) {
            self.scan_error = mapError(rc);
            return null;
        }

        if (self.matches_len > 0) {
            const match = self.matches_buf[0];
            self.match_index = 1;
            return match;
        }

        return null;
    }

    fn matchCallback(
        id: c_uint,
        from: c_ulonglong,
        to: c_ulonglong,
        _: c_uint,
        ctx: ?*anyopaque,
    ) callconv(.c) c_int {
        const self: *Self = @ptrCast(@alignCast(ctx));
        if (self.matches_len >= self.matches_buf.len) {
            // Buffer full, stop scanning
            return 1;
        }
        self.matches_buf[self.matches_len] = .{
            .id = id,
            .start = from,
            .end = to,
        };
        self.matches_len += 1;
        return 0;
    }

    /// Check if an error occurred during scanning
    pub fn err(self: *const Self) ?Error {
        return self.scan_error;
    }
};

// =============================================================================
// Stream (Streaming Mode)
// =============================================================================

/// A stream for incremental pattern matching
///
/// Streams allow scanning data that arrives in chunks while maintaining
/// state between chunks. Matches that span chunks are correctly detected.
pub const Stream = struct {
    handle: *c.hs_stream_t,
    database: *const Database,

    const Self = @This();

    /// Write data to the stream and scan for matches
    pub fn scan(
        self: *Self,
        scratch: *Scratch,
        data: []const u8,
        context: anytype,
        comptime callback: fn (@TypeOf(context), Match) bool,
    ) Error!bool {
        const Context = @TypeOf(context);
        const Wrapper = struct {
            fn handler(
                id: c_uint,
                from: c_ulonglong,
                to: c_ulonglong,
                _: c_uint,
                ctx: ?*anyopaque,
            ) callconv(.c) c_int {
                const match = Match{
                    .id = id,
                    .start = from,
                    .end = to,
                };
                const user_ctx: Context = @ptrCast(@alignCast(ctx));
                return if (callback(user_ctx, match)) 0 else 1;
            }
        };

        const rc = c.hs_scan_stream(
            self.handle,
            data.ptr,
            @intCast(data.len),
            0,
            scratch.handle,
            Wrapper.handler,
            @ptrCast(@alignCast(@constCast(context))),
        );

        if (rc == c.HS_SCAN_TERMINATED) return false;
        if (rc != c.HS_SUCCESS) return mapError(rc);
        return true;
    }

    /// Write data without callbacks (useful for building up context)
    pub fn write(self: *Self, scratch: *Scratch, data: []const u8) Error!void {
        const rc = c.hs_scan_stream(
            self.handle,
            data.ptr,
            @intCast(data.len),
            0,
            scratch.handle,
            null,
            null,
        );
        if (rc != c.HS_SUCCESS) return mapError(rc);
    }

    /// Reset stream to initial state
    pub fn reset(self: *Self, scratch: *Scratch) Error!void {
        const rc = c.hs_reset_stream(self.handle, 0, scratch.handle, null, null);
        if (rc != c.HS_SUCCESS) return mapError(rc);
    }

    /// Close the stream and free resources
    ///
    /// This may trigger end-of-data matches (e.g., $ anchors).
    pub fn close(
        self: *Self,
        scratch: *Scratch,
        context: anytype,
        comptime callback: ?fn (@TypeOf(context), Match) bool,
    ) Error!void {
        if (callback) |cb| {
            const Context = @TypeOf(context);
            const Wrapper = struct {
                fn handler(
                    id: c_uint,
                    from: c_ulonglong,
                    to: c_ulonglong,
                    _: c_uint,
                    ctx: ?*anyopaque,
                ) callconv(.c) c_int {
                    const match = Match{
                        .id = id,
                        .start = from,
                        .end = to,
                    };
                    const user_ctx: Context = @ptrCast(@alignCast(ctx));
                    return if (cb(user_ctx, match)) 0 else 1;
                }
            };

            const rc = c.hs_close_stream(
                self.handle,
                scratch.handle,
                Wrapper.handler,
                @ptrCast(@alignCast(context)),
            );
            if (rc != c.HS_SUCCESS) return mapError(rc);
        } else {
            const rc = c.hs_close_stream(self.handle, scratch.handle, null, null);
            if (rc != c.HS_SUCCESS) return mapError(rc);
        }
        self.handle = undefined;
    }

    /// Close the stream without checking for EOD matches
    pub fn deinit(self: *Self) void {
        _ = c.hs_close_stream(self.handle, null, null, null);
        self.handle = undefined;
    }
};

// =============================================================================
// Utility Functions
// =============================================================================

/// Get Hyperscan library version string
pub fn version() []const u8 {
    const ver = c.hs_version();
    return std.mem.sliceTo(ver, 0);
}

/// Check if the current platform supports Hyperscan
pub fn isPlatformValid() bool {
    return c.hs_valid_platform() == c.HS_SUCCESS;
}

// =============================================================================
// Tests
// =============================================================================

test "compile single pattern" {
    var db = try Database.compile("hello", .{});
    defer db.deinit();

    const db_size = try db.size();
    try std.testing.expect(db_size > 0);
}

test "compile with flags" {
    var db = try Database.compile("hello", .{
        .flags = (Flags{ .caseless = true }).with(.{ .utf8 = true }),
    });
    defer db.deinit();
}

test "compile multi-pattern" {
    var db = try Database.compileMulti(std.testing.allocator, &.{
        .{ .expression = "error", .id = 1 },
        .{ .expression = "warn", .id = 2 },
        .{ .expression = "info", .id = 3 },
    }, .{});
    defer db.deinit();
}

test "scratch allocation" {
    var db = try Database.compile("test", .{});
    defer db.deinit();

    var scratch = try Scratch.init(&db);
    defer scratch.deinit();

    const scratch_size = try scratch.size();
    try std.testing.expect(scratch_size > 0);
}

test "scratch clone" {
    var db = try Database.compile("test", .{});
    defer db.deinit();

    var scratch1 = try Scratch.init(&db);
    defer scratch1.deinit();

    var scratch2 = try scratch1.clone();
    defer scratch2.deinit();
}

test "block scan - matches found" {
    var db = try Database.compile("hello", .{});
    defer db.deinit();

    var scratch = try Scratch.init(&db);
    defer scratch.deinit();

    var scanner = db.scan(&scratch, "say hello world");
    var count: usize = 0;
    while (scanner.next()) |match| {
        try std.testing.expectEqual(@as(u32, 0), match.id);
        try std.testing.expectEqual(@as(u64, 9), match.end);
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expect(scanner.err() == null);
}

test "block scan - no matches" {
    var db = try Database.compile("hello", .{});
    defer db.deinit();

    var scratch = try Scratch.init(&db);
    defer scratch.deinit();

    var scanner = db.scan(&scratch, "goodbye world");
    try std.testing.expect(scanner.next() == null);
    try std.testing.expect(scanner.err() == null);
}

test "matches helper" {
    var db = try Database.compile("hello", .{});
    defer db.deinit();

    var scratch = try Scratch.init(&db);
    defer scratch.deinit();

    try std.testing.expect(try db.matches(&scratch, "hello world"));
    try std.testing.expect(!try db.matches(&scratch, "goodbye world"));
}

test "multi-pattern scan" {
    var db = try Database.compileMulti(std.testing.allocator, &.{
        .{ .expression = "error", .id = 1 },
        .{ .expression = "warn", .id = 2 },
        .{ .expression = "info", .id = 3 },
    }, .{});
    defer db.deinit();

    var scratch = try Scratch.init(&db);
    defer scratch.deinit();

    var scanner = db.scan(&scratch, "error: something bad, warn: be careful");
    var found_error = false;
    var found_warn = false;

    while (scanner.next()) |match| {
        if (match.id == 1) found_error = true;
        if (match.id == 2) found_warn = true;
    }

    try std.testing.expect(found_error);
    try std.testing.expect(found_warn);
}

test "literal pattern" {
    // Literal patterns treat special chars as-is
    var db = try Database.compileLiteral("hello?", .{});
    defer db.deinit();

    var scratch = try Scratch.init(&db);
    defer scratch.deinit();

    // Should NOT match "hell" (? is literal, not optional)
    try std.testing.expect(!try db.matches(&scratch, "hell"));
    // Should match "hello?"
    try std.testing.expect(try db.matches(&scratch, "hello?"));
}

test "database serialization" {
    var db = try Database.compile("test", .{});
    defer db.deinit();

    const bytes = try db.serialize(std.testing.allocator);
    defer std.testing.allocator.free(bytes);

    try std.testing.expect(bytes.len > 0);

    var db2 = try Database.deserialize(bytes);
    defer db2.deinit();

    var scratch = try Scratch.init(&db2);
    defer scratch.deinit();

    try std.testing.expect(try db2.matches(&scratch, "test"));
}

test "streaming mode" {
    var db = try Database.compile("hello world", .{ .mode = .stream });
    defer db.deinit();

    var scratch = try Scratch.init(&db);
    defer scratch.deinit();

    var stream = try db.openStream();
    defer stream.deinit();

    var match_count: usize = 0;
    const Ctx = struct {
        count: *usize,
    };

    // Write data in chunks
    _ = try stream.scan(&scratch, "hello ", &Ctx{ .count = &match_count }, struct {
        fn cb(_: *const Ctx, _: Match) bool {
            return true;
        }
    }.cb);

    _ = try stream.scan(&scratch, "world", &Ctx{ .count = &match_count }, struct {
        fn cb(ctx: *const Ctx, _: Match) bool {
            ctx.count.* += 1;
            return true;
        }
    }.cb);

    try std.testing.expectEqual(@as(usize, 1), match_count);
}

test "case insensitive matching" {
    var db = try Database.compile("hello", .{ .flags = .{ .caseless = true } });
    defer db.deinit();

    var scratch = try Scratch.init(&db);
    defer scratch.deinit();

    try std.testing.expect(try db.matches(&scratch, "HELLO"));
    try std.testing.expect(try db.matches(&scratch, "HeLLo"));
    try std.testing.expect(try db.matches(&scratch, "hello"));
}

test "version check" {
    const ver = version();
    try std.testing.expect(ver.len > 0);
}

test "platform validation" {
    // Should succeed on supported platforms
    try std.testing.expect(isPlatformValid());
}
