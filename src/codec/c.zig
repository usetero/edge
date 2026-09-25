//! The one C import for this module, so every file sees the same types.
pub const c = @cImport({
    @cInclude("zlib.h");
    @cInclude("zstd.h");
    @cInclude("zstd_errors.h");
});
