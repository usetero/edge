//! Request-owned response spans; only scalar initialized lengths cross completion.
const Self = @This();

parts: [3][]const u8,
close: bool,
part: u8 = 0,
offset: usize = 0,

pub const Buffers = struct { head: []u8, body: []u8, tail: []u8 };
pub const Lengths = struct { head: u32, body: u32, tail: u32, close: bool };

/// The owner must retain the responding request slot for the lifetime of this view.
/// Losing the client or finishing its response invalidates every borrowed span.
pub fn init(buffers: Buffers, lengths: Lengths) !Self {
    if (lengths.head > buffers.head.len or lengths.body > buffers.body.len or lengths.tail > buffers.tail.len) {
        return error.InvalidResponseLength;
    }
    return .{
        .parts = .{ buffers.head[0..lengths.head], buffers.body[0..lengths.body], buffers.tail[0..lengths.tail] },
        .close = lengths.close,
    };
}

/// Borrow the next contiguous span; the socket owner applies its write-turn limit.
pub fn pending(self: *Self) []const u8 {
    while (self.part < self.parts.len and self.offset == self.parts[self.part].len) {
        self.part += 1;
        self.offset = 0;
    }
    return if (self.part == self.parts.len) "" else self.parts[self.part][self.offset..];
}

/// Advance only by bytes actually accepted by the transport, including zero.
pub fn advance(self: *Self, count: usize) !void {
    if (count > self.pending().len) return error.InvalidWriteLength;
    self.offset += count;
}
