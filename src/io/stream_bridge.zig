const std = @import("std");

pub const StreamBridge = struct {
    pub fn pipe(reader: *std.Io.Reader, writer: *std.Io.Writer) !u64 {
        var total: u64 = 0;
        var buf: [4096]u8 = undefined;
        while (true) {
            var fixed_writer = std.Io.Writer.fixed(&buf);
            const n = reader.stream(&fixed_writer, .limited(buf.len)) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return err,
            };
            if (n == 0) break;
            try writer.writeAll(fixed_writer.buffered()[0..n]);
            total += n;
        }
        return total;
    }
};

test "stream bridge copies all bytes" {
    var input = std.Io.Reader.fixed("hello world");
    var out_buf: [64]u8 = undefined;
    var output = std.Io.Writer.fixed(&out_buf);
    const n = try StreamBridge.pipe(&input, &output);
    try std.testing.expectEqual(@as(u64, 11), n);
    try std.testing.expectEqualStrings("hello world", output.buffered());
}
