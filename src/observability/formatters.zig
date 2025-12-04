const std = @import("std");
const Level = @import("level.zig").Level;

/// Format a timestamp as HH:MM:SS
pub fn formatTimestamp(buf: []u8) []const u8 {
    const timestamp = std.time.timestamp();
    const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = @intCast(timestamp) };
    const day_seconds = epoch_seconds.getDaySeconds();

    return std.fmt.bufPrint(buf, "{d:0>2}:{d:0>2}:{d:0>2}", .{
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
        day_seconds.getSecondsIntoMinute(),
    }) catch "??:??:??";
}

/// Format a timestamp as ISO8601
pub fn formatTimestampISO(buf: []u8) []const u8 {
    const timestamp = std.time.timestamp();
    const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = @intCast(timestamp) };
    const epoch_day = epoch_seconds.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = epoch_seconds.getDaySeconds();

    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        year_day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
        day_seconds.getSecondsIntoMinute(),
    }) catch "????-??-??T??:??:??Z";
}

test "formatTimestamp" {
    var buf: [16]u8 = undefined;
    const ts = formatTimestamp(&buf);
    try std.testing.expectEqual(@as(usize, 8), ts.len); // HH:MM:SS
    try std.testing.expectEqual(@as(u8, ':'), ts[2]);
    try std.testing.expectEqual(@as(u8, ':'), ts[5]);
}

test "formatTimestampISO" {
    var buf: [32]u8 = undefined;
    const ts = formatTimestampISO(&buf);
    try std.testing.expectEqual(@as(usize, 20), ts.len);
    try std.testing.expectEqual(@as(u8, 'T'), ts[10]);
    try std.testing.expectEqual(@as(u8, 'Z'), ts[19]);
}
