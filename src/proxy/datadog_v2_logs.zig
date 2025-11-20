const std = @import("std");
const httpz = @import("httpz");

/// Handles Datadog log ingestion
/// Takes an httpz.Request object and data buffer, processes the logs, and returns them in original format
/// Uses the request's arena allocator for all temporary allocations
pub fn processDatadogLogs(request: *httpz.Request, data: []const u8, verbose: bool) ![]u8 {
    const allocator = request.arena;

    // Check if the data is compressed
    const isCompressed = checkIfCompressed(request);

    // Decompress if needed
    var processedData: []u8 = undefined;
    var needsCleanup = false;

    if (isCompressed) {
        processedData = try decompressGzip(allocator, data);
        needsCleanup = true;
    } else {
        // Create a mutable copy for non-compressed data
        processedData = try allocator.alloc(u8, data.len);
        @memcpy(processedData, data);
        needsCleanup = true;
    }
    defer if (needsCleanup) allocator.free(processedData);

    // Determine the content type
    const contentType = getContentType(request);

    // Process based on content type
    if (std.mem.indexOf(u8, contentType, "application/json") != null) {
        // Parse and log JSON data
        if (verbose) {
            try processJsonLogs(allocator, processedData);
        }
    } else if (std.mem.indexOf(u8, contentType, "application/logplex") != null) {
        // Handle logplex format
        if (verbose) {
            try processLogplexLogs(processedData);
        }
    } else {
        // Handle raw text logs
        if (verbose) {
            try processRawLogs(processedData);
        }
    }

    // Reserialize the data in original format
    var result: []u8 = undefined;

    if (isCompressed) {
        // Recompress the data
        result = try compressGzip(allocator, processedData);
    } else {
        // Return uncompressed data
        result = try allocator.alloc(u8, processedData.len);
        @memcpy(result, processedData);
    }

    return result;
}

/// Check if the request contains compressed data using httpz.Request
fn checkIfCompressed(request: *httpz.Request) bool {
    // httpz.Request has a headers field that can be queried
    if (request.header("Content-Encoding")) |encoding| {
        return std.mem.indexOf(u8, encoding, "gzip") != null or
            std.mem.indexOf(u8, encoding, "deflate") != null;
    }
    return false;
}

/// Get the content type from request headers using httpz.Request
fn getContentType(request: *httpz.Request) []const u8 {
    if (request.header("Content-Type")) |content_type| {
        return content_type;
    }
    return "text/plain";
}

/// Decompress gzip data
fn decompressGzip(allocator: std.mem.Allocator, compressed: []const u8) ![]u8 {
    // Zig 0.15.x: Reader requires explicit buffer
    var reader: std.io.Reader = .fixed(compressed);
    var writer: std.io.Writer.Allocating = .init(allocator);
    defer writer.deinit();
    var decompressed: std.compress.flate.Decompress = .init(&reader, .gzip, &.{});
    _ = decompressed.reader.streamRemaining(&writer.writer) catch |err| switch (err) {
        error.ReadFailed => 0,
        error.WriteFailed => 0,
        else => return err,
    };

    const result = writer.written();
    std.log.info("result: {any}", .{result});
    return allocator.dupe(u8, result);
}

/// Compress data using gzip
fn compressGzip(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    std.debug.print("Compressing data 1...\n", .{});
    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();
    std.debug.print("Compressing data 2...\n", .{});
    // Create a compressor that writes to our Allocating writer
    var compress_buffer: [4096]u8 = undefined;
    var compressor = std.compress.flate.Compress.init(&aw.writer, &compress_buffer, .{
        .container = .gzip,
    });
    std.debug.print("Compressing data 3...\n", .{});

    // Write all data
    try compressor.writer.writeAll(data);
    std.debug.print("Compressing data 3.5 - before end...\n", .{});
    try compressor.endUnflushed();
    std.debug.print("Compressing data 4...\n", .{});
    return try aw.toOwnedSlice();
}

/// Process JSON formatted logs
fn processJsonLogs(allocator: std.mem.Allocator, data: []const u8) !void {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, data, .{});
    defer parsed.deinit();

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    // Check if it's an array of logs or a single log
    switch (parsed.value) {
        .array => |logs| {
            try stdout.print("Processing {d} log entries:\n", .{logs.items.len});
            try stdout.flush();
            for (logs.items, 0..) |log, i| {
                try stdout.print("\n=== Log Entry {d} ===\n", .{i + 1});
                try stdout.flush();
                try printJsonLog(log);
            }
        },
        .object => {
            try stdout.print("\n=== Single Log Entry ===\n", .{});
            try stdout.flush();
            try printJsonLog(parsed.value);
        },
        else => {
            try stdout.print("Unexpected JSON format\n", .{});
            try stdout.flush();
        },
    }
}

/// Print a single JSON log entry
fn printJsonLog(log: std.json.Value) !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    try std.json.Stringify.value(log, .{ .whitespace = .indent_2 }, stdout);
    try stdout.print("\n", .{});
    try stdout.flush();
}

/// Process logplex formatted logs
fn processLogplexLogs(data: []const u8) !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    try stdout.print("\n=== Logplex Format Logs ===\n", .{});
    try stdout.flush();

    // Logplex format: <prival>version timestamp hostname app procid msgid msg
    var lines = std.mem.tokenize(u8, data, "\n");
    var lineNum: usize = 1;

    while (lines.next()) |line| {
        try stdout.print("Line {d}: {s}\n", .{ lineNum, line });

        // Basic parsing of syslog format
        if (line.len > 0 and line[0] == '<') {
            // Find end of priority
            if (std.mem.indexOf(u8, line, ">")) |endPri| {
                const remaining = line[endPri + 1 ..];
                var parts = std.mem.tokenize(u8, remaining, " ");

                if (parts.next()) |version| {
                    try stdout.print("  Version: {s}\n", .{version});
                }
                if (parts.next()) |timestamp| {
                    try stdout.print("  Timestamp: {s}\n", .{timestamp});
                }
                if (parts.next()) |hostname| {
                    try stdout.print("  Hostname: {s}\n", .{hostname});
                }
                if (parts.next()) |app| {
                    try stdout.print("  App: {s}\n", .{app});
                }
                if (parts.next()) |procid| {
                    try stdout.print("  ProcID: {s}\n", .{procid});
                }
                if (parts.next()) |msgid| {
                    try stdout.print("  MsgID: {s}\n", .{msgid});
                }

                // Rest is the message
                if (parts.rest().len > 0) {
                    try stdout.print("  Message: {s}\n", .{parts.rest()});
                }
            }
        }

        lineNum += 1;
    }
    try stdout.flush();
}

/// Process raw text logs
fn processRawLogs(data: []const u8) !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    try stdout.print("\n=== Raw Text Logs ===\n", .{});

    // Split by newlines and print each line
    var lines = std.mem.tokenize(u8, data, "\n");
    var lineNum: usize = 1;

    while (lines.next()) |line| {
        try stdout.print("Line {d}: {s}\n", .{ lineNum, line });
        lineNum += 1;
    }

    try stdout.print("\nTotal bytes: {d}\n", .{data.len});
    try stdout.flush();
}

// ============================================================================
// MAIN PUBLIC FUNCTION - Simple Interface
// ============================================================================

/// Main public function for processing Datadog logs
/// Takes an httpz.Request and data buffer
/// Returns the data in its original format (compressed if it was compressed)
/// Uses the request's arena allocator for all temporary allocations
pub fn process(request: *httpz.Request, data: []const u8) ![]u8 {
    return processDatadogLogs(request, data, true);
}

// ============================================================================
// TESTS
// ============================================================================

test "processJsonLogs" {
    const allocator = std.testing.allocator;

    // Test JSON log
    const jsonLog =
        \\[{
        \\  "ddsource": "nginx",
        \\  "ddtags": "env:staging,version:5.1",
        \\  "hostname": "i-012345678",
        \\  "message": "2019-11-19T14:37:58,995 INFO [process.name][20081] Hello World",
        \\  "service": "payment",
        \\  "status": "info"
        \\}]
    ;

    // Just test that JSON processing doesn't crash
    try processJsonLogs(allocator, jsonLog);
}

test "compressGzip and decompressGzip" {
    const allocator = std.testing.allocator;

    const originalData = "Test log message";

    // Compress the test data
    std.debug.print("Compressing data...\n", .{});
    const compressed = try compressGzip(allocator, originalData);
    std.debug.print("Successfully compressed data...\n", .{});
    defer allocator.free(compressed);

    std.debug.print("Compressed data length: {}\n", .{compressed.len});

    try std.testing.expect(compressed.len > 0 and compressed.len != 8);

    // Decompress to verify
    std.debug.print("Decompressing data...\n", .{});
    const decompressed = try decompressGzip(allocator, compressed);
    defer allocator.free(decompressed);

    try std.testing.expectEqualStrings(originalData, decompressed);
}
