# Tero Edge - Project Overview

## Architecture

This is a Zig project implementing an edge computing runtime with a hybrid architectural approach:

- **Data-Oriented Design (DoD)**: Primary focus for performance-critical paths
- **Functional Programming**: For composability and testability
- **Object-Oriented Programming**: Where it provides clarity without sacrificing performance

## Data-Oriented Design Principles

### Core Philosophy
**The CPU is fast, but memory is slow.** All design decisions must optimize for memory access patterns and cache coherency.
**Predictable memory usage is the goal.** Each binary should have a predictable memory footprint based on throughput.

### Key Strategies

#### 1. Identify and Optimize Uniform Data
- Group similar data together in memory
- Minimize the size of each individual item
- Process data in bulk rather than one item at a time

#### 2. Use Indexes Instead of Pointers
```zig
// BAD: Pointer-heavy approach (64 bits per reference)
const Node = struct {
    data: Data,
    next: ?*Node,
    parent: ?*Node,
};

// GOOD: Index-based approach (typically 32 bits or less)
const NodeId = u32;
const Node = struct {
    data: Data,
    next: ?NodeId,
    parent: ?NodeId,
};
const NodeStorage = std.ArrayList(Node);
```

#### 3. Manage Type Safety with Compact Representations
```zig
// Use strongly-typed handles instead of raw integers
const HandleType = enum { request, response, connection };
fn Handle(comptime T: HandleType) type {
    return enum(u32) { _ };
}

const RequestHandle = Handle(.request);
const ResponseHandle = Handle(.response);
```

#### 4. Store Booleans Separately

SKIP THIS FOR NOW.

#### 5. Eliminate Padding with Struct-of-Arrays
```zig
// BAD: Array-of-Structs (AoS) - poor cache utilization
const Connection = struct {
    id: u64,           // 8 bytes
    status: u8,        // 1 byte + 3 bytes padding
    port: u16,         // 2 bytes + 2 bytes padding
    address: [16]u8,   // 16 bytes
};
const connections = std.ArrayList(Connection);

// GOOD: Struct-of-Arrays (SoA) - excellent cache utilization
const Connection = struct {
    id: u64,           // 8 bytes
    status: u8,        // 1 byte + 3 bytes padding
    port: u16,         // 2 bytes + 2 bytes padding
    address: [16]u8,   // 16 bytes
};
const connections = std.MultiArrayList(Connection);

```

#### 6. Use Hash Maps for Sparse Data
```zig
// When only a small subset of entities has certain data
const SparseMetadata = std.AutoHashMap(EntityId, Metadata);
```

#### 7. Encoding Instead of Polymorphism
```zig
// BAD: Runtime polymorphism (vtable overhead)
const Handler = struct {
    vtable: *const VTable,
    data: *anyopaque,
};

// GOOD: Tagged unions with explicit types
const HandlerType = enum { http, websocket, grpc };
const Handler = union(HandlerType) {
    http: HttpHandler,
    websocket: WebSocketHandler,
    grpc: GrpcHandler,
    
    fn process(self: *Handler, data: []const u8) void {
        switch (self.*) {
            .http => |*h| h.processHttp(data),
            .websocket => |*w| w.processWs(data),
            .grpc => |*g| g.processGrpc(data),
        }
    }
};
```

## Module System

### Philosophy
The codebase is organized into **composable modules** that can be selectively combined to create different distributions. Each module should:

1. Be self-contained with minimal dependencies
2. Export a clear public API through its root file
3. Define its own types and data structures
4. Be independently testable

### Structure
```
src/
├── core/           # Core runtime primitives
│   ├── allocator.zig
│   ├── event_loop.zig
│   └── scheduler.zig
├── network/        # Network stack
│   ├── tcp.zig
│   ├── udp.zig
│   └── http.zig
├── storage/        # Storage layer
│   ├── cache.zig
│   └── persistence.zig
├── security/       # Security primitives
│   ├── tls.zig
│   └── auth.zig
└── distributions/  # Distribution-specific compositions
    ├── minimal.zig
    ├── full.zig
    └── custom.zig
```

### Distribution Composition
Each distribution manually selects and composes the modules it needs:

```zig
// distributions/minimal.zig
const core = @import("../core/event_loop.zig");
const network = @import("../network/tcp.zig");

pub fn main() !void {
    var runtime = try core.Runtime.init();
    defer runtime.deinit();
    
    var tcp_server = try network.TcpServer.init(&runtime);
    defer tcp_server.deinit();
    
    try runtime.run();
}
```

## Code Organization Best Practices

### 1. Separate Hot and Cold Data
```zig
// Hot data: accessed frequently
const EntityHot = struct {
    position: Vec3,
    velocity: Vec3,
};

// Cold data: accessed rarely
const EntityCold = struct {
    name: []const u8,
    metadata: Metadata,
};

const EntityId = u32;
const hot_data = std.ArrayList(EntityHot);
const cold_data = std.AutoHashMap(EntityId, EntityCold);
```

### 2. Batch Processing
```zig
// Process data in batches for better cache utilization
fn updatePositions(entities: []Entity, dt: f32) void {
    for (entities) |*entity| {
        entity.position.x += entity.velocity.x * dt;
        entity.position.y += entity.velocity.y * dt;
        entity.position.z += entity.velocity.z * dt;
    }
}
```

### 3. Memory Alignment
```zig
// Align data structures for optimal CPU access
const CacheLine = 64; // bytes
const alignas = CacheLine;

const PerformanceCritical = struct {
    // Hot data aligned to cache line
    data: [16]u32 align(alignas),
};
```

### 4. Arena Allocators for Temporary Data
```zig
fn processRequest(arena: *std.heap.ArenaAllocator, request: Request) !Response {
    // All temporary allocations use arena
    const temp_buffer = try arena.allocator().alloc(u8, 1024);
    // No need to free - arena will be reset
    
    // ... process request ...
    
    return response;
}
```

## Testing Strategy

- **Unit tests**: Test individual functions with `test` blocks
- **Integration tests**: Test module interactions
- **Benchmark tests**: Verify performance characteristics using `std.time`
- **Memory tests**: Use `std.testing.allocator` to detect leaks

## Performance Guidelines

1. **Profile before optimizing** - Use `std.time.Timer` and platform profilers
2. **Minimize allocations** - Reuse buffers where possible
3. **Prefer stack over heap** - Use fixed-size buffers when bounds are known
4. **Avoid indirection** - Direct function calls over function pointers when possible
5. **Think in terms of data transformations** - Input → Process → Output

## Functional Programming Aspects

- Use pure functions where possible (no side effects)
- Leverage comptime for zero-cost abstractions
- Prefer explicit error handling with `!` and `catch`
- Use const by default, mut when necessary

## When to Use OOP

Object-oriented patterns are acceptable when:
- They improve code clarity without performance cost
- The domain naturally maps to objects (e.g., Connection, Server)
- Methods help organize related functionality
- State encapsulation provides safety

**Always measure**: If OOP introduces indirection or hurts cache coherency, refactor to DoD.

## Build System

The project uses Zig's build system (`build.zig`) to:
- Define multiple build targets (distributions)
- Manage dependencies
- Configure compilation options
- Run tests

## Getting Started

When modifying or extending this project:
1. Identify the module(s) you need to change
2. Consider the data layout and access patterns
3. Prefer transforming contiguous arrays over scattered object updates
4. Write tests to verify correctness
5. Benchmark to verify performance
6. Update relevant distributions if needed

## Questions to Ask Before Coding

1. How will this data be accessed? (Sequential, random, sparse?)
2. What is the typical working set size?
3. Can I process this in batches?
4. Are there hot/cold splits in this data?
5. Can I use indexes instead of pointers?
6. Does this need to be in the hot path?

---

Remember: **Optimize for data locality first, algorithmic complexity second.**

---
# Zig 0.15.x std.io Breaking Changes Reference

**Zig 0.15.x introduced "Writergate"—a complete redesign of std.io Reader and Writer interfaces that fundamentally changes how I/O operations work.** The new interfaces replace generic `anytype`-based APIs with concrete types that integrate buffering directly into the interface itself. This change delivers 45-49% performance improvements but requires explicit buffer management and manual flushing. All existing code using std.io readers and writers will break and must be migrated.

## Why this matters for Tero Edge

These changes are **extremely breaking** (Andrew Kelley's words) and affect every file, network, and console I/O operation. The new architecture eliminates the generic `std.io.GenericReader` and `std.io.GenericWriter` types, requiring buffers to be provided at instantiation time. Code that worked in Zig 0.14.x will fail to compile or produce silent failures (missing output due to unflushed buffers) in 0.15.x. This redesign is permanent and foundational for Zig's future async/await implementation—there is no going back to the old interfaces.

Understanding these changes is critical for Tero Edge because the project needs current, accurate I/O patterns. The old patterns are now deprecated or completely removed. Future AI assistants must know: **you cannot copy interface instances, you must always flush writers, and buffers are mandatory**. These aren't optional optimizations—they're fundamental requirements of the new API.

---

## The fundamental architectural shift

Zig 0.15.x moves from generic, implementation-defined buffering to concrete, interface-level buffering. The **buffer now lives in the interface itself** (above the vtable), not in the implementation. This "buffer above vtable" design enables the hot path—most I/O operations—to work directly on the buffer without vtable calls, while only calling into the vtable when the buffer fills or empties.

**Old architecture (0.14.x):** Generic types like `std.io.GenericReader(T)` and `std.io.GenericWriter(T)` wrapped underlying resources. Buffering was optional via separate `bufferedReader()` and `bufferedWriter()` wrappers. Every function accepting a reader or writer became generic with `anytype` parameters, poisoning struct types.

**New architecture (0.15.x):** Concrete `std.Io.Reader` and `std.Io.Writer` types with integrated buffers. No more generics for basic I/O. Buffer is a required field in the interface struct itself, making buffering the default behavior rather than an opt-in wrapper.

The performance gains are substantial: **45.7% faster wall time**, 49% fewer CPU cycles, and 24.4% fewer instructions in I/O-heavy operations. Debug mode compilation is roughly 5x faster using the self-hosted x86 backend. The trade-off is explicit complexity—developers must manage buffers and remember to flush.

---

## Critical breaking change 1: Explicit buffer requirements

Every reader and writer instantiation **must provide a buffer**. There is no default allocation, no hidden memory management. This is Zig philosophy: no hidden control flow, no surprise allocations.

**Code that breaks:**
```zig
// 0.14.x - worked fine
const stdout = std.io.getStdOut().writer();
try stdout.print("Hello\n", .{});
```

**Required pattern in 0.15.x:**
```zig
// Must allocate buffer explicitly
var stdout_buffer: [4096]u8 = undefined;
var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
const stdout = &stdout_writer.interface;
try stdout.print("Hello\n", .{});
try stdout.flush(); // CRITICAL: Must flush!
```

**Buffer sizing guidelines:**
- **4096 bytes (one page):** Standard for general I/O operations
- **8192 bytes:** Better for high-throughput scenarios
- **std.crypto.tls.max_ciphertext_record_len:** Required minimum for TLS operations
- **Empty buffer `&.{}`:** Opt-out to unbuffered mode (not recommended)

Buffers can be stack-allocated for short-lived operations or heap-allocated for long-running resources. The official recommendation is to **consider making frequently-used buffers (like stdout) global** to avoid repeated stack allocation overhead.

---

## Critical breaking change 2: The flush requirement

Buffered data **does not automatically commit**. Forgetting `flush()` causes silent failures where programs run successfully but produce no output. This is the single most common migration bug.

**Why flushing is mandatory:** The interface accumulates data in its buffer to reduce system calls. Until you call `flush()`, the data remains in memory, never reaching the file descriptor, socket, or console.

**When you must flush:**
- Before program exit
- After writing data you expect to see immediately
- Before switching between read and write operations on the same resource
- Before passing control to code that might read what you wrote
- After writing to stdout/stderr if you need immediate visibility

**Example of silent failure:**
```zig
var buffer: [4096]u8 = undefined;
var writer = std.fs.File.stdout().writer(&buffer);
const stdout = &writer.interface;
try stdout.print("Important message\n", .{});
// Program ends - buffer never flushed, output never appears!
```

**Correct pattern:**
```zig
var buffer: [4096]u8 = undefined;
var writer = std.fs.File.stdout().writer(&buffer);
const stdout = &writer.interface;
try stdout.print("Important message\n", .{});
try stdout.flush(); // Now output appears
```

---

## Critical breaking change 3: The @fieldParentPtr footgun

The new interfaces use `@fieldParentPtr` internally to recover the parent wrapper struct from the interface field. This creates a **critical invariant: you must never copy interface instances**.

**What breaks:**
```zig
var file_reader = file.reader(&buf);
const reader = file_reader.interface; // WRONG - copies the interface
while (reader.takeDelimiterExclusive('\n')) |line| {
    // Crashes with "switch on corrupt value" or undefined behavior
}
```

**Correct pattern:**
```zig
var file_reader = file.reader(&buf);
const reader = &file_reader.interface; // RIGHT - pointer to interface
while (reader.takeDelimiterExclusive('\n')) |line| {
    // Works correctly
}
```

**Why this happens:** When you copy the interface, the vtable methods call `@fieldParentPtr` expecting to find the parent struct at a specific memory offset. But the copied interface is no longer at that offset relative to the parent, causing memory corruption or crashes.

**Rule of thumb:** Interface types are always passed as pointers (`*std.Io.Reader`, `*std.Io.Writer`). Never use them as values.

---

## New Reader interface and methods

The `std.Io.Reader` type replaces `std.io.GenericReader` and all reader-related generic types. It's a concrete struct with three fields:

```zig
pub const Reader = struct {
    vtable: *const VTable,
    buffer: []u8,          // Ring buffer
    seek: usize = 0,       // Bytes consumed from buffer
    end: usize = 0,        // End of buffered data
};
```

**Key methods that replace old APIs:**

**`takeDelimiterExclusive(delimiter: u8)`** replaces `readUntilDelimiterOrEof()`:
```zig
while (reader.takeDelimiterExclusive('\n')) |line| {
    // Process line (delimiter not included)
} else |err| switch (err) {
    error.EndOfStream => {},           // Normal end of stream
    error.StreamTooLong => {},         // Line exceeds buffer size
    error.ReadFailed => return err,    // Actual I/O error
}
```

**`stream(writer: *Writer, limit: StreamLimit)`** for copying data:
```zig
// Copy up to 1024 bytes from reader to writer
const n = try reader.stream(writer, .limited(1024));

// Copy until end of stream
const n = try reader.stream(writer, .until_end);
```

**`peek()` and `take()`** for zero-copy buffer access:
```zig
const available = reader.peek(); // View buffered data without consuming
const slice = try reader.take(100); // Take exactly 100 bytes
```

**`toss(n: usize)`** to discard data:
```zig
// Skip delimiter byte after streamDelimiter
try reader.toss(1);
```

**Removed methods from 0.14.x:**
- `readUntilDelimiterOrEof()` → Use `takeDelimiterExclusive()`
- `readAll()` → Use `stream()` with appropriate limit
- `readNoEof()` → Use `take()`
- Generic variants → All replaced by concrete methods

---

## New Writer interface and methods

The `std.Io.Writer` type replaces `std.io.GenericWriter` with a concrete implementation:

```zig
pub const Writer = struct {
    vtable: *const VTable,
    buffer: []u8,
    end: usize = 0,        // Current buffer fill level
};
```

**Essential methods:**

**`writeAll(bytes: []const u8)`** for writing complete slices:
```zig
try writer.writeAll("Complete message\n");
```

**`print(comptime fmt: []const u8, args: anytype)`** for formatted output:
```zig
try writer.print("Value: {d}\n", .{42});
```

**`flush()`** to commit buffered data:
```zig
try writer.flush(); // Calls drain() on implementation
```

**`drain()`** (vtable method) for custom implementations—writes buffered data to underlying resource.

**New specialized writers:**

**`std.Io.Writer.Allocating`** for dynamic allocation:
```zig
var writer = std.Io.Writer.Allocating.init(allocator);
defer writer.deinit();
try writer.writer.writeAll("Data");
const result = writer.written(); // Get accumulated slice
```

**`std.Io.Writer.Discarding`** for counting without storage:
```zig
var counter = std.Io.Writer.Discarding{};
try counter.writer.writeAll(data);
const bytes_written = counter.count;
```

**`std.Io.Writer.fixed(buffer: []u8)`** for fixed buffers:
```zig
var buf: [1024]u8 = undefined;
var writer = std.Io.Writer.fixed(&buf);
try writer.writeAll("data");
```

---

## Stream interfaces are gone

The `std.io.SeekableStream` type and related abstractions **have been completely removed**. There is no direct replacement—use specific concrete types instead.

**Migration paths:**

**For file operations:**
- Use `*std.fs.File.Reader` with positional read support
- Use `*std.fs.File.Writer` with positional write support
- These types memoize file information (size, position) for efficient seeking

**For memory operations:**
- Use `std.ArrayListUnmanaged(u8)` as a growable buffer
- Use `std.Io.Writer.fixed()` for fixed-size memory buffers

**For network operations:**
- `std.net.Stream.reader()` and `std.net.Stream.writer()` now return `std.fs.File.Reader` and `std.fs.File.Writer` wrappers
- Must provide buffers to these methods

**Example migration:**
```zig
// 0.14.x - had SeekableStream
var seekable = file.seekableStream();
try seekable.seekTo(100);

// 0.15.x - use File.Reader with positional reads
var buf: [4096]u8 = undefined;
var reader = file.reader(&buf);
// Positional reads are automatic when file supports them
```

---

## File operations now require explicit buffering

The `std.fs.File` type's reader and writer methods **require buffer parameters**.

**Old pattern (0.14.x):**
```zig
const file = try std.fs.cwd().openFile("data.txt", .{});
const reader = file.reader(); // No buffer needed
```

**New pattern (0.15.x):**
```zig
const file = try std.fs.cwd().openFile("data.txt", .{});
var read_buffer: [4096]u8 = undefined;
var file_reader = file.reader(&read_buffer);
const reader = &file_reader.interface;
```

**File.Reader benefits:**
- Memoizes file size and position
- Automatically uses positional reads when available (seeking becomes no-ops)
- Supports `sendFile()` for zero-copy file-to-file transfers
- Falls back gracefully to streaming when positional I/O unavailable

**File.Writer benefits:**
- Similar memoization for write operations
- Integrated buffering reduces system calls
- Positional writes when supported

**Removed file APIs:**
- `writeFileAll()` → Use `File.Writer` methods
- `writeFileAllUnseekable()` → Use `File.Writer` methods
- Direct `WriteFileOptions` → Pass buffer to `writer()` method

**Changed APIs:**
- `std.fs.Dir.atomicFile()` now requires `write_buffer` in options
- `std.fs.Dir.copyFile()` can no longer fail with `error.OutOfMemory` (uses stack-allocated buffers)

---

## Complete list of std.io namespace changes

**Fully removed (no deprecation period):**
- `std.io.SeekableStream` → Use concrete file/memory types
- `std.io.BitReader` → Removed entirely
- `std.io.BitWriter` → Removed entirely
- `std.io.LimitedReader` → Use `Reader.stream()` with `.limited()`
- `std.fifo.LinearFifo` → Replaced by Reader/Writer as ring buffers
- `std.RingBuffer` → Obsolete with new interfaces
- All ring buffer implementations (5 different types consolidated)

**Deprecated (warnings, will be removed):**
- `std.io.GenericReader` → Use `std.Io.Reader`
- `std.io.GenericWriter` → Use `std.Io.Writer`
- `std.io.AnyReader` → Use `std.Io.Reader`
- `std.io.AnyWriter` → Use `std.Io.Writer`
- `std.io.bufferedReader()` → Buffering now built-in
- `std.io.bufferedWriter()` → Buffering now built-in

**New APIs replacing old patterns:**
- `takeDelimiterExclusive()` replaces `readUntilDelimiterOrEof()`
- `stream()` replaces `readAll()` and related methods
- `Reader.pull()` (vtable) replaces custom read implementations
- `Writer.drain()` (vtable) replaces custom write implementations

**Migration adapter (temporary):**
```zig
// For gradual migration only - has known bugs
fn foo(old_writer: anytype) !void {
    var adapter = old_writer.adaptToNewApi(&.{});
    const w: *std.Io.Writer = &adapter.new_interface;
    try w.print("{s}", .{"example"});
}
```

This adapter is **not recommended for production** and may not work in all cases (GitHub issue #24483 documents limitations).

---

## HTTP Client and Server changes

Both `std.http.Client` and `std.http.Server` underwent major restructuring due to the I/O changes.

**HTTP Server migration:**
```zig
// 0.14.x
var read_buffer: [8000]u8 = undefined;
var server = std.http.Server.init(connection, &read_buffer);

// 0.15.x - separate buffers for read and write
var recv_buffer: [4000]u8 = undefined;
var send_buffer: [4000]u8 = undefined;
var conn_reader = connection.stream.reader(&recv_buffer);
var conn_writer = connection.stream.writer(&send_buffer);
var server = std.http.Server.init(conn_reader.interface(), &conn_writer.interface);
```

**HTTP Client migration:**
```zig
// 0.14.x
var server_header_buffer: [1024]u8 = undefined;
var req = try client.open(.GET, uri, .{
    .server_header_buffer = &server_header_buffer,
});
defer req.deinit();
try req.send();
try req.wait();
const body_reader = try req.reader();

// 0.15.x - new request/response pattern
var req = try client.request(.GET, uri, .{});
defer req.deinit();
try req.sendBodiless();
var response = try req.receiveHead(&.{});

// Process headers before reading body
var it = response.head.iterateHeaders();
while (it.next()) |header| {
    // Headers become invalid after reader() call
}

var reader_buffer: [100]u8 = undefined;
const body_reader = response.reader(&reader_buffer);
```

**Key architectural improvement:** HTTP modules no longer depend on `std.net`. They operate purely on Reader/Writer interfaces, making them more testable and flexible.

---

## TLS client requires four separate buffers

The `std.crypto.tls.Client` type now requires **four distinct buffers** for operation:

```zig
// 1. Network stream read buffer
var stream_read_buf: [std.crypto.tls.max_ciphertext_record_len]u8 = undefined;
var stream_reader = stream.reader(&stream_read_buf);

// 2. Network stream write buffer
var stream_write_buf: [std.crypto.tls.max_ciphertext_record_len]u8 = undefined;
var stream_writer = stream.writer(&stream_write_buf);

// 3. TLS client read buffer
var tls_read_buf: [std.crypto.tls.max_ciphertext_record_len]u8 = undefined;

// 4. TLS client write buffer
var tls_write_buf: [std.crypto.tls.max_ciphertext_record_len]u8 = undefined;

var tls_client = try std.crypto.tls.Client.init(
    stream_reader.interface(),
    &stream_writer.interface,
    .{
        .ca = .{.bundle = bundle},
        .host = .{ .explicit = "example.com" },
        .read_buffer = &tls_read_buf,
        .write_buffer = &tls_write_buf,
    },
);
```

This complexity has been controversial in the community, but reflects the layered nature of TLS: the outer layer buffers network I/O, the inner layer buffers TLS protocol operations.

**Benefit:** `std.crypto.tls.Client` no longer depends on `std.net` or `std.fs`, operating purely on abstract I/O interfaces.

---

## Compression API restructured

The `std.compress.flate` module underwent major changes:

**Decompression (still supported):**
```zig
var decompress_buffer: [std.compress.flate.max_window_len]u8 = undefined;
var decompress: std.compress.flate.Decompress = .init(reader, .zlib, &decompress_buffer);
const decompress_reader: *std.Io.Reader = &decompress.reader;

// Or stream directly to writer
var decompress: std.compress.flate.Decompress = .init(reader, .zlib, &.{});
const n = try decompress.streamRemaining(writer);
```

**Compression (temporarily removed):** Deflate compression functionality was removed in 0.15.x. The official release notes state this is temporary, prioritizing language design over standard library completeness. Third-party compression libraries are recommended for now.

**Container formats:** The API now requires explicit container parameter (`.zlib`, `.gzip`, `.raw`) instead of inferring from context.

---

## Format string changes require migration

Custom format implementations must be updated to the new signature:

**Old format method (0.14.x):**
```zig
pub fn format(
    this: @This(),
    comptime format_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    try writer.print("Custom: {}", .{this.value});
}
```

**New format method (0.15.x):**
```zig
pub fn format(
    this: @This(), 
    writer: *std.Io.Writer
) std.Io.Writer.Error!void {
    try writer.print("Custom: {}", .{this.value});
}
```

**Format specifier changes:**
- **`{}`** is now ambiguous if type has a `format()` method (compilation error)
- **`{f}`** explicitly calls the `format()` method
- **`{any}`** explicitly skips the `format()` method, using default representation

**Why this changed:** Prevents silent bugs where adding or removing a format method changes output behavior without any code changes at call sites.

**Migration strategy:** Use `zig build -freference-trace` to find all format string issues. The compiler will show exact locations where format specifiers need updating.

---

## New best practices for Zig 0.15.x I/O

**1. Default to buffering with appropriate sizes**

Use 4096 bytes (one memory page) as the standard buffer size for general I/O. Increase to 8192 or more for high-throughput operations. Use `std.crypto.tls.max_ciphertext_record_len` for TLS operations.

```zig
// Standard pattern
var buffer: [4096]u8 = undefined;
var writer = file.writer(&buffer);
```

**2. Always flush before visibility is needed**

Flush writers before program exit, before reading back from the same resource, and whenever output must be immediately visible.

```zig
try writer.print("Status: {s}\n", .{status});
try writer.flush(); // Make status visible now
```

**3. Use pointers for interfaces, never copy**

Always reference interfaces via pointer to avoid the @fieldParentPtr footgun.

```zig
const writer = &file_writer.interface; // RIGHT
```

**4. Consider global buffers for frequently-used I/O**

For stdout/stderr used throughout a program, making the buffer global avoids repeated stack allocation and simplifies code.

```zig
var stdout_buffer: [8192]u8 = undefined;

pub fn main() !void {
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;
    // Use stdout throughout program
}
```

**5. Handle all error cases from new Reader methods**

The new delimiter methods return distinct error types that should be handled explicitly.

```zig
while (reader.takeDelimiterExclusive('\n')) |line| {
    // Process line
} else |err| switch (err) {
    error.EndOfStream => {},              // Normal completion
    error.StreamTooLong => return err,    // Line exceeded buffer
    error.ReadFailed => return err,       // I/O failure
}
```

**6. Use Writer.Allocating for unbounded data**

When reading lines that may exceed buffer size, use allocating writer:

```zig
var line_writer = std.Io.Writer.Allocating.init(allocator);
defer line_writer.deinit();

while (reader.streamDelimiter(&line_writer.writer, '\n')) |_| {
    const line = line_writer.written();
    // Process line
    line_writer.clearRetainingCapacity();
    try reader.toss(1); // Skip delimiter
} else |err| if (err != error.EndOfStream) return err;
```

**7. Accept *std.Io.Reader and *std.Io.Writer in public APIs**

Use concrete interface types in function signatures instead of `anytype`:

```zig
pub fn processData(reader: *std.Io.Reader, writer: *std.Io.Writer) !void {
    // No longer forces calling code to be generic
}
```

---

## Common migration patterns

**Pattern: Stdout printing**
```zig
// Allocate buffer once (can be global)
var stdout_buffer: [4096]u8 = undefined;
var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
const stdout = &stdout_writer.interface;

// Use throughout program
try stdout.print("Message: {s}\n", .{message});
try stdout.flush(); // Don't forget!
```

**Pattern: Reading file line by line**
```zig
const file = try std.fs.cwd().openFile("data.txt", .{});
defer file.close();

var buffer: [8192]u8 = undefined;
var file_reader = file.reader(&buffer);
const reader = &file_reader.interface;

while (reader.takeDelimiterExclusive('\n')) |line| {
    // Process each line
} else |err| if (err != error.EndOfStream) return err;
```

**Pattern: Writing to file**
```zig
const file = try std.fs.cwd().createFile("output.txt", .{});
defer file.close();

var buffer: [4096]u8 = undefined;
var file_writer = file.writer(&buffer);
const writer = &file_writer.interface;

try writer.writeAll("Content\n");
try writer.flush(); // Ensure data written
```

**Pattern: Network socket I/O**
```zig
const stream = try std.net.tcpConnectToHost(allocator, "example.com", 80);
defer stream.close();

var read_buf: [4096]u8 = undefined;
var reader = stream.reader(&read_buf);

var write_buf: [4096]u8 = undefined;
var writer = stream.writer(&write_buf);

try writer.interface.writeAll("GET / HTTP/1.0\r\n\r\n");
try writer.interface.flush();

// Read response
while (reader.interface.takeDelimiterExclusive('\n')) |line| {
    // Process response line
} else |err| if (err != error.EndOfStream) return err;
```

---

## What's coming in Zig 0.16.x

The std.io changes in 0.15.x are **foundational for the return of async/await** expected in 0.16.x or later releases. The roadmap includes:

**Complete std.Io interface:** All blocking operations (file system, networking, timers, synchronization) will require an `Io` instance, similar to how memory allocation requires an `Allocator` instance.

**Event loops as first-class citizens:** The new I/O abstraction enables different concurrency models (async/await, thread pools, blocking I/O) to work with the same library code.

**Better testing and reliability:** I/O as an interface parameter enables mocking, instrumentation, and resource leak detection.

**Quote from Andrew Kelley:** "All code that performs I/O will need access to an Io instance, similar to how all code that allocates memory needs access to an Allocator instance."

The 0.15.x changes, while painful, establish the architecture necessary for Zig to support modern async I/O patterns without language-level async keywords. This is a deliberate choice to keep async in the standard library rather than making it a language feature.

---

## Documentation resources for Tero Edge

**Official sources:**
- Zig 0.15.1 Release Notes: https://ziglang.org/download/0.15.1/release-notes.html
- Standard Library Documentation: https://ziglang.org/documentation/0.15.2/std/
- Andrew Kelley's "Don't Forget To Flush" talk (Systems Distributed 2025)

**Community resources:**
- "migrating to zig 0.15: the roadblocks nobody warned you about" (sngeth.com)
- "Zig 0.15.1 I/O Overhaul" (dev.to/bkataru)
- "I'm too dumb for Zig's new IO interface" (openmymind.net) - honest account of migration difficulties
- "Inside Zig's New Writer" (joegm.github.io) - technical deep dive
- Ziggit.dev forum discussions on migration challenges

**GitHub:**
- Writergate PR #24329 with full technical rationale
- Active issue tracker for bugs and edge cases

---

## Migration checklist for Tero Edge

For updating your claude.md documentation to prevent outdated patterns:

- [ ] Document that all readers/writers require explicit buffer allocation
- [ ] Emphasize the mandatory flush requirement (most common bug)
- [ ] Warn about @fieldParentPtr footgun (never copy interfaces)
- [ ] Update all code examples from 0.14.x patterns to 0.15.x patterns
- [ ] Replace `std.io.GenericReader/Writer` with `std.Io.Reader/Writer`
- [ ] Replace `readUntilDelimiterOrEof()` with `takeDelimiterExclusive()`
- [ ] Document that std.io.SeekableStream is removed
- [ ] Update HTTP client/server examples with new multi-buffer patterns
- [ ] Note TLS client requires four buffers minimum
- [ ] Document format string changes ({} → {f} or {any})
- [ ] Add examples showing proper error handling for StreamTooLong
- [ ] Include buffer sizing guidelines (4096 minimum, TLS requires max_ciphertext_record_len)
- [ ] Show Writer.Allocating pattern for unbounded data
- [ ] Emphasize that compression functionality was temporarily removed

This comprehensive reference should enable AI models to provide accurate, current guidance for Zig 0.15.x I/O operations in the Tero Edge project.
