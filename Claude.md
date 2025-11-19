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
