const std = @import("std");
const policy_pb = @import("proto");
const policy_source = @import("./policy_source.zig");

const Policy = policy_pb.Policy;
const SourceType = policy_source.SourceType;

/// Update notification sent by providers to subscribers
pub const PolicyUpdate = struct {
    policies: []const Policy,
    source: SourceType,
};

/// Callback signature for policy updates
/// Context is provider-specific state, onUpdate is called when policies change
pub const PolicyCallback = struct {
    context: *anyopaque,
    onUpdate: *const fn (context: *anyopaque, update: PolicyUpdate) anyerror!void,

    pub fn call(self: PolicyCallback, update: PolicyUpdate) !void {
        try self.onUpdate(self.context, update);
    }
};

/// PolicyProvider interface - implemented by file, http, and future providers
/// Uses vtable pattern for polymorphism without heap allocation
pub const PolicyProvider = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        subscribe: *const fn (ptr: *anyopaque, callback: PolicyCallback) anyerror!void,
        deinit: *const fn (ptr: *anyopaque) void,
    };

    /// Subscribe to policy updates from this provider
    /// Provider will call callback immediately with current policies,
    /// then on each subsequent update
    pub fn subscribe(self: PolicyProvider, callback: PolicyCallback) !void {
        try self.vtable.subscribe(self.ptr, callback);
    }

    /// Cleanup provider resources
    pub fn deinit(self: PolicyProvider) void {
        self.vtable.deinit(self.ptr);
    }

    /// Create a PolicyProvider from a concrete provider implementation
    /// Provider must implement: subscribe(*Self, PolicyCallback) !void and deinit(*Self) void
    pub fn init(provider: anytype) PolicyProvider {
        const Ptr = @TypeOf(provider);
        const ptr_info = @typeInfo(Ptr);

        if (ptr_info != .Pointer) @compileError("provider must be a pointer");
        if (ptr_info.Pointer.size != .One) @compileError("provider must be single-item pointer");

        const T = ptr_info.Pointer.child;

        // Verify provider has required methods
        if (!@hasDecl(T, "subscribe")) @compileError("provider must have subscribe method");
        if (!@hasDecl(T, "deinit")) @compileError("provider must have deinit method");

        const gen = struct {
            fn subscribeImpl(ptr: *anyopaque, callback: PolicyCallback) anyerror!void {
                const self: Ptr = @ptrCast(@alignCast(ptr));
                return self.subscribe(callback);
            }

            fn deinitImpl(ptr: *anyopaque) void {
                const self: Ptr = @ptrCast(@alignCast(ptr));
                self.deinit();
            }

            const vtable = VTable{
                .subscribe = subscribeImpl,
                .deinit = deinitImpl,
            };
        };

        return .{
            .ptr = provider,
            .vtable = &gen.vtable,
        };
    }
};
