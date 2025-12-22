const std = @import("std");
const proto = @import("proto");

const Policy = proto.policy.Policy;

/// Update notification sent by providers to subscribers
pub const PolicyUpdate = struct {
    policies: []const Policy,
    /// ID of the provider that sent this update
    provider_id: []const u8,
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
        getId: *const fn (ptr: *anyopaque) []const u8,
        subscribe: *const fn (ptr: *anyopaque, callback: PolicyCallback) anyerror!void,
        recordPolicyError: *const fn (ptr: *anyopaque, policy_id: []const u8, error_message: []const u8) void,
        recordPolicyStats: *const fn (ptr: *anyopaque, policy_id: []const u8, hits: i64, misses: i64, bytes_before: i64, bytes_after: i64) void,
        deinit: *const fn (ptr: *anyopaque) void,
    };

    /// Get the unique identifier for this provider
    pub fn getId(self: PolicyProvider) []const u8 {
        return self.vtable.getId(self.ptr);
    }

    /// Subscribe to policy updates from this provider
    /// Provider will call callback immediately with current policies,
    /// then on each subsequent update
    pub fn subscribe(self: PolicyProvider, callback: PolicyCallback) !void {
        try self.vtable.subscribe(self.ptr, callback);
    }

    /// Report an error encountered when applying a policy.
    /// How this is handled depends on the provider:
    /// - HttpProvider: Records error to send in next sync request
    /// - FileProvider: Logs error to stderr
    pub fn recordPolicyError(self: PolicyProvider, policy_id: []const u8, error_message: []const u8) void {
        self.vtable.recordPolicyError(self.ptr, policy_id, error_message);
    }

    /// Report statistics about policy hits, misses, and byte changes.
    /// How this is handled depends on the provider:
    /// - HttpProvider: Records stats to send in next sync request
    /// - FileProvider: Logs stats to stdout
    pub fn recordPolicyStats(self: PolicyProvider, policy_id: []const u8, hits: i64, misses: i64, bytes_before: i64, bytes_after: i64) void {
        self.vtable.recordPolicyStats(self.ptr, policy_id, hits, misses, bytes_before, bytes_after);
    }

    /// Cleanup provider resources
    pub fn deinit(self: PolicyProvider) void {
        self.vtable.deinit(self.ptr);
    }

    /// Create a PolicyProvider from a concrete provider implementation
    /// Provider must implement:
    /// - getId(*Self) []const u8
    /// - subscribe(*Self, PolicyCallback) !void
    /// - recordPolicyError(*Self, []const u8, []const u8) void
    /// - recordPolicyStats(*Self, []const u8, i64, i64, i64, i64) void
    /// - deinit(*Self) void
    pub fn init(provider: anytype) PolicyProvider {
        const Ptr = @TypeOf(provider);
        const ptr_info = @typeInfo(Ptr);

        if (ptr_info != .pointer) @compileError("provider must be a pointer");
        if (ptr_info.pointer.size != .one) @compileError("provider must be single-item pointer");

        const T = ptr_info.pointer.child;

        // Verify provider has required methods
        if (!@hasDecl(T, "getId")) @compileError("provider must have getId method");
        if (!@hasDecl(T, "subscribe")) @compileError("provider must have subscribe method");
        if (!@hasDecl(T, "recordPolicyError")) @compileError("provider must have recordPolicyError method");
        if (!@hasDecl(T, "recordPolicyStats")) @compileError("provider must have recordPolicyStats method");
        if (!@hasDecl(T, "deinit")) @compileError("provider must have deinit method");

        const gen = struct {
            fn getIdImpl(ptr: *anyopaque) []const u8 {
                const self: Ptr = @ptrCast(@alignCast(ptr));
                return self.getId();
            }

            fn subscribeImpl(ptr: *anyopaque, callback: PolicyCallback) anyerror!void {
                const self: Ptr = @ptrCast(@alignCast(ptr));
                return self.subscribe(callback);
            }

            fn recordPolicyErrorImpl(ptr: *anyopaque, policy_id: []const u8, error_message: []const u8) void {
                const self: Ptr = @ptrCast(@alignCast(ptr));
                self.recordPolicyError(policy_id, error_message);
            }

            fn recordPolicyStatsImpl(ptr: *anyopaque, policy_id: []const u8, hits: i64, misses: i64, bytes_before: i64, bytes_after: i64) void {
                const self: Ptr = @ptrCast(@alignCast(ptr));
                self.recordPolicyStats(policy_id, hits, misses, bytes_before, bytes_after);
            }

            fn deinitImpl(ptr: *anyopaque) void {
                const self: Ptr = @ptrCast(@alignCast(ptr));
                self.deinit();
            }

            const vtable = VTable{
                .getId = getIdImpl,
                .subscribe = subscribeImpl,
                .recordPolicyError = recordPolicyErrorImpl,
                .recordPolicyStats = recordPolicyStatsImpl,
                .deinit = deinitImpl,
            };
        };

        return .{
            .ptr = provider,
            .vtable = &gen.vtable,
        };
    }
};
