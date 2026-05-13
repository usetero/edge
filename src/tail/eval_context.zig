const std = @import("std");
const policy = @import("policy_zig");

const FieldRef = policy.FieldRef;
const LogAccessor = policy.LogAccessor;

pub const TailAttr = struct {
    key: []const u8,
    value: []const u8,
};

pub const TailLineContext = struct {
    allocator: std.mem.Allocator,
    message: ?[]const u8 = null,
    severity: ?[]const u8 = null,
    attrs: std.ArrayListUnmanaged(TailAttr) = .{},

    pub fn logValue(ctx_ptr: *const anyopaque, field: FieldRef) ?[]const u8 {
        const self: *const TailLineContext = @ptrCast(@alignCast(ctx_ptr));
        return switch (field) {
            .log_field => |lf| switch (lf) {
                .LOG_FIELD_BODY => self.message,
                .LOG_FIELD_SEVERITY_TEXT => self.severity,
                else => null,
            },
            .log_attribute => |attr_path| {
                if (attr_path.path.items.len == 0) return null;
                const key = attr_path.path.items[0];
                return self.getAttr(key);
            },
            .resource_attribute, .scope_attribute => null,
        };
    }

    pub fn logSet(ctx_ptr: *anyopaque, field: FieldRef, value: []const u8) void {
        const self: *TailLineContext = @ptrCast(@alignCast(ctx_ptr));
        switch (field) {
            .log_field => |lf| switch (lf) {
                .LOG_FIELD_BODY => self.message = value,
                .LOG_FIELD_SEVERITY_TEXT => self.severity = value,
                else => {},
            },
            .log_attribute => |attr_path| {
                if (attr_path.path.items.len == 0) return;
                _ = self.putAttr(attr_path.path.items[0], value);
            },
            .resource_attribute, .scope_attribute => {},
        }
    }

    pub fn logDelete(ctx_ptr: *anyopaque, field: FieldRef) bool {
        const self: *TailLineContext = @ptrCast(@alignCast(ctx_ptr));
        return switch (field) {
            .log_field => |lf| switch (lf) {
                .LOG_FIELD_BODY => blk: {
                    const existed = self.message != null;
                    self.message = null;
                    break :blk existed;
                },
                .LOG_FIELD_SEVERITY_TEXT => blk: {
                    const existed = self.severity != null;
                    self.severity = null;
                    break :blk existed;
                },
                else => false,
            },
            .log_attribute => |attr_path| blk: {
                if (attr_path.path.items.len == 0) break :blk false;
                break :blk self.removeAttr(attr_path.path.items[0]);
            },
            .resource_attribute, .scope_attribute => false,
        };
    }

    pub fn logMove(ctx_ptr: *anyopaque, from: FieldRef, to: []const u8) void {
        const self: *TailLineContext = @ptrCast(@alignCast(ctx_ptr));
        const value = TailLineContext.logValue(self, from) orelse return;
        if (!self.putAttr(to, value)) return;
        _ = TailLineContext.logDelete(self, from);
    }

    fn getAttr(self: *const TailLineContext, key: []const u8) ?[]const u8 {
        for (self.attrs.items) |attr| {
            if (std.mem.eql(u8, attr.key, key)) return attr.value;
        }
        return null;
    }

    fn getAttrIndex(self: *const TailLineContext, key: []const u8) ?usize {
        for (self.attrs.items, 0..) |attr, i| {
            if (std.mem.eql(u8, attr.key, key)) return i;
        }
        return null;
    }

    fn putAttr(self: *TailLineContext, key: []const u8, value: []const u8) bool {
        if (self.getAttrIndex(key)) |idx| {
            self.attrs.items[idx].value = value;
            return true;
        }
        self.attrs.append(self.allocator, .{ .key = key, .value = value }) catch return false;
        return true;
    }

    fn removeAttr(self: *TailLineContext, key: []const u8) bool {
        if (self.getAttrIndex(key)) |idx| {
            _ = self.attrs.swapRemove(idx);
            return true;
        }
        return false;
    }
};

/// LogAccessor template for the tail evaluator. Wires all primitives —
/// the tail registry is dedicated to TailLineContext only, so no runtime
/// dispatch is needed.
pub const log_accessor: LogAccessor = .{
    .value = TailLineContext.logValue,
    .set = TailLineContext.logSet,
    .delete = TailLineContext.logDelete,
    .move = TailLineContext.logMove,
};
