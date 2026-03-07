const std = @import("std");
const policy = @import("policy_zig");

const FieldRef = policy.FieldRef;
const MutateOp = policy.MutateOp;

pub const TailAttr = struct {
    key: []const u8,
    value: []const u8,
};

pub const TailLineContext = struct {
    allocator: std.mem.Allocator,
    message: ?[]const u8 = null,
    severity: ?[]const u8 = null,
    attrs: std.ArrayListUnmanaged(TailAttr) = .{},

    pub fn fieldAccessor(ctx_ptr: *const anyopaque, field: FieldRef) ?[]const u8 {
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

    pub fn fieldMutator(ctx_ptr: *anyopaque, op: MutateOp) bool {
        const self: *TailLineContext = @ptrCast(@alignCast(ctx_ptr));
        return switch (op) {
            .remove => |field| self.removeField(field),
            .set => |set| self.setField(set.field, set.value, set.upsert),
            .rename => |rename| self.renameField(rename.from, rename.to, rename.upsert),
        };
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

    fn removeField(self: *TailLineContext, field: FieldRef) bool {
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

    fn setField(self: *TailLineContext, field: FieldRef, value: []const u8, upsert: bool) bool {
        return switch (field) {
            .log_field => |lf| switch (lf) {
                .LOG_FIELD_BODY => blk: {
                    if (!upsert and self.message == null) break :blk false;
                    self.message = value;
                    break :blk true;
                },
                .LOG_FIELD_SEVERITY_TEXT => blk: {
                    if (!upsert and self.severity == null) break :blk false;
                    self.severity = value;
                    break :blk true;
                },
                else => false,
            },
            .log_attribute => |attr_path| blk: {
                if (attr_path.path.items.len == 0) break :blk false;
                const key = attr_path.path.items[0];
                if (!upsert and self.getAttr(key) == null) break :blk false;
                break :blk self.putAttr(key, value);
            },
            .resource_attribute, .scope_attribute => false,
        };
    }

    fn renameField(self: *TailLineContext, from: FieldRef, to_key: []const u8, upsert: bool) bool {
        const value = TailLineContext.fieldAccessor(self, from) orelse return false;
        if (!upsert and self.getAttr(to_key) != null) return false;
        if (!self.putAttr(to_key, value)) return false;
        return self.removeField(from);
    }
};
