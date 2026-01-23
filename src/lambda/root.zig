//! Lambda Extension Module
//!
//! Provides Lambda Extensions API client for running Tero Edge
//! as an AWS Lambda external extension.

pub const extension_api = @import("extension_api.zig");

pub const ExtensionClient = extension_api.ExtensionClient;
pub const EventType = extension_api.EventType;
pub const ExtensionEvent = extension_api.ExtensionEvent;
pub const ShutdownReason = extension_api.ShutdownReason;

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}
