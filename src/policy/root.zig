//! Policy management package for Tero Edge
//!
//! This package provides policy loading, management, and evaluation capabilities.
//! Policies can be loaded from multiple sources (file, HTTP) with priority-based
//! conflict resolution.
//!
//! ## Usage
//!
//! ```zig
//! const policy = @import("policy");
//!
//! // Create a registry
//! var registry = policy.Registry.init(allocator, bus);
//! defer registry.deinit();
//!
//! // Create and register a file provider
//! const file_provider = try policy.FileProvider.init(allocator, bus, "local", "policies.json");
//! defer file_provider.deinit();
//!
//! const provider_interface = policy.Provider.init(file_provider);
//! try registry.registerProvider(&provider_interface);
//! ```

const std = @import("std");

// =============================================================================
// Core Types
// =============================================================================

/// Re-export source types
pub const source = @import("./source.zig");
pub const SourceType = source.SourceType;
pub const PolicyMetadata = source.PolicyMetadata;

/// Re-export provider interface
pub const provider = @import("./provider.zig");
pub const Provider = provider.PolicyProvider;
pub const PolicyCallback = provider.PolicyCallback;
pub const PolicyUpdate = provider.PolicyUpdate;

/// Re-export registry
pub const registry = @import("./registry.zig");
pub const Registry = registry.PolicyRegistry;
pub const Snapshot = registry.PolicySnapshot;
pub const ConfigType = registry.PolicyConfigType;
pub const TestPolicyProvider = registry.TestPolicyProvider;

// =============================================================================
// Provider Implementations
// =============================================================================

/// File-based policy provider
pub const FileProvider = @import("./provider_file.zig").FileProvider;

/// HTTP-based policy provider
pub const HttpProvider = @import("./provider_http.zig").HttpProvider;

// =============================================================================
// Configuration Types
// =============================================================================

pub const types = @import("./types.zig");
pub const ServiceMetadata = types.ServiceMetadata;
pub const ProviderType = types.ProviderType;
pub const ProviderConfig = types.ProviderConfig;
pub const Header = types.Header;

// =============================================================================
// Parsing
// =============================================================================

pub const parser = @import("./parser.zig");

// =============================================================================
// Tests
// =============================================================================

test {
    // Run all tests in submodules
    std.testing.refAllDecls(@This());
}
