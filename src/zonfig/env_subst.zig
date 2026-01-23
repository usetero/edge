const std = @import("std");

/// Environment variable substitution error types
pub const SubstError = error{
    /// Found `${` but no closing `}`
    UnclosedVariable,
    /// Empty variable name `${}`
    EmptyVariableName,
    /// Variable name contains invalid characters
    InvalidVariableName,
    /// Out of memory during substitution
    OutOfMemory,
};

/// Result of environment variable substitution
pub const SubstResult = struct {
    /// The resulting string with substitutions applied
    value: []const u8,
    /// Whether any substitutions were made (if false, value is the original string)
    was_substituted: bool,
};

/// Substitute environment variables in a string.
/// Variables are specified as `${VAR_NAME}`.
///
/// If a variable is not set in the environment, it is replaced with an empty string.
/// Returns the substituted string (allocated) or the original string if no substitutions needed.
///
/// Examples:
///   - `${HOME}/config` -> `/home/user/config`
///   - `prefix_${VAR}_suffix` -> `prefix_value_suffix`
///   - `${UNSET_VAR}` -> `` (empty string)
///   - `no variables here` -> `no variables here` (original, not copied)
///   - `$${ESCAPED}` -> `${ESCAPED}` (double $ escapes)
pub fn substitute(allocator: std.mem.Allocator, input: []const u8) SubstError!SubstResult {
    // Quick scan to see if there are any potential variables
    if (std.mem.indexOf(u8, input, "${") == null) {
        return .{ .value = input, .was_substituted = false };
    }

    var result: std.ArrayListUnmanaged(u8) = .empty;
    errdefer result.deinit(allocator);

    var i: usize = 0;
    while (i < input.len) {
        // Check for escape sequence $${ -> ${
        if (i + 2 < input.len and input[i] == '$' and input[i + 1] == '$' and input[i + 2] == '{') {
            result.append(allocator, '$') catch return error.OutOfMemory;
            result.append(allocator, '{') catch return error.OutOfMemory;
            i += 3;
            continue;
        }

        // Check for variable start
        if (i + 1 < input.len and input[i] == '$' and input[i + 1] == '{') {
            // Find the closing brace
            const var_start = i + 2;
            const closing = std.mem.indexOfScalarPos(u8, input, var_start, '}') orelse {
                return error.UnclosedVariable;
            };

            const var_name = input[var_start..closing];

            // Validate variable name
            if (var_name.len == 0) {
                return error.EmptyVariableName;
            }

            if (!isValidVariableName(var_name)) {
                return error.InvalidVariableName;
            }

            // Get environment variable value
            if (std.posix.getenv(var_name)) |value| {
                result.appendSlice(allocator, value) catch return error.OutOfMemory;
            }
            // If not set, we just skip it (replace with empty string)

            i = closing + 1;
        } else {
            result.append(allocator, input[i]) catch return error.OutOfMemory;
            i += 1;
        }
    }

    return .{
        .value = result.toOwnedSlice(allocator) catch return error.OutOfMemory,
        .was_substituted = true,
    };
}

/// Substitute environment variables, returning a required value.
/// If the variable is not set and no default is provided, returns an error.
pub fn substituteRequired(
    allocator: std.mem.Allocator,
    input: []const u8,
    comptime allow_empty: bool,
) (SubstError || error{MissingRequiredVariable})!SubstResult {
    const result = try substitute(allocator, input);

    if (!allow_empty and result.value.len == 0 and result.was_substituted) {
        if (result.was_substituted) {
            allocator.free(result.value);
        }
        return error.MissingRequiredVariable;
    }

    return result;
}

/// Check if a string contains any environment variable references
pub fn containsVariables(input: []const u8) bool {
    var i: usize = 0;
    while (i < input.len) {
        // Skip escape sequences
        if (i + 2 < input.len and input[i] == '$' and input[i + 1] == '$' and input[i + 2] == '{') {
            i += 3;
            continue;
        }

        if (i + 1 < input.len and input[i] == '$' and input[i + 1] == '{') {
            return true;
        }
        i += 1;
    }
    return false;
}

/// Validate that a variable name is valid.
/// Valid characters: A-Z, a-z, 0-9, _
/// Must not start with a digit.
fn isValidVariableName(name: []const u8) bool {
    if (name.len == 0) return false;

    // First character must not be a digit
    const first = name[0];
    if (first >= '0' and first <= '9') return false;

    for (name) |c| {
        const is_alpha = (c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z');
        const is_digit = c >= '0' and c <= '9';
        const is_underscore = c == '_';

        if (!is_alpha and !is_digit and !is_underscore) {
            return false;
        }
    }

    return true;
}

/// Parse a variable reference and extract the name.
/// Returns null if not a valid variable reference.
pub fn parseVariable(input: []const u8) ?[]const u8 {
    if (input.len < 3) return null;
    if (input[0] != '$' or input[1] != '{') return null;

    const closing = std.mem.indexOfScalar(u8, input[2..], '}') orelse return null;
    const var_name = input[2 .. 2 + closing];

    if (var_name.len == 0 or !isValidVariableName(var_name)) {
        return null;
    }

    return var_name;
}

// ============================================================================
// Tests
// ============================================================================

test "substitute: no variables returns original" {
    const result = try substitute(std.testing.allocator, "no variables here");
    try std.testing.expectEqual(false, result.was_substituted);
    try std.testing.expectEqualStrings("no variables here", result.value);
    // Should not free - original string
}

test "substitute: empty string returns original" {
    const result = try substitute(std.testing.allocator, "");
    try std.testing.expectEqual(false, result.was_substituted);
    try std.testing.expectEqualStrings("", result.value);
}

test "substitute: simple variable" {
    // We can't set env vars in tests easily, but we can test the parsing
    // For actual env var tests, we rely on integration tests or mock

    // Test with a likely-set variable (PATH is almost always set)
    const result = try substitute(std.testing.allocator, "path=${PATH}");
    defer if (result.was_substituted) std.testing.allocator.free(result.value);

    if (std.posix.getenv("PATH")) |path_value| {
        const expected = try std.fmt.allocPrint(std.testing.allocator, "path={s}", .{path_value});
        defer std.testing.allocator.free(expected);
        try std.testing.expectEqualStrings(expected, result.value);
        try std.testing.expectEqual(true, result.was_substituted);
    }
}

test "substitute: unset variable becomes empty" {
    const result = try substitute(std.testing.allocator, "prefix_${DEFINITELY_NOT_SET_VAR_12345}_suffix");
    defer if (result.was_substituted) std.testing.allocator.free(result.value);

    try std.testing.expectEqualStrings("prefix__suffix", result.value);
    try std.testing.expectEqual(true, result.was_substituted);
}

test "substitute: multiple variables" {
    const result = try substitute(std.testing.allocator, "${UNSET1}_${UNSET2}_${UNSET3}");
    defer if (result.was_substituted) std.testing.allocator.free(result.value);

    try std.testing.expectEqualStrings("__", result.value);
    try std.testing.expectEqual(true, result.was_substituted);
}

test "substitute: variable at start" {
    const result = try substitute(std.testing.allocator, "${UNSET_VAR}suffix");
    defer if (result.was_substituted) std.testing.allocator.free(result.value);

    try std.testing.expectEqualStrings("suffix", result.value);
}

test "substitute: variable at end" {
    const result = try substitute(std.testing.allocator, "prefix${UNSET_VAR}");
    defer if (result.was_substituted) std.testing.allocator.free(result.value);

    try std.testing.expectEqualStrings("prefix", result.value);
}

test "substitute: only variable" {
    const result = try substitute(std.testing.allocator, "${UNSET_VAR}");
    defer if (result.was_substituted) std.testing.allocator.free(result.value);

    try std.testing.expectEqualStrings("", result.value);
}

test "substitute: escape sequence" {
    const result = try substitute(std.testing.allocator, "literal $${VAR} here");
    defer if (result.was_substituted) std.testing.allocator.free(result.value);

    try std.testing.expectEqualStrings("literal ${VAR} here", result.value);
    try std.testing.expectEqual(true, result.was_substituted);
}

test "substitute: mixed escape and real variable" {
    const result = try substitute(std.testing.allocator, "$${ESCAPED}_${UNSET}_end");
    defer if (result.was_substituted) std.testing.allocator.free(result.value);

    try std.testing.expectEqualStrings("${ESCAPED}__end", result.value);
}

test "substitute: unclosed variable error" {
    const result = substitute(std.testing.allocator, "prefix${UNCLOSED");
    try std.testing.expectError(error.UnclosedVariable, result);
}

test "substitute: empty variable name error" {
    const result = substitute(std.testing.allocator, "prefix${}_suffix");
    try std.testing.expectError(error.EmptyVariableName, result);
}

test "substitute: invalid variable name - starts with digit" {
    const result = substitute(std.testing.allocator, "${1INVALID}");
    try std.testing.expectError(error.InvalidVariableName, result);
}

test "substitute: invalid variable name - contains special char" {
    const result = substitute(std.testing.allocator, "${VAR-NAME}");
    try std.testing.expectError(error.InvalidVariableName, result);
}

test "substitute: invalid variable name - contains space" {
    const result = substitute(std.testing.allocator, "${VAR NAME}");
    try std.testing.expectError(error.InvalidVariableName, result);
}

test "substitute: valid variable names" {
    // Underscore prefix is valid
    const r1 = try substitute(std.testing.allocator, "${_VAR}");
    defer if (r1.was_substituted) std.testing.allocator.free(r1.value);

    // All caps with underscore
    const r2 = try substitute(std.testing.allocator, "${MY_VAR_123}");
    defer if (r2.was_substituted) std.testing.allocator.free(r2.value);

    // Mixed case
    const r3 = try substitute(std.testing.allocator, "${myVar}");
    defer if (r3.was_substituted) std.testing.allocator.free(r3.value);

    // Single character
    const r4 = try substitute(std.testing.allocator, "${X}");
    defer if (r4.was_substituted) std.testing.allocator.free(r4.value);
}

test "substitute: dollar sign not followed by brace" {
    const result = try substitute(std.testing.allocator, "price is $100");
    try std.testing.expectEqual(false, result.was_substituted);
    try std.testing.expectEqualStrings("price is $100", result.value);
}

test "substitute: adjacent variables" {
    const result = try substitute(std.testing.allocator, "${A}${B}${C}");
    defer if (result.was_substituted) std.testing.allocator.free(result.value);

    try std.testing.expectEqualStrings("", result.value);
}

test "substitute: nested braces not supported" {
    // This should work - inner ${B} is just literal text in var name, which is invalid
    const result = substitute(std.testing.allocator, "${A${B}}");
    try std.testing.expectError(error.InvalidVariableName, result);
}

test "isValidVariableName" {
    try std.testing.expect(isValidVariableName("VAR"));
    try std.testing.expect(isValidVariableName("var"));
    try std.testing.expect(isValidVariableName("Var"));
    try std.testing.expect(isValidVariableName("VAR_NAME"));
    try std.testing.expect(isValidVariableName("_VAR"));
    try std.testing.expect(isValidVariableName("VAR123"));
    try std.testing.expect(isValidVariableName("_"));
    try std.testing.expect(isValidVariableName("a"));

    try std.testing.expect(!isValidVariableName(""));
    try std.testing.expect(!isValidVariableName("123"));
    try std.testing.expect(!isValidVariableName("1VAR"));
    try std.testing.expect(!isValidVariableName("VAR-NAME"));
    try std.testing.expect(!isValidVariableName("VAR NAME"));
    try std.testing.expect(!isValidVariableName("VAR.NAME"));
    try std.testing.expect(!isValidVariableName("VAR$NAME"));
}

test "containsVariables" {
    try std.testing.expect(containsVariables("${VAR}"));
    try std.testing.expect(containsVariables("prefix${VAR}suffix"));
    try std.testing.expect(containsVariables("${A}${B}"));
    try std.testing.expect(containsVariables("text${VAR}"));

    try std.testing.expect(!containsVariables(""));
    try std.testing.expect(!containsVariables("no vars"));
    try std.testing.expect(!containsVariables("$VAR")); // No braces
    try std.testing.expect(!containsVariables("$100")); // Not a var
    try std.testing.expect(!containsVariables("$${ESCAPED}")); // Escaped
}

test "parseVariable" {
    try std.testing.expectEqualStrings("VAR", parseVariable("${VAR}").?);
    try std.testing.expectEqualStrings("MY_VAR", parseVariable("${MY_VAR}suffix").?);
    try std.testing.expectEqualStrings("a", parseVariable("${a}").?);

    try std.testing.expectEqual(@as(?[]const u8, null), parseVariable(""));
    try std.testing.expectEqual(@as(?[]const u8, null), parseVariable("VAR"));
    try std.testing.expectEqual(@as(?[]const u8, null), parseVariable("$VAR"));
    try std.testing.expectEqual(@as(?[]const u8, null), parseVariable("${}")); // Empty name
    try std.testing.expectEqual(@as(?[]const u8, null), parseVariable("${1VAR}")); // Invalid name
}

test "substitute: real environment variable HOME" {
    // HOME is almost always set on Unix systems
    if (std.posix.getenv("HOME")) |home_value| {
        const result = try substitute(std.testing.allocator, "${HOME}/.config");
        defer if (result.was_substituted) std.testing.allocator.free(result.value);

        const expected = try std.fmt.allocPrint(std.testing.allocator, "{s}/.config", .{home_value});
        defer std.testing.allocator.free(expected);

        try std.testing.expectEqualStrings(expected, result.value);
        try std.testing.expectEqual(true, result.was_substituted);
    }
}

test "substitute: preserves surrounding content exactly" {
    const result = try substitute(std.testing.allocator, "Bearer ${UNSET_TOKEN}");
    defer if (result.was_substituted) std.testing.allocator.free(result.value);

    try std.testing.expectEqualStrings("Bearer ", result.value);
}

test "substitute: handles special JSON characters in surrounding text" {
    const result = try substitute(std.testing.allocator, "\"key\": \"${UNSET}\"");
    defer if (result.was_substituted) std.testing.allocator.free(result.value);

    try std.testing.expectEqualStrings("\"key\": \"\"", result.value);
}

test "substitute: long variable name" {
    const long_name = "THIS_IS_A_VERY_LONG_ENVIRONMENT_VARIABLE_NAME_THAT_SHOULD_STILL_WORK";
    const input = try std.fmt.allocPrint(std.testing.allocator, "${{{s}}}", .{long_name});
    defer std.testing.allocator.free(input);

    const result = try substitute(std.testing.allocator, input);
    defer if (result.was_substituted) std.testing.allocator.free(result.value);

    // Should succeed (var is unset, so result is empty)
    try std.testing.expectEqualStrings("", result.value);
}
