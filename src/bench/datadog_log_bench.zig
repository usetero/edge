//! Matrix benchmark for the per-record Datadog log eval path.
//!
//! Go-table style: every record SHAPE (a parse code path in
//! signals/datadog/log.zig) is crossed with every POLICY (an engine code path
//! in policy_zig), and each combination is benchmarked over
//! `logs.evalLogRecord` — the exact function the production RecordSink runs —
//! with the same parser/arena reuse the httpz frontend has.
//!
//! One benchmark op = `records_per_iter` records, so ns/record = result / 100.
//!
//! Usage (always -Doptimize=ReleaseFast; Debug numbers are ~40x off):
//!   zig build datadog-log-bench -Doptimize=ReleaseFast          full matrix
//!   ./zig-out/bin/datadog-log-bench --list          print case names
//!   ./zig-out/bin/datadog-log-bench --mem           per-record arena high-water
//!   ./zig-out/bin/datadog-log-bench --profile <case> [seconds]
//!       tight-loop one case (default 15s) for attaching a CPU profiler:
//!       xcrun xctrace record --template 'CPU Profiler' --attach <pid>
const std = @import("std");
const zbench = @import("zbench");
const edge = @import("edge");
const proto = @import("proto");
const o11y = @import("o11y");

const logs = edge.signals_datadog_logs;
const PolicyRegistry = edge.policy.Registry;
const EventBus = o11y.EventBus;
const NoopEventBus = o11y.NoopEventBus;

/// A real production log whose `message` is a stringified JSON document
/// (GCP/Cloud Run -> Datadog forwarder shape); its unwrapped body is
/// "evidence skipped".
const wrapped_log = @embedFile("datadog_wrapped_log");

const records_per_iter = 100;

// ============================== Shapes ==============================
// Each shape targets a distinct path in DatadogLog.parse. Templates take one
// {d} so every record in a batch is distinct. All messages contain "request"
// (and the wrapped fixture's body contains "evidence") so body-matching
// policies hit every shape.

const Shape = struct {
    name: []const u8,
    /// Record template with exactly one {d}; null = repeat `wrapped_log`.
    template: ?[]const u8,
};

const shapes = [_]Shape{
    // Known fields only: the eager asString walk, no extras.
    .{
        .name = "plain",
        .template =
        // ziglint-ignore: Z024 (one record = one template line)
        \\{"message":"Log entry {d}: user authentication request completed with MFA verification","service":"auth-service","hostname":"web-01.us-east-1.prod.example.com","ddsource":"nodejs","ddtags":"env:prod,version:1.2.3,team:platform","status":"info","timestamp":1733946000000}
    },
    // Escape-heavy strings: forces the unescape slow path in writeString.
    .{
        .name = "escapes",
        .template =
        // ziglint-ignore: Z024 (one record = one template line)
        \\{"message":"Log \"entry\" {d}:\n\trequest with\ttabs, a \\ backslash, and é accents in the payload body","service":"auth-service","hostname":"web-01.us-east-1.prod.example.com","ddsource":"nodejs","ddtags":"env:prod,version:1.2.3","status":"info","timestamp":1733946000000}
    },
    // Unknown scalar fields: extra-map path (key dupe + asAny scalars).
    .{
        .name = "scalar_extras",
        .template =
        // ziglint-ignore: Z024 (one record = one template line)
        \\{"message":"Log entry {d}: user authentication request completed with MFA verification","service":"auth-service","hostname":"web-01.us-east-1.prod.example.com","ddsource":"nodejs","ddtags":"env:prod,version:1.2.3","status":"info","timestamp":1733946000000,"trace_id":"abc123-def456","span_id":"span-00fe12","request_id":"req-000000012345","usr.id":"user-42","duration_ms":137,"success":true}
    },
    // Nested containers: asAny + stringifyAnyValue + extra_raw_json path.
    .{
        .name = "nested_extras",
        .template =
        // ziglint-ignore: Z024 (one record = one template line)
        \\{"message":"Log entry {d}: user authentication request completed with MFA verification","service":"auth-service","hostname":"web-01.us-east-1.prod.example.com","ddsource":"nodejs","ddtags":"env:prod,version:1.2.3","status":"info","timestamp":1733946000000,"trace_id":"abc123-def456","http":{"method":"POST","status_code":200,"url":"/api/v1/orders/9137","useragent":"Mozilla/5.0 (compatible; svc/1.2)"},"error":{"kind":"","stack":""},"tags":["region:us-east-1","tier:web","shard:7"]}
    },
    // JSON-wrapped message: ensureUnwrapped / flattenValue / bodyForMatch DFS.
    .{ .name = "wrapped", .template = null },
};

// ============================== Policies ==============================
// Each policy targets a distinct engine/accessor path. `build` returns the
// policies to load; an empty slice means an empty registry (engine early-out).

const PolicySpec = struct {
    name: []const u8,
    build: *const fn (std.mem.Allocator) anyerror![]proto.policy.Policy,
};

fn noPolicies(_: std.mem.Allocator) anyerror![]proto.policy.Policy {
    return &.{};
}

/// Severity regex that never matches ("info" records): the scan-and-keep hot
/// path — hyperscan runs, nothing matches, no serialization.
fn sevMiss(gpa: std.mem.Allocator) anyerror![]proto.policy.Policy {
    var p: proto.policy.Policy = .{
        .id = try gpa.dupe(u8, "sev-miss"),
        .name = try gpa.dupe(u8, "sev-miss"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try gpa.dupe(u8, "none") } },
    };
    try p.target.?.log.match.append(gpa, .{
        .field = .{ .log_field = .LOG_FIELD_SEVERITY_TEXT },
        .match = .{ .regex = try gpa.dupe(u8, "TRACE") },
    });
    return onePolicy(gpa, p);
}

/// Body regex hitting every shape: the drop path.
fn bodyDrop(gpa: std.mem.Allocator) anyerror![]proto.policy.Policy {
    var p: proto.policy.Policy = .{
        .id = try gpa.dupe(u8, "body-drop"),
        .name = try gpa.dupe(u8, "body-drop"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try gpa.dupe(u8, "none") } },
    };
    try p.target.?.log.match.append(gpa, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try gpa.dupe(u8, "(request|evidence)") },
    });
    return onePolicy(gpa, p);
}

/// Exact match on an unknown field: extra-map lookup (findExtraString). Hits
/// scalar_extras/nested_extras, field-absent path everywhere else.
fn attrExact(gpa: std.mem.Allocator) anyerror![]proto.policy.Policy {
    var path: proto.policy.AttributePath = .{};
    try path.path.append(gpa, try gpa.dupe(u8, "trace_id"));
    var p: proto.policy.Policy = .{
        .id = try gpa.dupe(u8, "attr-exact"),
        .name = try gpa.dupe(u8, "attr-exact"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try gpa.dupe(u8, "none") } },
    };
    try p.target.?.log.match.append(gpa, .{
        .field = .{ .log_attribute = path },
        .match = .{ .exact = try gpa.dupe(u8, "abc123-def456") },
    });
    return onePolicy(gpa, p);
}

/// keep=all + redact a top-level field on every record: the mutate ->
/// re-serialize (replace verdict) path.
fn redactService(gpa: std.mem.Allocator) anyerror![]proto.policy.Policy {
    var transform: proto.policy.LogTransform = .{};
    var svc_path: proto.policy.AttributePath = .{};
    try svc_path.path.append(gpa, try gpa.dupe(u8, "service"));
    try transform.redact.append(gpa, .{
        .field = .{ .log_attribute = svc_path },
        .replacement = try gpa.dupe(u8, "REDACTED"),
    });
    var p: proto.policy.Policy = .{
        .id = try gpa.dupe(u8, "redact-service"),
        .name = try gpa.dupe(u8, "redact-service"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try gpa.dupe(u8, "all"), .transform = transform } },
    };
    try p.target.?.log.match.append(gpa, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try gpa.dupe(u8, "(request|evidence)") },
    });
    return onePolicy(gpa, p);
}

/// The production EvidenceSkipped policy: body exact AND nested attribute
/// exact — both only fire after the wrapped message is unwrapped. Only the
/// wrapped shape matches; every other shape pays the miss.
fn wrappedDrop(gpa: std.mem.Allocator) anyerror![]proto.policy.Policy {
    var p: proto.policy.Policy = .{
        .id = try gpa.dupe(u8, "evidence-skipped"),
        .name = try gpa.dupe(u8, "evidence-skipped"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try gpa.dupe(u8, "none") } },
    };
    try p.target.?.log.match.append(gpa, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .exact = try gpa.dupe(u8, "evidence skipped") },
    });
    var event_type_path: proto.policy.AttributePath = .{};
    try event_type_path.path.append(gpa, try gpa.dupe(u8, "data"));
    try event_type_path.path.append(gpa, try gpa.dupe(u8, "jsonPayload"));
    try event_type_path.path.append(gpa, try gpa.dupe(u8, "event_type"));
    try p.target.?.log.match.append(gpa, .{
        .field = .{ .log_attribute = event_type_path },
        .match = .{ .exact = try gpa.dupe(u8, "EvidenceSkipped") },
    });
    return onePolicy(gpa, p);
}

/// keep=all + edits *inside* the wrapped message: parse -> mutate ->
/// re-serialize (re-wrap) via the std.json message_tree. Only wrapped matches.
fn wrappedRewrite(gpa: std.mem.Allocator) anyerror![]proto.policy.Policy {
    var transform: proto.policy.LogTransform = .{};
    var remove_path: proto.policy.AttributePath = .{};
    try remove_path.path.append(gpa, try gpa.dupe(u8, "data"));
    try remove_path.path.append(gpa, try gpa.dupe(u8, "jsonPayload"));
    try remove_path.path.append(gpa, try gpa.dupe(u8, "event_type"));
    try transform.remove.append(gpa, .{ .field = .{ .log_attribute = remove_path } });

    var redact_path: proto.policy.AttributePath = .{};
    try redact_path.path.append(gpa, try gpa.dupe(u8, "data"));
    try redact_path.path.append(gpa, try gpa.dupe(u8, "jsonPayload"));
    try redact_path.path.append(gpa, try gpa.dupe(u8, "account_name"));
    try transform.redact.append(gpa, .{
        .field = .{ .log_attribute = redact_path },
        .replacement = try gpa.dupe(u8, "REDACTED"),
    });

    var p: proto.policy.Policy = .{
        .id = try gpa.dupe(u8, "rewrite-wrapped"),
        .name = try gpa.dupe(u8, "rewrite-wrapped"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try gpa.dupe(u8, "all"), .transform = transform } },
    };
    try p.target.?.log.match.append(gpa, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .exact = try gpa.dupe(u8, "evidence skipped") },
    });
    return onePolicy(gpa, p);
}

fn onePolicy(gpa: std.mem.Allocator, p: proto.policy.Policy) ![]proto.policy.Policy {
    const list = try gpa.alloc(proto.policy.Policy, 1);
    list[0] = p;
    return list;
}

const policies = [_]PolicySpec{
    .{ .name = "none", .build = noPolicies },
    .{ .name = "sev_miss", .build = sevMiss },
    .{ .name = "body_drop", .build = bodyDrop },
    .{ .name = "attr_exact", .build = attrExact },
    .{ .name = "redact", .build = redactService },
    .{ .name = "wrapped_drop", .build = wrappedDrop },
    .{ .name = "wrapped_rewrite", .build = wrappedRewrite },
};

// ============================== Harness ==============================

// Parser + record arena are process-lived and reused across every record and
// case, exactly like the httpz frontend's per-thread RecordScratch.
var g_bus: *EventBus = undefined;
var g_gpa: std.mem.Allocator = undefined;
var g_parser: logs.Parser = .init;
var g_arena: std.heap.ArenaAllocator = undefined;

const Case = struct {
    name: []const u8,
    registry: *PolicyRegistry,
    records: []const []const u8,

    pub fn run(self: *Case, _: std.mem.Allocator) void {
        for (self.records) |record| {
            const verdict = evalOne(self.registry, record);
            std.mem.doNotOptimizeAway(&verdict);
        }
    }
};

fn evalOne(registry: *PolicyRegistry, record: []const u8) std.meta.Tag(logs.RecordVerdict) {
    _ = g_arena.reset(.retain_capacity);
    const verdict = logs.evalLogRecord(
        g_arena.allocator(),
        &g_parser,
        g_gpa,
        registry,
        g_bus,
        record,
    ) catch |err| std.debug.panic("evalLogRecord failed: {t}", .{err});
    return std.meta.activeTag(verdict);
}

fn buildRecords(gpa: std.mem.Allocator, shape: Shape) ![]const []const u8 {
    const records = try gpa.alloc([]const u8, records_per_iter);
    for (records, 0..) |*slot, i| {
        slot.* = if (shape.template) |template|
            try renderTemplate(gpa, template, i)
        else
            std.mem.trim(u8, wrapped_log, " \t\r\n");
    }
    return records;
}

/// std.fmt needs a comptime format string; templates arrive here through a
/// runtime Shape, so substitute the single {d} by hand.
fn renderTemplate(gpa: std.mem.Allocator, template: []const u8, i: usize) ![]const u8 {
    const marker = std.mem.indexOf(u8, template, "{d}") orelse unreachable;
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    try out.writer.writeAll(template[0..marker]);
    try out.writer.print("{d}", .{i});
    try out.writer.writeAll(template[marker + 3 ..]);
    return out.toOwnedSlice();
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const arena = init.arena.allocator();
    g_gpa = gpa;
    g_arena = .init(gpa);
    defer g_arena.deinit();
    defer g_parser.deinit(gpa);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(init.io);
    g_bus = noop_bus.eventBus();

    const args = try init.minimal.args.toSlice(arena);

    // One registry per policy spec, shared by every shape.
    var registries: [policies.len]*PolicyRegistry = undefined;
    for (&registries, policies) |*slot, spec| {
        const registry = try arena.create(PolicyRegistry);
        registry.* = PolicyRegistry.init(gpa, g_bus);
        const list = try spec.build(arena);
        if (list.len > 0) try registry.updatePolicies(list, "bench", .file);
        slot.* = registry;
    }
    defer for (registries) |registry| registry.deinit();

    // The full shape x policy matrix.
    var cases: [shapes.len * policies.len]Case = undefined;
    for (shapes, 0..) |shape, si| {
        const records = try buildRecords(arena, shape);
        for (policies, 0..) |spec, pi| {
            cases[si * policies.len + pi] = .{
                .name = try std.fmt.allocPrint(arena, "{s}/{s}", .{ shape.name, spec.name }),
                .registry = registries[pi],
                .records = records,
            };
        }
    }

    // Sanity-check the combinations that define the matrix's meaning, so a
    // regex typo can't silently turn a case into a different code path.
    try expectVerdict(&cases, "plain/none", .keep);
    try expectVerdict(&cases, "plain/sev_miss", .keep);
    try expectVerdict(&cases, "plain/body_drop", .drop);
    try expectVerdict(&cases, "plain/attr_exact", .keep);
    try expectVerdict(&cases, "scalar_extras/attr_exact", .drop);
    try expectVerdict(&cases, "nested_extras/attr_exact", .drop);
    try expectVerdict(&cases, "plain/redact", .replace);
    try expectVerdict(&cases, "plain/wrapped_drop", .keep);
    try expectVerdict(&cases, "wrapped/wrapped_drop", .drop);
    try expectVerdict(&cases, "wrapped/wrapped_rewrite", .replace);

    if (args.len > 1 and std.mem.eql(u8, args[1], "--list")) {
        for (cases) |case| std.debug.print("{s}\n", .{case.name});
        return;
    }

    // Per-record scratch memory. zbench's track_allocations can't see this:
    // the harness allocates from the retained global arena on purpose
    // (mirroring production RecordScratch reuse), so malloc-level tracking
    // reads 0B — steady state really is allocation-free. What varies per
    // shape is how much arena scratch one record burns; report the arena's
    // high-water capacity after a batch from a cold arena.
    if (args.len > 1 and std.mem.eql(u8, args[1], "--mem")) {
        std.debug.print(
            "{s:<32} arena high-water bytes (worst record of {d})\n",
            .{ "case", records_per_iter },
        );
        for (&cases) |*case| {
            // Fresh arena per case so retained capacity = this case's peak.
            g_arena.deinit();
            g_arena = .init(g_gpa);
            for (case.records) |record| _ = evalOne(case.registry, record);
            std.debug.print("{s:<32} {d}\n", .{ case.name, g_arena.queryCapacity() });
        }
        return;
    }

    if (args.len > 2 and std.mem.eql(u8, args[1], "--profile")) {
        const case = findCase(&cases, args[2]) orelse {
            std.debug.print("unknown case '{s}' (use --list)\n", .{args[2]});
            return error.UnknownCase;
        };
        const seconds = if (args.len > 3) try std.fmt.parseInt(u64, args[3], 10) else 15;
        const pid = std.c.getpid();
        std.debug.print(
            "profiling '{s}' for {d}s, pid {d}\n  xcrun xctrace record --template 'CPU Profiler' --attach {d}\n",
            .{ case.name, seconds, pid, pid },
        );
        const deadline = std.Io.Timestamp.now(init.io, .awake).toNanoseconds() +
            seconds * std.time.ns_per_s;
        var iters: u64 = 0;
        // Io.Threaded's Timestamp.now costs ~1-9us on macOS; checking it per
        // iteration polluted profiles by several percent. Check every 32.
        while (true) : (iters += 32) {
            for (0..32) |_| case.run(gpa);
            if (std.Io.Timestamp.now(init.io, .awake).toNanoseconds() >= deadline) break;
        }
        std.debug.print("{d} iterations x {d} records\n", .{ iters, records_per_iter });
        return;
    }

    // track_allocations stays off: the harness allocates via the global
    // arena/parser (production reuse), so zbench's tracked allocator always
    // reads 0B. Use --mem for the per-record scratch numbers instead.
    var bench = zbench.Benchmark.init(gpa, .{
        // One op = 100 records. 1.5s x 35 cases ~= 1 minute per full run;
        // long enough for stable p99s without making iteration painful.
        .time_budget_ns = 1500 * std.time.ns_per_ms,
    });
    defer bench.deinit();

    for (&cases) |*case| {
        try bench.addParam(case.name, @as(*const Case, case), .{});
    }

    const stdout: std.Io.File = .stdout();
    try bench.run(init.io, stdout);
}

fn findCase(cases: []Case, name: []const u8) ?*Case {
    for (cases) |*case| {
        if (std.mem.eql(u8, case.name, name)) return case;
    }
    return null;
}

fn expectVerdict(
    cases: []Case,
    name: []const u8,
    expected: std.meta.Tag(logs.RecordVerdict),
) !void {
    const case = findCase(cases, name) orelse return error.UnknownCase;
    const got = evalOne(case.registry, case.records[0]);
    if (got != expected) {
        std.debug.print("case '{s}': expected {t}, got {t}\n", .{ name, expected, got });
        return error.WrongVerdict;
    }
}
