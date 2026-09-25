const std = @import("std");

pub const Frontend = enum { stdio, httpz };

fn keepProfilingSymbols(m: *std.Build.Module) void {
    m.omit_frame_pointer = false;
    m.strip = false;
}

const EdgeExeOptions = struct {
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    imports: []const std.Build.Module.Import,
    build_options: *std.Build.Step.Options,
    profiling: bool,
};

/// Adds one edge executable with the shared imports, build options, and libc + zstd.
fn addEdgeExe(b: *std.Build, name: []const u8, source: []const u8, options: EdgeExeOptions) *std.Build.Step.Compile {
    const exe = b.addExecutable(.{
        .name = name,
        .root_module = b.createModule(.{
            .root_source_file = b.path(source),
            .target = options.target,
            .optimize = options.optimize,
            .imports = options.imports,
        }),
    });
    exe.root_module.addOptions("build_options", options.build_options);
    exe.root_module.link_libc = true;
    exe.root_module.linkSystemLibrary("z", .{});
    exe.root_module.linkSystemLibrary("zstd", .{});
    if (options.profiling) keepProfilingSymbols(exe.root_module);
    return exe;
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    // Keep frame pointers + symbols so sampling profilers (Instruments) can
    // unwind and name frames instead of dumping self-time onto
    // <deduplicated_symbol>. Pair with -Doptimize=ReleaseFast for a realistic
    // profile. Must be applied to every module in the hot path (deps included),
    // since it's a per-module setting.
    const profiling = b.option(bool, "profiling", "Keep frame pointers and symbols for profilers") orelse false;
    const version = b.option([]const u8, "version", "Build version exposed in metrics") orelse "dev";
    const commit = b.option([]const u8, "commit", "Build commit exposed in metrics") orelse "unknown";
    // stdio is the default. httpz gives one pool thread a batch of up to 16 requests, so one slow
    // intake response blocks the batch, health probes included (bench/matrix c02, c05).
    // bench/matrix runs every case against both frontends.
    const frontend = b.option(
        Frontend,
        "frontend",
        "Inbound HTTP frontend (stdio = std.Io-native, httpz = event loop + worker pool)",
    ) orelse .stdio;

    // Multiplies the work in src/codec/codec_test.zig. 1 keeps
    // `zig build test` fast; a deep run uses 20 or more.
    const decode_test_scale = b.option(
        u32,
        "decode-test-scale",
        "Work multiplier for the decode safety tests",
    ) orelse 1;

    const build_options = b.addOptions();
    build_options.addOption(u32, "decode_test_scale", decode_test_scale);
    build_options.addOption([]const u8, "version", version);
    build_options.addOption([]const u8, "commit", commit);
    build_options.addOption(Frontend, "frontend", frontend);

    // ==========================================================================
    // Dependencies
    // ==========================================================================

    const zimdjson = b.dependency("zimdjson", .{
        .target = target,
        .optimize = optimize,
    });
    const zbench_dep = b.dependency("zbench", .{
        .target = target,
        .optimize = optimize,
    });
    const policy_dep = b.dependency("policy_zig", .{
        .target = target,
        .optimize = optimize,
    });
    const metrics_dep = b.dependency("metrics", .{
        .target = target,
        .optimize = optimize,
    });
    const httpz_dep = b.dependency("httpz", .{
        .target = target,
        .optimize = optimize,
    });
    const httpz_mod = httpz_dep.module("httpz");

    // Shared modules from policy-zig ensure type identity across boundaries.
    const proto_mod = policy_dep.module("proto");
    const o11y_mod = policy_dep.module("observability");
    // Optional extensions module (pulls in the z3 S3 client). Only edge code
    // that wires s3-dump imports it.
    const ext_mod = policy_dep.module("extensions");

    // ==========================================================================
    // Edge Library Module
    // ==========================================================================

    const mod = b.addModule("edge", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "proto", .module = proto_mod },
            .{ .name = "zimdjson", .module = zimdjson.module("zimdjson") },
            .{ .name = "policy_zig", .module = policy_dep.module("policy_zig") },
            .{ .name = "o11y", .module = o11y_mod },
            .{ .name = "extensions", .module = ext_mod },
            .{ .name = "metrics_zig", .module = metrics_dep.module("metrics") },
            .{ .name = "httpz", .module = httpz_mod },
        },
    });
    mod.addOptions("build_options", build_options);

    if (profiling) {
        for ([_]*std.Build.Module{
            mod,
            proto_mod,
            o11y_mod,
            policy_dep.module("policy_zig"),
            zimdjson.module("zimdjson"),
            metrics_dep.module("metrics"),
            httpz_mod,
        }) |m| keepProfilingSymbols(m);
    }

    // ==========================================================================
    // Main Executable
    // ==========================================================================

    const exe_options: EdgeExeOptions = .{
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "proto", .module = proto_mod },
            .{ .name = "zimdjson", .module = zimdjson.module("zimdjson") },
            .{ .name = "policy_zig", .module = policy_dep.module("policy_zig") },
            .{ .name = "o11y", .module = o11y_mod },
            .{ .name = "extensions", .module = ext_mod },
            .{ .name = "metrics_zig", .module = metrics_dep.module("metrics") },
            .{ .name = "httpz", .module = httpz_mod },
        },
        .build_options = build_options,
        .profiling = profiling,
    };

    const exe = addEdgeExe(b, "edge", "src/main.zig", exe_options);
    b.installArtifact(exe);

    // ==========================================================================
    // Distribution Builds
    // ==========================================================================

    const distributions = .{
        .{ "datadog", "src/datadog_main.zig", "Datadog ingestion" },
        .{ "otlp", "src/otlp_main.zig", "OpenTelemetry (OTLP) ingestion" },
        .{ "prometheus", "src/prometheus_main.zig", "Prometheus metrics scraping" },
        .{ "tail", "src/edge_tail_main.zig", "Log tailing" },
        .{ "edge", "src/main.zig", "Full distribution (OTLP, Datadog & Prometheus)" },
        .{ "lambda", "src/lambda_main.zig", "AWS Lambda extension (Datadog)" },
    };

    inline for (distributions) |dist| {
        const name = dist[0];
        const source = dist[1];
        const desc = dist[2];

        const dist_exe = addEdgeExe(b, "edge-" ++ name, source, exe_options);

        const dist_step = b.step(name, "Build the " ++ name ++ " distribution (" ++ desc ++ ")");
        dist_step.dependOn(&b.addInstallArtifact(dist_exe, .{}).step);

        const run_dist_step = b.step("run-" ++ name, "Run the " ++ name ++ " distribution");
        const run_dist_cmd = b.addRunArtifact(dist_exe);
        run_dist_step.dependOn(&run_dist_cmd.step);
        run_dist_cmd.step.dependOn(b.getInstallStep());
        if (b.args) |args| {
            run_dist_cmd.addArgs(args);
        }
    }

    // ==========================================================================
    // Run Step
    // ==========================================================================

    const run_step = b.step("run", "Run the app");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // ==========================================================================
    // Tests
    // ==========================================================================

    const mod_tests = b.addTest(.{
        .root_module = mod,
    });
    // Only tests use zlib: compress_buffered.zig is the test oracle.
    mod_tests.root_module.link_libc = true;
    mod_tests.root_module.linkSystemLibrary("z", .{});
    mod_tests.root_module.linkSystemLibrary("zstd", .{});

    const run_mod_tests = b.addRunArtifact(mod_tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);

    // The echo server is its own module (src/bench is outside the src
    // package), so its tests need their own artifact or they never run. The
    // matrix trusts this binary to behave like an intake, which makes its
    // parsing and its `/stats` output worth a check.
    //
    // The fake intake must take the heads a real intake takes, so it shares
    // the frontend's head repair rather than keeping its own copy.
    const echo_mod = b.createModule(.{
        .root_source_file = b.path("src/bench/echo_server.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "head_repair", .module = b.createModule(.{
            .root_source_file = b.path("src/frontend/stdio/head_repair.zig"),
            .target = target,
            .optimize = optimize,
        }) }},
    });
    const echo_tests = b.addTest(.{ .root_module = echo_mod });
    test_step.dependOn(&b.addRunArtifact(echo_tests).step);

    // Real-storage smoke test for the s3-dump extension, filtered to the MinIO
    // e2e test. Excluded from `test` (it needs a live backend); driven by
    // `task test:s3-e2e`, which starts MinIO, creates the bucket, and sets the
    // S3 env vars this test reads.
    const s3_e2e_tests = b.addTest(.{
        .root_module = mod,
        .filters = &.{"e2e minio"},
    });
    const run_s3_e2e_tests = b.addRunArtifact(s3_e2e_tests);
    const s3_e2e_step = b.step("test-s3-e2e", "Run the s3-dump MinIO smoke test (needs S3 env vars)");
    s3_e2e_step.dependOn(&run_s3_e2e_tests.step);

    // ==========================================================================
    // Benchmark Tools
    // ==========================================================================

    const echo_server = b.addExecutable(.{ .name = "echo-server", .root_module = echo_mod });

    const echo_step = b.step("echo-server", "Build the echo server for benchmarking");
    echo_step.dependOn(&b.addInstallArtifact(echo_server, .{}).step);

    // Pool harness: checks that edge evicts a stale keep-alive connection and retries.
    const pool_harness = b.addExecutable(.{
        .name = "upstream-pool-harness",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/bench/upstream_pool_harness.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const pool_harness_step = b.step("upstream-pool-harness", "Verify upstream pool eviction+retry against real edge");
    const run_pool_harness = b.addRunArtifact(pool_harness);
    run_pool_harness.step.dependOn(b.getInstallStep()); // harness spawns zig-out/bin/edge
    pool_harness_step.dependOn(&run_pool_harness.step);

    // End-to-end chunked-request harness for the stdio frontend. It runs the
    // real edge binary; see src/bench/chunked_harness.zig.
    const chunked_harness = b.addExecutable(.{
        .name = "chunked-harness",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/bench/chunked_harness.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const chunked_harness_step = b.step(
        "chunked-harness",
        "Verify chunked request streaming through the stdio frontend against real edge",
    );
    const run_chunked_harness = b.addRunArtifact(chunked_harness);
    run_chunked_harness.step.dependOn(b.getInstallStep()); // harness spawns zig-out/bin/edge
    chunked_harness_step.dependOn(&run_chunked_harness.step);

    // Datadog log search/filter microbenchmark (zbench).
    const datadog_log_bench = b.addExecutable(.{
        .name = "datadog-log-bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/bench/datadog_log_bench.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "edge", .module = mod },
                .{ .name = "zbench", .module = zbench_dep.module("zbench") },
                .{ .name = "proto", .module = proto_mod },
                .{ .name = "o11y", .module = o11y_mod },
            },
        }),
    });
    datadog_log_bench.root_module.addAnonymousImport("datadog_wrapped_log", .{
        .root_source_file = b.path("bench/datadog/payloads/wrapped_log.json"),
    });
    // The bench has a --profile mode for attaching Instruments; always keep
    // frame pointers + symbols so ReleaseFast stacks symbolicate.
    keepProfilingSymbols(datadog_log_bench.root_module);
    datadog_log_bench.root_module.link_libc = true;
    datadog_log_bench.root_module.linkSystemLibrary("z", .{});
    datadog_log_bench.root_module.linkSystemLibrary("zstd", .{});

    const datadog_log_bench_step = b.step("datadog-log-bench", "Run the Datadog log eval matrix benchmark");
    const run_datadog_log_bench = b.addRunArtifact(datadog_log_bench);
    // Forward CLI args (e.g. `zig build datadog-log-bench -- --profile plain/none 30`)
    // and install the binary so a profiler can be attached to it directly.
    if (b.args) |args| run_datadog_log_bench.addArgs(args);
    datadog_log_bench_step.dependOn(&run_datadog_log_bench.step);
    datadog_log_bench_step.dependOn(&b.addInstallArtifact(datadog_log_bench, .{}).step);

    // JSON-array framer microbenchmark (zbench).
    const json_framer_bench = b.addExecutable(.{
        .name = "json-framer-bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/bench/json_framer_bench.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "edge", .module = mod },
                .{ .name = "zbench", .module = zbench_dep.module("zbench") },
            },
        }),
    });
    json_framer_bench.root_module.link_libc = true;
    json_framer_bench.root_module.linkSystemLibrary("z", .{});
    json_framer_bench.root_module.linkSystemLibrary("zstd", .{});

    const json_framer_bench_step = b.step("json-framer-bench", "Run the JSON-array framer benchmark");
    const run_json_framer_bench = b.addRunArtifact(json_framer_bench);
    json_framer_bench_step.dependOn(&run_json_framer_bench.step);

    // gzip and zstd, old codec path against src/codec (zbench).
    const codec_bench = b.addExecutable(.{
        .name = "codec-bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/bench/codec_bench.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "edge", .module = mod },
                .{ .name = "zbench", .module = zbench_dep.module("zbench") },
            },
        }),
    });
    codec_bench.root_module.link_libc = true;
    codec_bench.root_module.linkSystemLibrary("z", .{});
    codec_bench.root_module.linkSystemLibrary("zstd", .{});
    const codec_bench_step = b.step("codec-bench", "Run the gzip/zstd codec benchmark, old against new");
    codec_bench_step.dependOn(&b.addRunArtifact(codec_bench).step);

    const run_echo_step = b.step("run-echo-server", "Run the echo server");
    const run_echo_cmd = b.addRunArtifact(echo_server);
    run_echo_step.dependOn(&run_echo_cmd.step);
    run_echo_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_echo_cmd.addArgs(args);
    }
}
