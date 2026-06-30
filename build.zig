const std = @import("std");

pub const Frontend = enum { stdio, httpz };

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const version = b.option([]const u8, "version", "Build version exposed in metrics") orelse "dev";
    const commit = b.option([]const u8, "commit", "Build commit exposed in metrics") orelse "unknown";
    // httpz is the default until std.Io has an evented implementation that
    // serves sockets (PLAN-FRONTEND-SWAP.md §6 swap-back criteria). CI must
    // keep building both.
    const frontend = b.option(
        Frontend,
        "frontend",
        "Inbound HTTP frontend (httpz = event loop + worker pool, stdio = std.Io-native)",
    ) orelse .httpz;

    const build_options = b.addOptions();
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
            .{ .name = "metrics_zig", .module = metrics_dep.module("metrics") },
            .{ .name = "httpz", .module = httpz_mod },
        },
    });
    mod.addOptions("build_options", build_options);

    // ==========================================================================
    // Main Executable
    // ==========================================================================

    const exe = b.addExecutable(.{
        .name = "edge",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "edge", .module = mod },
            },
        }),
    });
    exe.root_module.addImport("proto", proto_mod);
    exe.root_module.addImport("zimdjson", zimdjson.module("zimdjson"));
    exe.root_module.addImport("policy_zig", policy_dep.module("policy_zig"));
    exe.root_module.addImport("o11y", o11y_mod);
    exe.root_module.addImport("metrics_zig", metrics_dep.module("metrics"));
    exe.root_module.addImport("httpz", httpz_mod);
    exe.root_module.addOptions("build_options", build_options);
    exe.root_module.link_libc = true;
    exe.root_module.linkSystemLibrary("z", .{});
    exe.root_module.linkSystemLibrary("zstd", .{});

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

        const dist_exe = b.addExecutable(.{
            .name = "edge-" ++ name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(source),
                .target = target,
                .optimize = optimize,
            }),
        });
        dist_exe.root_module.addImport("proto", proto_mod);
        dist_exe.root_module.addImport("zimdjson", zimdjson.module("zimdjson"));
        dist_exe.root_module.addImport("policy_zig", policy_dep.module("policy_zig"));
        dist_exe.root_module.addImport("o11y", o11y_mod);
        dist_exe.root_module.addImport("metrics_zig", metrics_dep.module("metrics"));
        dist_exe.root_module.addImport("httpz", httpz_mod);
        dist_exe.root_module.addOptions("build_options", build_options);
        dist_exe.root_module.link_libc = true;
        dist_exe.root_module.linkSystemLibrary("z", .{});
        dist_exe.root_module.linkSystemLibrary("zstd", .{});

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
    mod_tests.root_module.link_libc = true;
    mod_tests.root_module.linkSystemLibrary("z", .{});
    mod_tests.root_module.linkSystemLibrary("zstd", .{});
    mod_tests.root_module.addImport("metrics_zig", metrics_dep.module("metrics"));
    mod_tests.root_module.addOptions("build_options", build_options);
    // Benchmark fixture embedded by test-only code in src/signals/otlp/metrics.zig.
    // It lives under bench/ (outside the src package), so @embedFile needs it wired
    // in as a named module import rather than a relative path.
    mod_tests.root_module.addAnonymousImport("otlp_metrics_benchmark_pb", .{
        .root_source_file = b.path("bench/scaling/payloads/otlp-metrics.pb"),
    });

    const run_mod_tests = b.addRunArtifact(mod_tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);

    // ==========================================================================
    // Benchmark Tools
    // ==========================================================================

    const echo_server = b.addExecutable(.{
        .name = "echo-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/bench/echo_server.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const echo_step = b.step("echo-server", "Build the echo server for benchmarking");
    echo_step.dependOn(&b.addInstallArtifact(echo_server, .{}).step);

    // Upstream connection-pool poisoning harness: reproduces the stale-keepalive
    // poison (ziglang/zig#30165 send-side) and verifies the eviction fix.
    const pool_harness = b.addExecutable(.{
        .name = "upstream-pool-harness",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/bench/upstream_pool_harness.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const pool_harness_step = b.step("upstream-pool-harness", "Verify the upstream pool eviction+retry fix against the real edge binary");
    const run_pool_harness = b.addRunArtifact(pool_harness);
    run_pool_harness.step.dependOn(b.getInstallStep()); // harness spawns zig-out/bin/edge
    pool_harness_step.dependOn(&run_pool_harness.step);

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
    datadog_log_bench.root_module.link_libc = true;
    datadog_log_bench.root_module.linkSystemLibrary("z", .{});
    datadog_log_bench.root_module.linkSystemLibrary("zstd", .{});

    const datadog_log_bench_step = b.step("datadog-log-bench", "Run the Datadog log search benchmark");
    const run_datadog_log_bench = b.addRunArtifact(datadog_log_bench);
    datadog_log_bench_step.dependOn(&run_datadog_log_bench.step);

    const run_echo_step = b.step("run-echo-server", "Run the echo server");
    const run_echo_cmd = b.addRunArtifact(echo_server);
    run_echo_step.dependOn(&run_echo_cmd.step);
    run_echo_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_echo_cmd.addArgs(args);
    }
}
