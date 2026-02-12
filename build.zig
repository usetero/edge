const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ==========================================================================
    // Dependencies
    // ==========================================================================

    const httpz = b.dependency("httpz", .{
        .target = target,
        .optimize = optimize,
    });
    const zimdjson = b.dependency("zimdjson", .{
        .target = target,
        .optimize = optimize,
    });
    const policy_dep = b.dependency("policy_zig", .{
        .target = target,
        .optimize = optimize,
    });

    // Shared modules from policy-zig ensure type identity across boundaries.
    const proto_mod = policy_dep.module("proto");
    const o11y_mod = policy_dep.module("o11y");

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
        },
    });

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
    exe.root_module.addImport("httpz", httpz.module("httpz"));
    exe.root_module.addImport("proto", proto_mod);
    exe.root_module.addImport("zimdjson", zimdjson.module("zimdjson"));
    exe.root_module.addImport("policy_zig", policy_dep.module("policy_zig"));
    exe.root_module.addImport("o11y", o11y_mod);
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
        dist_exe.root_module.addImport("httpz", httpz.module("httpz"));
        dist_exe.root_module.addImport("proto", proto_mod);
        dist_exe.root_module.addImport("zimdjson", zimdjson.module("zimdjson"));
        dist_exe.root_module.addImport("policy_zig", policy_dep.module("policy_zig"));
        dist_exe.root_module.addImport("o11y", o11y_mod);
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
    echo_server.root_module.addImport("httpz", httpz.module("httpz"));

    const echo_step = b.step("echo-server", "Build the echo server for benchmarking");
    echo_step.dependOn(&b.addInstallArtifact(echo_server, .{}).step);

    const run_echo_step = b.step("run-echo-server", "Run the echo server");
    const run_echo_cmd = b.addRunArtifact(echo_server);
    run_echo_step.dependOn(&run_echo_cmd.step);
    run_echo_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_echo_cmd.addArgs(args);
    }
}
