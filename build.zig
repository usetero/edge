const std = @import("std");
const protobuf = @import("protobuf");

// Although this function looks imperative, it does not perform the build
// directly and instead it mutates the build graph (`b`) that will be then
// executed by an external runner. The functions in `std.Build` implement a DSL
// for defining build steps and express dependencies between them, allowing the
// build runner to parallelize the build automatically (and the cache system to
// know when a step doesn't need to be re-run).
pub fn build(b: *std.Build) void {
    // Standard target options allow the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});
    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});
    // It's also possible to define more custom flags to toggle optional features
    // of this build script using `b.option()`. All defined flags (including
    // target and optimize options) will be listed when running `zig build --help`
    // in this directory.

    const httpz = b.dependency("httpz", .{
        .target = target,
        .optimize = optimize,
    });
    const protobuf_dep = b.dependency("protobuf", .{
        .target = target,
        .optimize = optimize,
    });
    const zimdjson = b.dependency("zimdjson", .{
        .target = target,
        .optimize = optimize,
    });

    // Create a proto module for generated protobuf files
    const proto_mod = b.addModule("proto", .{
        .root_source_file = b.path("src/proto/root.zig"),
        .target = target,
    });
    proto_mod.addImport("protobuf", protobuf_dep.module("protobuf"));

    // This creates a module, which represents a collection of source files alongside
    // some compilation options, such as optimization mode and linked system libraries.
    // Zig modules are the preferred way of making Zig code available to consumers.
    // addModule defines a module that we intend to make available for importing
    // to our consumers. We must give it a name because a Zig package can expose
    // multiple modules and consumers will need to be able to specify which
    // module they want to access.
    const mod = b.addModule("edge", .{
        // The root source file is the "entry point" of this module. Users of
        // this module will only be able to access public declarations contained
        // in this file, which means that if you have declarations that you
        // intend to expose to consumers that were defined in other files part
        // of this module, you will have to make sure to re-export them from
        // the root file.
        .root_source_file = b.path("src/root.zig"),
        // Later on we'll use this module as the root module of a test executable
        // which requires us to specify a target.
        .target = target,
        .imports = &.{
            .{ .name = "proto", .module = proto_mod },
            .{ .name = "zimdjson", .module = zimdjson.module("zimdjson") },
        },
    });

    // Here we define an executable. An executable needs to have a root module
    // which needs to expose a `main` function. While we could add a main function
    // to the module defined above, it's sometimes preferable to split business
    // logic and the CLI into two separate modules.
    //
    // If your goal is to create a Zig library for others to use, consider if
    // it might benefit from also exposing a CLI tool. A parser library for a
    // data serialization format could also bundle a CLI syntax checker, for example.
    //
    // If instead your goal is to create an executable, consider if users might
    // be interested in also being able to embed the core functionality of your
    // program in their own executable in order to avoid the overhead involved in
    // subprocessing your CLI tool.
    //
    // If neither case applies to you, feel free to delete the declaration you
    // don't need and to put everything under a single module.
    const exe = b.addExecutable(.{
        .name = "edge",
        .root_module = b.createModule(.{
            // b.createModule defines a new module just like b.addModule but,
            // unlike b.addModule, it does not expose the module to consumers of
            // this package, which is why in this case we don't have to give it a name.
            .root_source_file = b.path("src/main.zig"),
            // Target and optimization levels must be explicitly wired in when
            // defining an executable or library (in the root module), and you
            // can also hardcode a specific target for an executable or library
            // definition if desireable (e.g. firmware for embedded devices).
            .target = target,
            .optimize = optimize,
            // List of modules available for import in source files part of the
            // root module.
            .imports = &.{
                // Here "edge" is the name you will use in your source code to
                // import this module (e.g. `@import("edge")`). The name is
                // repeated because you are allowed to rename your imports, which
                // can be extremely useful in case of collisions (which can happen
                // importing modules from different packages).
                .{ .name = "edge", .module = mod },
            },
        }),
    });
    exe.root_module.addImport("httpz", httpz.module("httpz"));
    exe.root_module.addImport("protobuf", protobuf_dep.module("protobuf"));
    exe.root_module.addImport("proto", proto_mod);
    exe.root_module.addImport("zimdjson", zimdjson.module("zimdjson"));

    // Link zlib for gzip compression
    exe.root_module.link_libc = true;
    exe.root_module.linkSystemLibrary("z", .{});
    exe.root_module.linkSystemLibrary("zstd", .{});
    exe.root_module.linkSystemLibrary("hs", .{});

    // This declares intent for the executable to be installed into the
    // install prefix when running `zig build` (i.e. when executing the default
    // step). By default the install prefix is `zig-out/` but can be overridden
    // by passing `--prefix` or `-p`.
    b.installArtifact(exe);

    // ==========================================================================
    // Distribution Builds
    // ==========================================================================
    // Each distribution is a focused edge proxy for a specific backend.
    // Build with: zig build <distribution>
    // Run with: zig build run-<distribution>

    const distributions = .{
        .{ "datadog", "src/datadog_main.zig", "Datadog log ingestion" },
        .{ "otlp", "src/otlp_main.zig", "OpenTelemetry (OTLP) log ingestion" },
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
        dist_exe.root_module.addImport("protobuf", protobuf_dep.module("protobuf"));
        dist_exe.root_module.addImport("proto", proto_mod);
        dist_exe.root_module.addImport("zimdjson", zimdjson.module("zimdjson"));
        dist_exe.root_module.link_libc = true;
        dist_exe.root_module.linkSystemLibrary("z", .{});
        dist_exe.root_module.linkSystemLibrary("zstd", .{});
        dist_exe.root_module.linkSystemLibrary("hs", .{});

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

    // This creates a top level step. Top level steps have a name and can be
    // invoked by name when running `zig build` (e.g. `zig build run`).
    // This will evaluate the `run` step rather than the default step.
    // For a top level step to actually do something, it must depend on other
    // steps (e.g. a Run step, as we will see in a moment).
    const run_step = b.step("run", "Run the app");

    // This creates a RunArtifact step in the build graph. A RunArtifact step
    // invokes an executable compiled by Zig. Steps will only be executed by the
    // runner if invoked directly by the user (in the case of top level steps)
    // or if another step depends on it, so it's up to you to define when and
    // how this Run step will be executed. In our case we want to run it when
    // the user runs `zig build run`, so we create a dependency link.
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);

    // By making the run step depend on the default step, it will be run from the
    // installation directory rather than directly from within the cache directory.
    run_cmd.step.dependOn(b.getInstallStep());

    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // Creates an executable that will run `test` blocks from the provided module.
    const mod_tests = b.addTest(.{
        .root_module = mod,
    });
    mod_tests.root_module.link_libc = true;
    mod_tests.root_module.linkSystemLibrary("z", .{});
    mod_tests.root_module.linkSystemLibrary("zstd", .{});
    mod_tests.root_module.linkSystemLibrary("hs", .{});

    // A run step that will run the test executable.
    const run_mod_tests = b.addRunArtifact(mod_tests);

    // A top level step for running all tests.
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);

    // ==========================================================================
    // Benchmark Tools
    // ==========================================================================

    // Echo server for benchmarking - a minimal HTTP server that returns 202
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

    // Proto generation step - only create when explicitly requested via build option.
    // This avoids fetching protoc binary during normal builds (which fails on ARM64 CI).
    const gen_proto_opt = b.option(bool, "gen-proto", "Generate protobuf files") orelse false;
    if (gen_proto_opt) {
        const gen_proto = b.step("gen-proto", "generates zig files from protocol buffer definitions");
        const protoc_step = protobuf.RunProtocStep.create(protobuf_dep.builder, target, .{
            .destination_directory = b.path("src/proto"),
            .source_files = &.{
                "proto/tero/policy/v1/policy.proto",
                "proto/tero/policy/v1/log.proto",
                "proto/opentelemetry/proto/logs/v1/logs.proto",
            },
            .include_directories = &.{
                "proto",
            },
        });
        gen_proto.dependOn(&protoc_step.step);
    }
    // Just like flags, top level steps are also listed in the `--help` menu.
    //
    // The Zig build system is entirely implemented in userland, which means
    // that it cannot hook into private compiler APIs. All compilation work
    // orchestrated by the build system will result in other Zig compiler
    // subcommands being invoked with the right flags defined. You can observe
    // these invocations when one fails (or you pass a flag to increase
    // verbosity) to validate assumptions and diagnose problems.
    //
    // Lastly, the Zig build system is relatively simple and self-contained,
    // and reading its source code will allow you to master it.
}
