const std = @import("std");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addStaticLibrary(.{
        .name = "zephyrus",
        // In this case the main source file is merely a path, however, in more
        // complicated build scripts, this could be a generated file.
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    //  const dep = b.dependency("yaml", .{});

    const yaml = buildYaml(b, target, optimize);
    lib.root_module.addImport("yaml", yaml);
    // b.installArtifact(yaml);
    // lib.addIncludePath(b.path("clib/libyaml/include"));

    // Add ssz.zig as a dependency to the library
    // const ssz_dep = b.dependency(
    //     "zabi",
    //     .{
    //         .target = target,
    //         .optimize = optimize,
    //     },
    // );
    // lib.root_module.addImport("zabi", ssz_dep.module("zabi"));

    // This declares intent for the library to be installed into the standard
    // location when the user invokes the "install" step (the default step when
    // running `zig build`).
    b.installArtifact(lib);

    const exe = b.addExecutable(.{
        .name = "zephyrus",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // exe.root_module.addImport("zabi", ssz_dep.module("zabi"));
    // This declares intent for the executable to be installed into the
    // standard location when the user invokes the "install" step (the default
    // step when running `zig build`).
    b.installArtifact(exe);

    // This *creates* a Run step in the build graph, to be executed when another
    // step is evaluated that depends on it. The next line below will establish
    // such a dependency.
    const run_cmd = b.addRunArtifact(exe);

    // By making the run step depend on the install step, it will be run from the
    // installation directory rather than directly from within the cache directory.
    // This is not necessary, however, if the application depends on other installed
    // files, this ensures they will be present and in the expected location.
    run_cmd.step.dependOn(b.getInstallStep());

    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // This creates a build step. It will be visible in the `zig build --help` menu,
    // and can be selected like this: `zig build run`
    // This will evaluate the `run` step rather than the default, which is "install".
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // Creates a step for unit testing. This only builds the test executable
    // but does not run it.
    const lib_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    // lib_unit_tests.addIncludePath(b.path("clib/libyaml/include"));
    lib_unit_tests.root_module.addImport("yaml", yaml);

    // lib_unit_tests.root_module.addImport("zabi", ssz_dep.module("zabi"));

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const exe_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_exe_unit_tests.step);
}

fn buildYaml(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.Mode) *std.Build.Module {
    const translate_c = b.addTranslateC(.{
        .root_source_file = b.path("clib/libyaml/include/yaml.h"),
        .target = target,
        .optimize = optimize,
    });

    const mod = b.addModule("yaml", .{
        .root_source_file = translate_c.getOutput(),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .link_libcpp = true,
    });

    mod.addIncludePath(b.path("clib/libyaml/include"));
    mod.addIncludePath(b.path("clib/libyaml/src"));

    const yaml_a = b.addStaticLibrary(.{
        .name = "yaml",
        .target = target,
        .optimize = optimize,
    });

    yaml_a.addCSourceFiles(.{
        .root = b.path("clib/libyaml"),
        .files = &.{
            "src/api.c",
            "src/dumper.c",
            "src/emitter.c",
            "src/loader.c",
            "src/parser.c",
            "src/reader.c",
            "src/scanner.c",
            "src/writer.c",
        },
        .flags = &.{
            "-DYAML_VERSION_MAJOR=0",
            "-DYAML_VERSION_MINOR=2",
            "-DYAML_VERSION_PATCH=5",
            "-DYAML_VERSION_STRING=\"0.2.5\"",
        },
    });
    // lib.installHeader(b.path("clib/libyaml/inclued/yaml.h"), "yaml.h");
    yaml_a.installHeadersDirectory(b.path("clib/libyaml/src"), "", .{});
    yaml_a.installHeadersDirectory(b.path("clib/libyaml/include"), "", .{});
    yaml_a.addIncludePath(b.path("clib/libyaml/include"));
    yaml_a.linkLibC();
    b.installArtifact(yaml_a);
    mod.linkLibrary(yaml_a);

    return mod;
}
