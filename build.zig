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

    // const dep_mcl_c = b.dependency("mcl", .{});
    //
    // const mcl = b.addStaticLibrary(.{
    //     .name = "mcl",
    //     .target = target,
    //     .optimize = optimize,
    // });
    // mcl.addIncludePath(dep_mcl_c.path("src"));
    // mcl.addIncludePath(dep_mcl_c.path("include"));
    // mcl.addIncludePath(dep_mcl_c.path("include/mcl"));
    //
    // // const mcl_flags = [_][]const u8{ "-g3", "-Wall", "-Wextra", "-Wformat=2", "-Wcast-qual", "-Wcast-align", "-Wwrite-strings", "-Wfloat-equal", "-Wpointer-arith", "-Wundef", "-m64", "-fomit-frame-pointer", "-DNDEBUG", "-fno-stack-protector", "-O3", "-fpic" };
    //
    // mcl.addCSourceFiles(.{ .root = dep_mcl_c.path(""), .files = &.{ "src/bn_c256.cpp", "src/bn_c384.cpp","src/bn_c384_256.cpp","src/bn_c512.cpp","src/bint64.ll" } });
    // mcl.installHeadersDirectory(dep_mcl_c.path("src"), "", .{});
    // mcl.installHeadersDirectory(dep_mcl_c.path("include"), "", .{});
    // mcl.installHeadersDirectory(dep_mcl_c.path("include/mcl"), "", .{});
    // mcl.linkLibC();
    // mcl.linkLibCpp();
    //
    // b.installArtifact(mcl);
    //
    // const dep_bls_c = b.dependency("bls", .{});
    //
    // const bls = b.addStaticLibrary(.{
    //     .name = "bls",
    //     .target = target,
    //     .optimize = optimize,
    // });
    // bls.addIncludePath(dep_bls_c.path("src"));
    // bls.addIncludePath(dep_bls_c.path("include"));
    // bls.addIncludePath(dep_mcl_c.path("src"));
    // bls.addIncludePath(dep_mcl_c.path("include"));
    // bls.addIncludePath(dep_mcl_c.path("include/mcl"));
    //
    // const bls_flags = [_][]const u8{ "-g3", "-Wall", "-Wextra", "-Wformat=2", "-Wcast-qual", "-Wcast-align", "-Wwrite-strings", "-Wfloat-equal", "-Wpointer-arith", "-Wundef", "-m64", "-fomit-frame-pointer", "-DNDEBUG", "-fno-stack-protector", "-O3", "-fpic", "-DBLS_ETH" };
    //
    // bls.addCSourceFiles(.{ .root = dep_bls_c.path(""), .flags = &bls_flags, .files = &.{ "src/bls_c256.cpp", "src/bls_c384.cpp", "src/bls_c384_256.cpp", "src/bls_c512.cpp", "src/mylib.c" } });
    // bls.installHeadersDirectory(dep_mcl_c.path("src"), "", .{});
    // bls.installHeadersDirectory(dep_mcl_c.path("include"), "", .{});
    // bls.installHeadersDirectory(dep_mcl_c.path("include/mcl"), "", .{});
    // bls.installHeadersDirectory(dep_bls_c.path("src"), "", .{});
    // bls.installHeadersDirectory(dep_bls_c.path("include"), "", .{});
    // bls.linkLibC();
    // bls.linkLibCpp();
    //
    // b.installArtifact(bls);

    const lib = b.addStaticLibrary(.{
        .name = "zephyrus",
        // In this case the main source file is merely a path, however, in more
        // complicated build scripts, this could be a generated file.
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

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
    // lib_unit_tests.installHeadersDirectory(b.path("bls/include/"), "", .{});
    // lib_unit_tests.installHeadersDirectory(b.path("bls/mcl/include/"), "", .{});
    lib_unit_tests.addIncludePath(b.path("bls/include/"));
    lib_unit_tests.addIncludePath(b.path("bls/mcl/include/"));
    lib_unit_tests.addObjectFile(b.path("bls/mcl/lib/libmcl.a"));
    lib_unit_tests.addObjectFile(b.path("bls/lib/libbls384_256.a"));
    lib_unit_tests.linkLibC();
    lib_unit_tests.linkLibCpp();
    // lib_unit_tests.addIncludePath(dep_mcl_c.path("src"));
    // lib_unit_tests.addIncludePath(dep_mcl_c.path("include"));
    // lib_unit_tests.addIncludePath(dep_mcl_c.path("include/mcl"));
    // lib_unit_tests.addIncludePath(dep_bls_c.path("src"));
    // lib_unit_tests.addIncludePath(dep_bls_c.path("include"));
    // lib_unit_tests.linkLibrary(mcl);
    // lib_unit_tests.linkLibrary(bls);
    // lib_unit_tests.linkLibC();
    // lib_unit_tests.linkLibCpp();

    // lib_unit_tests.root_module.addImport("zabi", ssz_dep.module("zabi"));

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const exe_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // exe_unit_tests.addIncludePath(dep_mcl_c.path("src"));
    // exe_unit_tests.addIncludePath(dep_mcl_c.path("include"));
    // exe_unit_tests.addIncludePath(dep_mcl_c.path("include/mcl"));
    // exe_unit_tests.addIncludePath(dep_bls_c.path("src"));
    // exe_unit_tests.addIncludePath(dep_bls_c.path("include"));
    // exe_unit_tests.linkLibrary(mcl);
    // exe_unit_tests.linkLibrary(bls);
    // exe_unit_tests.linkLibC();
    // exe_unit_tests.linkLibCpp();

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_exe_unit_tests.step);
}
