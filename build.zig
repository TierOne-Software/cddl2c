const std = @import("std");

const zcbor_sources = [_][]const u8{
    "zcbor/src/zcbor_common.c",
    "zcbor/src/zcbor_decode.c",
    "zcbor/src/zcbor_encode.c",
    "zcbor/src/zcbor_print.c",
};

// Flags chosen for the embedded/RTOS target profile: strict C11, no VLAs,
// everything is caller-allocated (zcbor never calls malloc).
//
// ZCBOR_CANONICAL: encode definite-length, minimal-size headers
// (deterministic output, the usual choice for embedded/COSE). Decoding
// strictness can still be relaxed per-state at runtime.
//
// ZCBOR_FRAGMENTS: enable multi-part payload support (zcbor_update_state and
// the string-fragment APIs). This changes sizeof(zcbor_state_t), so it must
// be defined identically for the library and for everything that includes
// the zcbor headers (translate-c below gets the same defines).
const c_flags = [_][]const u8{
    "-std=c11",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-Wvla",
    "-DZCBOR_CANONICAL",
    "-DZCBOR_FRAGMENTS",
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // --- zcbor C library (static) -------------------------------------------
    const zcbor_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    zcbor_mod.addCSourceFiles(.{ .files = &zcbor_sources, .flags = &c_flags });
    zcbor_mod.addIncludePath(b.path("zcbor/include"));

    const zcbor_lib = b.addLibrary(.{
        .name = "zcbor",
        .linkage = .static,
        .root_module = zcbor_mod,
    });
    b.installArtifact(zcbor_lib);

    // --- translated zcbor headers, importable from Zig as "zcbor" ----------
    const zcbor_c = b.addTranslateC(.{
        .root_source_file = b.path("tests/zcbor_c.h"),
        .target = target,
        .optimize = optimize,
    });
    zcbor_c.addIncludePath(b.path("zcbor/include"));
    zcbor_c.defineCMacro("ZCBOR_CANONICAL", null);
    zcbor_c.defineCMacro("ZCBOR_FRAGMENTS", null);
    const zcbor_c_mod = zcbor_c.createModule();

    const test_step = b.step("test", "Run all tests");

    // --- Zig unit tests for the zcbor C implementation ----------------------
    const zcbor_test_mod = b.createModule(.{
        .root_source_file = b.path("tests/zcbor_test.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    zcbor_test_mod.addImport("zcbor", zcbor_c_mod);
    zcbor_test_mod.linkLibrary(zcbor_lib);

    const zcbor_tests = b.addTest(.{
        .name = "zcbor-tests",
        .root_module = zcbor_test_mod,
    });
    test_step.dependOn(&b.addRunArtifact(zcbor_tests).step);

    // --- Fragmented-payload tests (ZCBOR_FRAGMENTS) -------------------------
    const frag_test_mod = b.createModule(.{
        .root_source_file = b.path("tests/zcbor_fragments_test.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    frag_test_mod.addImport("zcbor", zcbor_c_mod);
    frag_test_mod.linkLibrary(zcbor_lib);

    const frag_tests = b.addTest(.{
        .name = "zcbor-fragments-tests",
        .root_module = frag_test_mod,
    });
    test_step.dependOn(&b.addRunArtifact(frag_tests).step);

    // --- Fuzz harness for the zcbor decoder ---------------------------------
    // Runs as a normal (single-pass) test under `zig build test`;
    // run `zig build test --fuzz` to fuzz continuously.
    const fuzz_mod = b.createModule(.{
        .root_source_file = b.path("tests/zcbor_fuzz.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    fuzz_mod.addImport("zcbor", zcbor_c_mod);
    fuzz_mod.linkLibrary(zcbor_lib);

    const fuzz_tests = b.addTest(.{
        .name = "zcbor-fuzz",
        .root_module = fuzz_mod,
    });
    test_step.dependOn(&b.addRunArtifact(fuzz_tests).step);

    // --- CDDL parser + C code generator (pure Zig) --------------------------
    const cddl_mod = b.addModule("cddl", .{
        .root_source_file = b.path("src/cddl.zig"),
        .target = target,
        .optimize = optimize,
    });

    const cddl_test_mod = b.createModule(.{
        .root_source_file = b.path("src/cddl.zig"),
        .target = target,
        .optimize = optimize,
    });
    const cddl_tests = b.addTest(.{
        .name = "cddl-tests",
        .root_module = cddl_test_mod,
    });
    test_step.dependOn(&b.addRunArtifact(cddl_tests).step);

    // --- cddl2c CLI ---------------------------------------------------------
    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_mod.addImport("cddl", cddl_mod);

    const exe = b.addExecutable(.{
        .name = "cddl2c",
        .root_module = exe_mod,
    });
    b.installArtifact(exe);

    // --- End-to-end: generate C types from examples/sample.cddl and compile
    // them with a C11 test program that checks the generated definitions.
    const gen = b.addRunArtifact(exe);
    gen.addFileArg(b.path("examples/sample.cddl"));
    gen.addArg("-o");
    const gen_header = gen.addOutputFileArg("sample_types.h");
    gen.addArg("-d");
    const gen_decode_c = gen.addOutputFileArg("sample_decode.c");
    gen.addArg("-e");
    const gen_encode_c = gen.addOutputFileArg("sample_encode.c");

    const c_test_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    c_test_mod.addCSourceFile(.{
        .file = b.path("tests/c/generated_types_test.c"),
        .flags = &c_flags,
    });
    // The generated codecs are compiled with the same strict flags; the
    // build fails if cddl2c emits anything that is not warning-clean C11.
    c_test_mod.addCSourceFile(.{ .file = gen_decode_c, .flags = &c_flags });
    c_test_mod.addCSourceFile(.{ .file = gen_encode_c, .flags = &c_flags });
    c_test_mod.addIncludePath(gen_header.dirname());
    c_test_mod.addIncludePath(b.path("zcbor/include"));

    c_test_mod.linkLibrary(zcbor_lib);
    const c_test_exe = b.addExecutable(.{
        .name = "generated-types-test",
        .root_module = c_test_mod,
    });
    test_step.dependOn(&b.addRunArtifact(c_test_exe).step);

    // --- Fuzz harnesses for the generated codecs ----------------------------
    // The generated decode/encode C is compiled into a Zig test module and
    // driven with fuzz inputs: garbage must be rejected cleanly, and the
    // fragmented APIs must be faithful across arbitrary section/chunk splits.
    const sample_gen_c = b.addTranslateC(.{
        .root_source_file = b.path("tests/sample_gen.h"),
        .target = target,
        .optimize = optimize,
    });
    sample_gen_c.addIncludePath(gen_header.dirname());
    sample_gen_c.addIncludePath(b.path("zcbor/include"));
    sample_gen_c.defineCMacro("ZCBOR_CANONICAL", null);
    sample_gen_c.defineCMacro("ZCBOR_FRAGMENTS", null);

    const gen_fuzz_mod = b.createModule(.{
        .root_source_file = b.path("tests/generated_fuzz.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    gen_fuzz_mod.addImport("gen", sample_gen_c.createModule());
    gen_fuzz_mod.linkLibrary(zcbor_lib);
    gen_fuzz_mod.addCSourceFile(.{ .file = gen_decode_c, .flags = &c_flags });
    gen_fuzz_mod.addCSourceFile(.{ .file = gen_encode_c, .flags = &c_flags });
    gen_fuzz_mod.addIncludePath(gen_header.dirname());
    gen_fuzz_mod.addIncludePath(b.path("zcbor/include"));

    const gen_fuzz_tests = b.addTest(.{
        .name = "generated-fuzz",
        .root_module = gen_fuzz_mod,
    });
    test_step.dependOn(&b.addRunArtifact(gen_fuzz_tests).step);

    // --- Benchmarks (`zig build bench`, `zig build bench-lto`) --------------
    // Always ReleaseFast: the zcbor C sources and the generated codecs are
    // compiled directly into the benchmark module at that optimize mode.
    // The -lto variant measures how much of the small-message overhead
    // cross-TU inlining recovers.
    const bench_optimize: std.builtin.OptimizeMode = .ReleaseFast;
    const bench_gen_c = b.addTranslateC(.{
        .root_source_file = b.path("tests/sample_gen.h"),
        .target = target,
        .optimize = bench_optimize,
    });
    bench_gen_c.addIncludePath(gen_header.dirname());
    bench_gen_c.addIncludePath(b.path("zcbor/include"));
    bench_gen_c.defineCMacro("ZCBOR_CANONICAL", null);
    bench_gen_c.defineCMacro("ZCBOR_FRAGMENTS", null);
    const bench_gen_mod = bench_gen_c.createModule();

    inline for (.{ false, true }) |use_lto| {
        const bench_mod = b.createModule(.{
            .root_source_file = b.path("bench/bench.zig"),
            .target = target,
            .optimize = bench_optimize,
            .link_libc = true,
        });
        bench_mod.addImport("gen", bench_gen_mod);
        bench_mod.addCSourceFiles(.{ .files = &zcbor_sources, .flags = &c_flags });
        bench_mod.addCSourceFile(.{ .file = gen_decode_c, .flags = &c_flags });
        bench_mod.addCSourceFile(.{ .file = gen_encode_c, .flags = &c_flags });
        bench_mod.addIncludePath(gen_header.dirname());
        bench_mod.addIncludePath(b.path("zcbor/include"));

        const bench_exe = b.addExecutable(.{
            .name = if (use_lto) "bench-lto" else "bench",
            .root_module = bench_mod,
        });
        if (use_lto) bench_exe.lto = .full;
        const bench_step = b.step(
            if (use_lto) "bench-lto" else "bench",
            if (use_lto)
                "Run codec throughput benchmarks with full LTO"
            else
                "Run codec throughput benchmarks (ReleaseFast)",
        );
        bench_step.dependOn(&b.addRunArtifact(bench_exe).step);
    }
}
