//! cddl2c: generate C11 types and zcbor-based codecs from a CDDL description.
//!
//! Usage: cddl2c INPUT.cddl [-o TYPES.h] [-d [DECODE.c]] [-e [ENCODE.c]]
//!
//!   -o TYPES.h    types header (stdout if omitted)
//!   -d [DECODE.c] also generate decode functions (.c + .h). The path is
//!                 derived from -o when not given (`X_types.h` -> `X_decode.c`).
//!   -e [ENCODE.c] also generate encode functions, same rules.

const std = @import("std");
const cddl = @import("cddl");

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const io = init.io;

    var input_path: ?[]const u8 = null;
    var output_path: ?[]const u8 = null;
    var gen_decode = false;
    var gen_encode = false;
    var decode_c_path: ?[]const u8 = null;
    var encode_c_path: ?[]const u8 = null;
    var frag_rules: std.ArrayList([]const u8) = .empty;
    var frag_restrict = false;
    var entry_rules: std.ArrayList([]const u8) = .empty;
    var entry_restrict = false;
    var unordered_maps = true;

    // initAllocator is required for Windows/WASI targets (the command line
    // must be decoded from UTF-16 into the arena); on POSIX it is a no-op.
    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, arena);
    defer args.deinit();
    _ = args.next(); // program name
    var pending: ?[:0]const u8 = null;
    while (pending orelse args.next()) |arg| {
        pending = null;
        if (std.mem.eql(u8, arg, "-o")) {
            output_path = args.next() orelse return usage();
        } else if (std.mem.eql(u8, arg, "-d") or std.mem.eql(u8, arg, "-e")) {
            // Optional value: only a following argument ending in ".c" is
            // treated as the output path.
            var path: ?[]const u8 = null;
            if (args.next()) |next_arg| {
                if (std.mem.endsWith(u8, next_arg, ".c")) {
                    path = next_arg;
                } else {
                    pending = next_arg;
                }
            }
            if (arg[1] == 'd') {
                gen_decode = true;
                if (path) |p| decode_c_path = p;
            } else {
                gen_encode = true;
                if (path) |p| encode_c_path = p;
            }
        } else if (std.mem.eql(u8, arg, "--frag")) {
            frag_restrict = true;
            const list = args.next() orelse return usage();
            var it = std.mem.splitScalar(u8, list, ',');
            while (it.next()) |rule| {
                if (rule.len > 0) try frag_rules.append(arena, rule);
            }
        } else if (std.mem.eql(u8, arg, "--entry")) {
            entry_restrict = true;
            const list = args.next() orelse return usage();
            var it = std.mem.splitScalar(u8, list, ',');
            while (it.next()) |rule| {
                if (rule.len > 0) try entry_rules.append(arena, rule);
            }
        } else if (std.mem.eql(u8, arg, "--ordered-maps")) {
            unordered_maps = false;
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            return usage();
        } else if (input_path == null) {
            input_path = arg;
        } else {
            return usage();
        }
    }
    const in_path = input_path orelse return usage();

    // Resolve output paths and the basenames used in #include directives.
    if (gen_decode and decode_c_path == null and output_path != null) {
        decode_c_path = try deriveSibling(arena, output_path.?, "_decode.c");
    }
    if (gen_encode and encode_c_path == null and output_path != null) {
        encode_c_path = try deriveSibling(arena, output_path.?, "_encode.c");
    }
    const decode_h_path: ?[]const u8 = if (decode_c_path) |p| try swapExt(arena, p, ".h") else null;
    const encode_h_path: ?[]const u8 = if (encode_c_path) |p| try swapExt(arena, p, ".h") else null;

    const types_base = std.fs.path.basename(output_path orelse "cddl_types.h");
    const decode_h_base = if (decode_h_path) |p| std.fs.path.basename(p) else "cddl_decode.h";
    const encode_h_base = if (encode_h_path) |p| std.fs.path.basename(p) else "cddl_encode.h";

    const cwd = std.Io.Dir.cwd();
    const source = cwd.readFileAlloc(io, in_path, arena, .limited(16 * 1024 * 1024)) catch |err| {
        std.debug.print("error: cannot read {s}: {t}\n", .{ in_path, err });
        return 1;
    };

    var pdiag: cddl.Parser.Diagnostic = .{};
    const doc = cddl.Parser.parse(arena, source, &pdiag) catch |err| switch (err) {
        error.ParseError => {
            std.debug.print("{s}:{d}:{d}: error: {s}\n", .{
                in_path, pdiag.line, pdiag.column, pdiag.message,
            });
            return 1;
        },
        else => return err,
    };

    // Reject ambiguous unions before generating anything: the decoder picks
    // the first matching arm, so an unprovable overlap is a silent misdecode.
    var vdiag: cddl.validate.Diagnostic = .{};
    cddl.validate.checkAmbiguousUnions(arena, &doc, &vdiag) catch |err| switch (err) {
        error.OutOfMemory => return err,
        error.AmbiguousUnion => {
            std.debug.print("{s}: error: {s}: {s}\n", .{ in_path, vdiag.message, vdiag.context });
            return 1;
        },
    };

    var gdiag: cddl.codegen.Diagnostic = .{};
    const out = cddl.codegen.generateAll(arena, doc, .{
        .guard = try guardName(arena, types_base),
        .entry_rules = if (entry_restrict) entry_rules.items else null,
        .xcode = .{
            .decode = gen_decode,
            .encode = gen_encode,
            .frag_rules = if (frag_restrict) frag_rules.items else null,
            .unordered_maps = unordered_maps,
            .types_h = types_base,
            .decode_h = decode_h_base,
            .encode_h = encode_h_base,
            .decode_guard = try guardName(arena, decode_h_base),
            .encode_guard = try guardName(arena, encode_h_base),
        },
    }, &gdiag) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => {
            std.debug.print("{s}: error: {s}: {s} ({t})\n", .{
                in_path, gdiag.message, gdiag.context, err,
            });
            return 1;
        },
    };

    try writeOut(io, output_path, out.types_h);
    if (gen_decode) {
        try writeOut(io, decode_h_path, out.decode_h.?);
        try writeOut(io, decode_c_path, out.decode_c.?);
    }
    if (gen_encode) {
        try writeOut(io, encode_h_path, out.encode_h.?);
        try writeOut(io, encode_c_path, out.encode_c.?);
    }
    return 0;
}

fn writeOut(io: std.Io, path: ?[]const u8, data: []const u8) !void {
    if (path) |p| {
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = p, .data = data });
    } else {
        try std.Io.File.stdout().writeStreamingAll(io, data);
    }
}

/// "out/sample_types.h" + "_decode.c" -> "out/sample_decode.c"
/// (a trailing "_types" in the stem is replaced by the suffix).
fn deriveSibling(arena: std.mem.Allocator, types_path: []const u8, suffix: []const u8) ![]const u8 {
    const dir = std.fs.path.dirname(types_path);
    const base = std.fs.path.basename(types_path);
    const stem_ext = if (std.mem.lastIndexOfScalar(u8, base, '.')) |i| base[0..i] else base;
    const stem = if (std.mem.endsWith(u8, stem_ext, "_types"))
        stem_ext[0 .. stem_ext.len - "_types".len]
    else
        stem_ext;
    if (dir) |d| {
        return std.fmt.allocPrint(arena, "{s}/{s}{s}", .{ d, stem, suffix });
    }
    return std.fmt.allocPrint(arena, "{s}{s}", .{ stem, suffix });
}

fn swapExt(arena: std.mem.Allocator, path: []const u8, ext: []const u8) ![]const u8 {
    const cut = if (std.mem.lastIndexOfScalar(u8, path, '.')) |i| path[0..i] else path;
    return std.fmt.allocPrint(arena, "{s}{s}", .{ cut, ext });
}

fn guardName(arena: std.mem.Allocator, basename: []const u8) ![]const u8 {
    const buf = try arena.alloc(u8, basename.len + 2);
    for (basename, 0..) |ch, j| {
        buf[j] = if (std.ascii.isAlphanumeric(ch)) std.ascii.toUpper(ch) else '_';
    }
    buf[basename.len] = '_';
    buf[basename.len + 1] = '_';
    return buf;
}

fn usage() u8 {
    std.debug.print(
        \\usage: cddl2c INPUT.cddl [-o TYPES.h] [-d [DECODE.c]] [-e [ENCODE.c]]
        \\              [--entry RULE[,RULE...]] [--frag RULE[,RULE...]]
        \\
        \\  -o TYPES.h    write the types header (stdout if omitted)
        \\  -d [DECODE.c] also generate decode functions (.c and .h)
        \\  -e [ENCODE.c] also generate encode functions (.c and .h)
        \\  --entry LIST  generate only the listed rules plus what they
        \\                reference, and give only them public cbor_decode_X/
        \\                cbor_encode_X wrappers (default: every rule)
        \\  --frag LIST   generate the fragmented-payload API only for the
        \\                listed rules (default: every qualifying rule;
        \\                --frag '' disables it entirely)
        \\  --ordered-maps  decode maps in strict CDDL wire order instead of
        \\                searching for keys (leaner, but rejects reordered
        \\                and canonically key-sorted senders)
        \\
        \\Paths for -d/-e default to siblings of -o: X_types.h -> X_decode.c etc.
        \\
    , .{});
    return 2;
}
