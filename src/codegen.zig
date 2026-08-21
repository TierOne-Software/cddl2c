//! C11 code generator for parsed CDDL.
//!
//! Generates up to three artifacts from a CDDL document:
//!   - a types header (structs/enums/typedefs, statically sized),
//!   - a decode C file + header (zcbor_decode.h based),
//!   - an encode C file + header (zcbor_encode.h based).
//!
//! Mapping summary (naming follows zcbor conventions: `_c` enum members,
//! `_choice`/`_present`/`_count` auxiliary fields, `decode_repeated_*`
//! helpers, `cbor_decode_X`/`cbor_encode_X` entry functions):
//!   - `&( a: 1, b: 2 )` and `&groupname`            -> C enum
//!   - choice of named int/tstr literals (`a / b`)   -> C enum
//!   - map/array/group rules                          -> C struct
//!   - heterogeneous type choices                     -> C struct with union + choice enum
//!   - scalar aliases (`port = uint .size 2`)         -> C typedef
//!   - tstr/bstr                                      -> struct zcbor_string (zero copy)
//!   - bounded repetitions (`0*4 x: uint`)            -> fixed array + `_count`
//!   - unbounded repetitions (`* x: uint`)            -> capped at default_max_qty
//!
//! Everything is caller-allocated; the generated code never allocates.

const std = @import("std");
const ast = @import("ast.zig");
const Parser = @import("Parser.zig");

pub const Options = struct {
    guard: []const u8 = "CDDL_TYPES_H__",
    /// Cap for `*`/`+` occurrences with no upper bound (like zcbor's
    /// --default-max-qty). Keeps all allocations static.
    default_max_qty: u64 = 3,
    /// Width used for `uint`/`int`/`nint` when nothing narrows them.
    default_int_bits: u8 = 32,
    /// Restrict generation to these rules plus everything they reference
    /// (tree-shaking); only the listed rules get public `cbor_decode_X`/
    /// `cbor_encode_X` wrappers. Null treats every rule as an entry.
    entry_rules: ?[]const []const u8 = null,
    xcode: XcodeOptions = .{},
};

pub const XcodeOptions = struct {
    decode: bool = false,
    encode: bool = false,
    /// Which rules get a fragmented-payload API (when they qualify).
    /// Null generates it for every qualifying rule; an explicit list
    /// restricts it (unused entry functions cost flash without
    /// -Wl,--gc-sections, and a smaller API surface is easier to audit).
    frag_rules: ?[]const []const u8 = null,
    /// Decode map members by searching for their keys instead of requiring
    /// wire order to match CDDL order. This is what CBOR maps mean
    /// semantically, and it accepts canonically key-sorted senders; the
    /// cost is O(n^2) key scanning on small maps. Disable for the leaner
    /// strict-order decode (`--ordered-maps`).
    unordered_maps: bool = true,
    /// Basenames used in generated #include directives and include guards.
    types_h: []const u8 = "cddl_types.h",
    decode_h: []const u8 = "cddl_decode.h",
    encode_h: []const u8 = "cddl_encode.h",
    decode_guard: []const u8 = "CDDL_DECODE_H__",
    encode_guard: []const u8 = "CDDL_ENCODE_H__",
};

pub const Output = struct {
    types_h: []const u8,
    decode_h: ?[]const u8 = null,
    decode_c: ?[]const u8 = null,
    encode_h: ?[]const u8 = null,
    encode_c: ?[]const u8 = null,
};

pub const Diagnostic = struct {
    message: []const u8 = "",
    context: []const u8 = "",
};

pub const Error = error{
    OutOfMemory,
    UnknownType,
    RecursiveType,
    Unsupported,
};

pub fn generate(gpa: std.mem.Allocator, doc: ast.Document, opts: Options) Error![]const u8 {
    var diag: Diagnostic = .{};
    return generateDiag(gpa, doc, opts, &diag);
}

/// Types-header-only entry point (kept for compatibility and tests).
pub fn generateDiag(
    gpa: std.mem.Allocator,
    doc: ast.Document,
    opts: Options,
    diag: *Diagnostic,
) Error![]const u8 {
    const out = try generateAll(gpa, doc, opts, diag);
    return out.types_h;
}

pub fn generateAll(
    gpa: std.mem.Allocator,
    doc: ast.Document,
    opts: Options,
    diag: *Diagnostic,
) Error!Output {
    var gen = Gen{
        .gpa = gpa,
        .doc = &doc,
        .opts = opts,
        .diag = diag,
        .xc = opts.xcode.decode or opts.xcode.encode,
    };

    if (opts.entry_rules) |entries| {
        for (entries) |name| {
            _ = try gen.resolveRule(name);
        }
    } else {
        for (doc.rules) |rule| {
            _ = try gen.resolveRule(rule.name);
        }
    }

    var out = Output{ .types_h = try gen.assembleTypes() };
    if (opts.xcode.decode) {
        out.decode_h = try gen.assembleXcodeHeader(.decode);
        out.decode_c = try gen.assembleXcodeSource(.decode);
    }
    if (opts.xcode.encode) {
        out.encode_h = try gen.assembleXcodeHeader(.encode);
        out.encode_c = try gen.assembleXcodeSource(.encode);
    }
    return out;
}

fn appendFmt(
    list: *std.ArrayList(u8),
    gpa: std.mem.Allocator,
    comptime fmt: []const u8,
    args: anytype,
) Error!void {
    const text = try std.fmt.allocPrint(gpa, fmt, args);
    try list.appendSlice(gpa, text);
}

const Mode = enum {
    decode,
    encode,

    fn prefix(m: Mode) []const u8 {
        return switch (m) {
            .decode => "decode",
            .encode => "encode",
        };
    }
};

// --- Value transcoding descriptions ------------------------------------------

/// How to decode/encode one value (attached to the C type of a member).
const XCall = union(enum) {
    /// Nothing known; treated as `skip` when a data item must be consumed.
    none,
    /// `any`: consume one element on decode; encoded as nil.
    skip,
    /// Call a generated function: decode_<stem>/encode_<stem>(state, ptr).
    call: FnRef,
    /// Direct zcbor primitive with optional validation.
    prim: Prim,
    /// Fully constrained value: expect on decode, put on encode.
    constant: ConstX,
    /// Tag wrapper: tag expect/put, then the inner value.
    tagged: TaggedX,
    /// `bstr .cbor X`: enter the wrapped byte string, transcode the typed
    /// inner value, and close the string again (one-shot, contiguous
    /// payload). The struct member is the inner type itself.
    cbor_wrap: struct { inner: *const XCall },
};

const FnRef = struct {
    stem: []const u8,
    /// True if the function takes no result (validation only).
    validator: bool = false,
};

const TaggedX = struct {
    tag: u64,
    inner: *const XCall,
};

const Prim = struct {
    kind: Kind,
    bits: u8 = 32,
    lo: ?i128 = null,
    hi: ?i128 = null,
    len_lo: ?u64 = null,
    len_hi: ?u64 = null,

    const Kind = enum { uint, int, boolean, f16, f32, f64, f16_32, f32_64, fany, tstr, bstr };
};

const ConstX = union(enum) {
    uint: u64,
    nint: i64,
    float: f64,
    tstr: []const u8,
    bstr: []const u8,
    nil,
    boolean: bool,
};

/// The C-facing result of resolving a CDDL rule.
const Named = struct {
    /// C tag or typedef name.
    name: []const u8,
    /// Function-name stem for generated xcoders.
    stem: []const u8,
    /// zcbor state backups needed to decode/encode this type.
    depth: usize = 0,
    framing: Framing = .group,
};

const Framing = enum { map, array, group };

const Typedef = struct {
    /// The typedef name, e.g. "port_t".
    name: []const u8,
    /// Function-name stem for generated xcoders.
    stem: []const u8,
    depth: usize = 0,
    /// For pure scalar aliases: the primitive call to inline at member
    /// sites instead of going through decode_<stem>/encode_<stem>.
    inline_x: ?XCall = null,
};

const Resolved = union(enum) {
    c_enum: Named,
    c_struct: Named,
    c_typedef: Typedef,
    /// Xcoder functions exist but there is no C type (fully constrained
    /// containers, e.g. a group of constants).
    validator: Named,
    constant: Constant, // literal rule; needs no storage
    none, // nothing at all (e.g. alias of `any`)
};

const Constant = union(enum) {
    int: i128,
    text: []const u8,
    bytes: []const u8,
    float: f64,
};

/// C type to use for one member, or no storage for fully-constrained values.
const CType = struct {
    text: []const u8 = "",
    storage: bool = true,
    note: []const u8 = "", // appended as a comment when non-empty
    x: XCall = .none,
    depth: usize = 0,
    /// For `bstr .cbor X` / `bstr .cborseq X`: the wrapped item type,
    /// used by the CBOR-in-CBOR fragmented API.
    cbor_item: ?*const CType = null,
};

const Gen = struct {
    gpa: std.mem.Allocator,
    doc: *const ast.Document,
    opts: Options,
    diag: *Diagnostic,
    xc: bool,
    /// Statement emitted when a zcbor call fails. "break;" while emitting a
    /// non-fatal attempt (optional-member decode), "return false;" otherwise.
    fail_action: []const u8 = "return false;",
    body: std.ArrayList(u8) = .empty,
    resolved: std.StringArrayHashMapUnmanaged(Resolved) = .empty,
    in_progress: std.StringArrayHashMapUnmanaged(void) = .empty,

    dec_protos: std.ArrayList(u8) = .empty,
    dec_fns: std.ArrayList(u8) = .empty,
    dec_pub_protos: std.ArrayList(u8) = .empty,
    dec_pub_fns: std.ArrayList(u8) = .empty,
    enc_protos: std.ArrayList(u8) = .empty,
    enc_fns: std.ArrayList(u8) = .empty,
    enc_pub_protos: std.ArrayList(u8) = .empty,
    enc_pub_fns: std.ArrayList(u8) = .empty,

    /// Per-struct walk context: type members + xcode function bodies.
    const Walk = struct {
        members: std.ArrayList(u8) = .empty,
        dec: std.ArrayList(u8) = .empty,
        /// Ordered decode of the occur-once members, kept alongside the
        /// search-based `dec` for the fragmented begin function.
        dec_frag: std.ArrayList(u8) = .empty,
        enc: std.ArrayList(u8) = .empty,
        keyed: bool,
        /// Key-search-based decoding (unordered maps).
        search: bool = false,
        /// Map has a "* any => any"-style extension point: unknown keys are
        /// skipped on decode instead of rejected.
        open_map: bool = false,
        max_depth: usize = 0,
        has_repeat: bool = false,
        enc_hint: u64 = 0,
        // Info about the last direct (non-group) member, used to decide
        // whether a fragmented-payload API can be generated for this struct.
        all_one: bool = true,
        last_direct: bool = false,
        last_ctype: CType = .{},
        last_name: []const u8 = "",
        last_key: ?ast.Key = null,
        last_dec_mark: usize = 0,
        last_dec_frag_mark: usize = 0,
        last_enc_mark: usize = 0,
    };

    fn err(self: *Gen, e: Error, message: []const u8, context: []const u8) Error {
        self.diag.* = .{ .message = message, .context = context };
        return e;
    }

    fn print(self: *Gen, comptime fmt: []const u8, args: anytype) Error!void {
        try appendFmt(&self.body, self.gpa, fmt, args);
    }

    fn protos(self: *Gen, mode: Mode) *std.ArrayList(u8) {
        return switch (mode) {
            .decode => &self.dec_protos,
            .encode => &self.enc_protos,
        };
    }

    fn fns(self: *Gen, mode: Mode) *std.ArrayList(u8) {
        return switch (mode) {
            .decode => &self.dec_fns,
            .encode => &self.enc_fns,
        };
    }

    // --- Output assembly -----------------------------------------------------

    fn assembleTypes(self: *Gen) Error![]const u8 {
        var out: std.ArrayList(u8) = .empty;
        try appendFmt(&out, self.gpa,
            \\/* Generated by cddl2c. Do not edit. */
            \\#ifndef {s}
            \\#define {s}
            \\
            \\#include <stdint.h>
            \\#include <stdbool.h>
            \\#include <stddef.h>
            \\#include "zcbor_common.h"
            \\
            \\
        , .{ self.opts.guard, self.opts.guard });
        try out.appendSlice(self.gpa, self.body.items);
        try appendFmt(&out, self.gpa, "#endif /* {s} */\n", .{self.opts.guard});
        return out.toOwnedSlice(self.gpa);
    }

    fn assembleXcodeHeader(self: *Gen, mode: Mode) Error![]const u8 {
        const guard = switch (mode) {
            .decode => self.opts.xcode.decode_guard,
            .encode => self.opts.xcode.encode_guard,
        };
        const pub_protos = switch (mode) {
            .decode => &self.dec_pub_protos,
            .encode => &self.enc_pub_protos,
        };
        var out: std.ArrayList(u8) = .empty;
        try appendFmt(&out, self.gpa,
            \\/* Generated by cddl2c. Do not edit. */
            \\#ifndef {s}
            \\#define {s}
            \\
            \\#include <stdint.h>
            \\#include <stddef.h>
            \\#include "{s}"
            \\
            \\#ifdef __cplusplus
            \\extern "C" {{
            \\#endif
            \\
            \\
        , .{ guard, guard, self.opts.xcode.types_h });
        try out.appendSlice(self.gpa, pub_protos.items);
        try appendFmt(&out, self.gpa,
            \\
            \\#ifdef __cplusplus
            \\}}
            \\#endif
            \\
            \\#endif /* {s} */
            \\
        , .{guard});
        return out.toOwnedSlice(self.gpa);
    }

    fn assembleXcodeSource(self: *Gen, mode: Mode) Error![]const u8 {
        const own_h = switch (mode) {
            .decode => self.opts.xcode.decode_h,
            .encode => self.opts.xcode.encode_h,
        };
        const zcbor_h = switch (mode) {
            .decode => "zcbor_decode.h",
            .encode => "zcbor_encode.h",
        };
        const pub_fns = switch (mode) {
            .decode => &self.dec_pub_fns,
            .encode => &self.enc_pub_fns,
        };
        var out: std.ArrayList(u8) = .empty;
        try appendFmt(&out, self.gpa,
            \\/* Generated by cddl2c. Do not edit. */
            \\#include <stdint.h>
            \\#include <stdbool.h>
            \\#include <stddef.h>
            \\#include <string.h>
            \\#include "zcbor_common.h"
            \\#include "{s}"
            \\#include "{s}"
            \\#include "{s}"
            \\
            \\
        , .{ zcbor_h, self.opts.xcode.types_h, own_h });
        try out.appendSlice(self.gpa, self.protos(mode).items);
        try out.appendSlice(self.gpa, "\n");
        try out.appendSlice(self.gpa, self.fns(mode).items);
        try out.appendSlice(self.gpa, pub_fns.items);
        return out.toOwnedSlice(self.gpa);
    }

    // --- Rule resolution -----------------------------------------------------

    fn resolveRule(self: *Gen, name: []const u8) Error!Resolved {
        if (self.resolved.get(name)) |r| return r;
        const rule = self.doc.find(name) orelse
            return self.err(error.UnknownType, "unknown type", name);
        if (self.in_progress.contains(name)) {
            return self.err(error.RecursiveType, "recursive type (cannot be statically allocated)", name);
        }
        if (self.in_progress.count() > 200) {
            return self.err(error.RecursiveType, "type reference chain too deep", name);
        }
        try self.in_progress.put(self.gpa, name, {});
        defer _ = self.in_progress.swapRemove(name);

        const result = switch (rule.value) {
            .group => |group| try self.emitStruct(try sanitize(self.gpa, name), group, .group, false),
            .type => |t| try self.resolveTypeRule(name, t),
        };
        try self.resolved.put(self.gpa, name, result);
        if (self.xc and self.isEntry(name)) try self.emitEntryFunctions(result);
        return result;
    }

    /// Whether a rule gets public entry wrappers.
    fn isEntry(self: *Gen, name: []const u8) bool {
        const entries = self.opts.entry_rules orelse return true;
        for (entries) |e| {
            if (std.mem.eql(u8, e, name)) return true;
        }
        return false;
    }

    /// Same, matched against a sanitized C name (for sites that no longer
    /// have the original CDDL rule name).
    fn isEntryCname(self: *Gen, cname: []const u8) Error!bool {
        const entries = self.opts.entry_rules orelse return true;
        for (entries) |e| {
            if (std.mem.eql(u8, try sanitize(self.gpa, e), cname)) return true;
        }
        return false;
    }

    fn resolveTypeRule(self: *Gen, name: []const u8, t: ast.Type) Error!Resolved {
        const cname = try sanitize(self.gpa, name);

        if (t.choices.len > 1) {
            if (try self.literalChoiceLabels(t)) |lc| {
                try self.emitEnum(cname, lc.labels, lc.kind);
                return .{ .c_enum = .{ .name = cname, .stem = cname } };
            }
            const depth = try self.emitUnionStruct(cname, t.choices);
            return .{ .c_struct = .{ .name = cname, .stem = cname, .depth = depth } };
        }

        const t1 = t.single().?;

        // Literal rules are constants: they need no C type of their own.
        if (t1.op == null) {
            switch (t1.base) {
                .uint => |v| return .{ .constant = .{ .int = v } },
                .nint => |v| return .{ .constant = .{ .int = v } },
                .float => |v| return .{ .constant = .{ .float = v } },
                .tstr => |v| return .{ .constant = .{ .text = v } },
                .bstr => |v| return .{ .constant = .{ .bytes = v } },
                else => {},
            }
        }

        switch (t1.base) {
            .map => |group| return self.emitStruct(cname, group, .map, true),
            .array => |group| return self.emitStruct(cname, group, .array, false),
            .enum_inline => |group| {
                try self.emitEnumFromGroup(cname, group.*);
                return .{ .c_enum = .{ .name = cname, .stem = cname } };
            },
            .enum_ref => |ref| {
                const group = try self.enumRefGroup(ref);
                try self.emitEnumFromGroup(cname, group);
                return .{ .c_enum = .{ .name = cname, .stem = cname } };
            },
            else => {},
        }

        // Everything else becomes a typedef of the member C type.
        const ctype = try self.typeCType(t, cname);
        if (!ctype.storage) return .none;
        const typedef_name = try std.fmt.allocPrint(self.gpa, "{s}_t", .{cname});
        if (ctype.note.len > 0) {
            try self.print("typedef {s} {s}; /* {s} */\n\n", .{ ctype.text, typedef_name, ctype.note });
        } else {
            try self.print("typedef {s} {s};\n\n", .{ ctype.text, typedef_name });
        }
        // Pure scalar aliases (no validation, no wrapped CBOR) are inlined
        // at member sites; their standalone functions are only needed when
        // the rule itself is a public entry.
        const inline_x: ?XCall = switch (ctype.x) {
            .prim => |p| if (p.lo == null and p.hi == null and p.len_lo == null and
                p.len_hi == null and ctype.cbor_item == null) ctype.x else null,
            else => null,
        };
        if (self.xc and (inline_x == null or self.isEntry(name))) {
            try self.emitTypedefFns(cname, typedef_name, ctype);
        }
        return .{ .c_typedef = .{
            .name = typedef_name,
            .stem = cname,
            .depth = ctype.depth,
            .inline_x = inline_x,
        } };
    }

    fn enumRefGroup(self: *Gen, ref: []const u8) Error!ast.Group {
        const target = self.doc.find(ref) orelse
            return self.err(error.UnknownType, "unknown group referenced by '&'", ref);
        return switch (target.value) {
            .group => |g| g,
            .type => self.err(error.Unsupported, "'&' must reference a group rule", ref),
        };
    }

    // --- Enums ---------------------------------------------------------------

    const EnumKind = enum { int_vals, text_pos, bytes_pos };

    const EnumLabel = struct {
        label: []const u8,
        value: i128,
        text: ?[]const u8 = null,
    };

    const LabeledChoices = struct {
        labels: []EnumLabel,
        kind: EnumKind,
    };

    /// If every choice is an int or tstr literal (directly or via a named
    /// rule), return enum labels for them. Int literals keep their values,
    /// tstr literals are numbered by position.
    fn literalChoiceLabels(self: *Gen, t: ast.Type) Error!?LabeledChoices {
        var labels: std.ArrayList(EnumLabel) = .empty;
        var seen_kind: ?EnumKind = null;

        for (t.choices) |t1| {
            if (t1.op != null) return null;
            var label: []const u8 = undefined;
            var value: ?i128 = null;
            var text: ?[]const u8 = null;
            var kind: EnumKind = .int_vals;

            switch (t1.base) {
                .uint => |v| {
                    value = v;
                    label = try std.fmt.allocPrint(self.gpa, "v{d}", .{v});
                },
                .nint => |v| {
                    value = v;
                    label = try std.fmt.allocPrint(self.gpa, "n{d}", .{-v});
                },
                .tstr => |v| {
                    kind = .text_pos;
                    text = v;
                    label = try sanitize(self.gpa, v);
                },
                .bstr => |v| {
                    kind = .bytes_pos;
                    text = v;
                    label = try sanitize(self.gpa, v);
                },
                .typename => |ref| {
                    const target = self.doc.find(ref) orelse return null;
                    const target_type = switch (target.value) {
                        .type => |tt| tt,
                        .group => return null,
                    };
                    const target_t1 = target_type.single() orelse return null;
                    if (target_t1.op != null) return null;
                    switch (target_t1.base) {
                        .uint => |v| value = v,
                        .nint => |v| value = v,
                        .tstr => |s| {
                            kind = .text_pos;
                            text = s;
                        },
                        .bstr => |s| {
                            kind = .bytes_pos;
                            text = s;
                        },
                        else => return null,
                    }
                    label = try sanitize(self.gpa, ref);
                },
                else => return null,
            }

            if (seen_kind) |k| {
                if (k != kind) return null; // mixed kinds cannot form one enum
            } else {
                seen_kind = kind;
            }
            try labels.append(self.gpa, .{ .label = label, .value = value orelse 0, .text = text });
        }

        if (labels.items.len == 0) return null;
        const kind = seen_kind.?;
        if (kind != .int_vals) {
            for (labels.items, 0..) |*l, i| l.value = @intCast(i);
        }
        return .{ .labels = try labels.toOwnedSlice(self.gpa), .kind = kind };
    }

    /// Enum from "&( ... )" / "&groupname" entries.
    fn emitEnumFromGroup(self: *Gen, cname: []const u8, group: ast.Group) Error!void {
        var labels: std.ArrayList(EnumLabel) = .empty;
        var next_value: i128 = 0;

        for (group.choices) |choice| {
            for (choice.entries) |entry| {
                if (!entry.occur.isOne()) {
                    return self.err(error.Unsupported, "occurrences make no sense inside '&()'", cname);
                }
                var label: []const u8 = undefined;
                var value: i128 = next_value;

                if (entry.key) |key| {
                    label = switch (key) {
                        .bareword => |w| try sanitize(self.gpa, w),
                        .value => |v| switch (v) {
                            .tstr => |s| try sanitize(self.gpa, s),
                            else => return self.err(error.Unsupported, "unsupported key in '&()'", cname),
                        },
                        .type => return self.err(error.Unsupported, "unsupported key in '&()'", cname),
                    };
                    const entry_type = switch (entry.value) {
                        .type => |et| et,
                        .inline_group => return self.err(error.Unsupported, "nested group in '&()'", cname),
                    };
                    if (entry_type.single()) |t1| {
                        switch (t1.base) {
                            .uint => |v| value = v,
                            .nint => |v| value = v,
                            else => {},
                        }
                    }
                } else {
                    // Keyless entry: a reference to a named literal, or a bare literal.
                    const entry_type = switch (entry.value) {
                        .type => |et| et,
                        .inline_group => return self.err(error.Unsupported, "nested group in '&()'", cname),
                    };
                    const t1 = entry_type.single() orelse
                        return self.err(error.Unsupported, "unsupported entry in '&()'", cname);
                    switch (t1.base) {
                        .uint => |v| {
                            value = v;
                            label = try std.fmt.allocPrint(self.gpa, "v{d}", .{v});
                        },
                        .nint => |v| {
                            value = v;
                            label = try std.fmt.allocPrint(self.gpa, "n{d}", .{-v});
                        },
                        .typename => |ref| {
                            label = try sanitize(self.gpa, ref);
                            const resolved = try self.resolveRule(ref);
                            switch (resolved) {
                                .constant => |con| switch (con) {
                                    .int => |v| value = v,
                                    else => {},
                                },
                                else => {},
                            }
                        },
                        else => return self.err(error.Unsupported, "unsupported entry in '&()'", cname),
                    }
                }

                try labels.append(self.gpa, .{ .label = label, .value = value });
                next_value = value + 1;
            }
        }
        try self.emitEnum(cname, labels.items, .int_vals);
    }

    fn emitEnum(self: *Gen, cname: []const u8, labels: []const EnumLabel, kind: EnumKind) Error!void {
        for (labels) |l| {
            // C11 6.7.2.2: enumeration constants must be representable as int.
            if (l.value > std.math.maxInt(i32) or l.value < std.math.minInt(i32)) {
                return self.err(error.Unsupported, "enum value does not fit a C int", cname);
            }
        }
        try self.print("enum {s} {{\n", .{cname});
        for (labels) |l| {
            try self.print("    {s}_{s}_c = {d},\n", .{ cname, l.label, l.value });
        }
        try self.print("}};\n\n", .{});
        if (self.xc) try self.emitEnumFns(cname, labels, kind);
    }

    fn emitEnumFns(self: *Gen, cname: []const u8, labels: []const EnumLabel, kind: EnumKind) Error!void {
        const gpa = self.gpa;

        // Decode.
        {
            const out = &self.dec_fns;
            try appendFmt(&self.dec_protos, gpa, "static bool decode_{s}(zcbor_state_t *state, void *void_result);\n", .{cname});
            try appendFmt(out, gpa, "static bool decode_{s}(zcbor_state_t *state, void *void_result)\n{{\n    enum {s} *result = void_result;\n", .{ cname, cname });
            switch (kind) {
                .int_vals => {
                    try appendFmt(out, gpa,
                        \\    int64_t val;
                        \\
                        \\    if (!zcbor_int64_decode(state, &val)) {{
                        \\        return false;
                        \\    }}
                        \\    switch (val) {{
                        \\
                    , .{});
                    var seen: std.ArrayList(i128) = .empty;
                    for (labels) |l| {
                        if (std.mem.indexOfScalar(i128, seen.items, l.value) != null) continue;
                        try seen.append(gpa, l.value);
                        try appendFmt(out, gpa, "    case {d}:\n", .{l.value});
                    }
                    try appendFmt(out, gpa,
                        \\        *result = (enum {s})val;
                        \\        return true;
                        \\    default:
                        \\        zcbor_error(state, ZCBOR_ERR_WRONG_VALUE);
                        \\        return false;
                        \\    }}
                        \\}}
                        \\
                        \\
                    , .{cname});
                },
                .text_pos, .bytes_pos => {
                    const decode_fn: []const u8 = if (kind == .text_pos) "zcbor_tstr_decode" else "zcbor_bstr_decode";
                    try appendFmt(out, gpa,
                        \\    struct zcbor_string val;
                        \\
                        \\    if (!{s}(state, &val)) {{
                        \\        return false;
                        \\    }}
                        \\
                    , .{decode_fn});
                    for (labels) |l| {
                        const text = l.text.?;
                        if (text.len == 0) {
                            try appendFmt(out, gpa, "    if (val.len == 0) {{\n", .{});
                        } else {
                            try appendFmt(out, gpa, "    if (val.len == {d} && memcmp(val.value, \"{s}\", {d}) == 0) {{\n", .{
                                text.len, try cEscape(gpa, text), text.len,
                            });
                        }
                        try appendFmt(out, gpa,
                            \\        *result = {s}_{s}_c;
                            \\        return true;
                            \\    }}
                            \\
                        , .{ cname, l.label });
                    }
                    try appendFmt(out, gpa,
                        \\    zcbor_error(state, ZCBOR_ERR_WRONG_VALUE);
                        \\    return false;
                        \\}}
                        \\
                        \\
                    , .{});
                },
            }
        }

        // Encode.
        {
            const out = &self.enc_fns;
            try appendFmt(&self.enc_protos, gpa, "static bool encode_{s}(zcbor_state_t *state, const void *void_input);\n", .{cname});
            try appendFmt(out, gpa, "static bool encode_{s}(zcbor_state_t *state, const void *void_input)\n{{\n    const enum {s} *input = void_input;\n", .{ cname, cname });
            switch (kind) {
                .int_vals => {
                    try appendFmt(out, gpa, "    switch (*input) {{\n", .{});
                    var seen: std.ArrayList(i128) = .empty;
                    for (labels) |l| {
                        if (std.mem.indexOfScalar(i128, seen.items, l.value) != null) continue;
                        try seen.append(gpa, l.value);
                        try appendFmt(out, gpa, "    case {s}_{s}_c:\n", .{ cname, l.label });
                    }
                    try appendFmt(out, gpa,
                        \\        break;
                        \\    default:
                        \\        zcbor_error(state, ZCBOR_ERR_BAD_ARG);
                        \\        return false;
                        \\    }}
                        \\    return zcbor_int64_put(state, (int64_t)*input);
                        \\}}
                        \\
                        \\
                    , .{});
                },
                .text_pos, .bytes_pos => {
                    const encode_fn: []const u8 = if (kind == .text_pos) "zcbor_tstr_encode_ptr" else "zcbor_bstr_encode_ptr";
                    try appendFmt(out, gpa, "    switch (*input) {{\n", .{});
                    for (labels) |l| {
                        const text = l.text.?;
                        try appendFmt(out, gpa,
                            \\    case {s}_{s}_c:
                            \\        return {s}(state, "{s}", {d});
                            \\
                        , .{ cname, l.label, encode_fn, try cEscape(gpa, text), text.len });
                    }
                    try appendFmt(out, gpa,
                        \\    default:
                        \\        zcbor_error(state, ZCBOR_ERR_BAD_ARG);
                        \\        return false;
                        \\    }}
                        \\}}
                        \\
                        \\
                    , .{});
                },
            }
        }
    }

    // --- Structs -------------------------------------------------------------

    fn emitStruct(self: *Gen, cname: []const u8, group: ast.Group, framing: Framing, keyed: bool) Error!Resolved {
        if (group.choices.len > 1) {
            return self.emitGroupChoiceStruct(cname, group, framing, keyed);
        }

        var walk = Walk{
            .keyed = keyed,
            // Group-choice alternatives (framing == .group with keys) stay
            // strictly ordered: union backtracking and key searching don't
            // compose.
            .search = self.opts.xcode.unordered_maps and framing == .map and keyed,
        };

        for (group.choices[0].entries, 0..) |entry, i| {
            try self.addMember(&walk, cname, entry, i);
        }

        const container: usize = if (framing == .group) 0 else 1;
        const depth = container + @max(walk.max_depth, @as(usize, if (walk.has_repeat) 1 else 0));
        const storage = walk.members.items.len > 0;

        if (storage) {
            try self.print("struct {s} {{\n{s}}};\n\n", .{ cname, walk.members.items });
        }
        if (self.xc) {
            try self.emitStructFns(cname, framing, &walk, storage, walk.enc_hint);
            try self.maybeEmitFragFns(cname, framing, &walk, storage, depth);
        }
        const named = Named{ .name = cname, .stem = cname, .depth = depth, .framing = framing };
        return if (storage) .{ .c_struct = named } else .{ .validator = named };
    }

    /// Generate the fragmented-payload API when the struct qualifies:
    /// a map/array whose members all occur exactly once and whose last member
    /// is a plain bstr/tstr. That member can then be streamed as fragments
    /// (large files, firmware images, logs) instead of being held in RAM.
    ///
    /// Fragmented encode relies on exact size hints: zcbor skips the
    /// canonical-mode header rewrite when the hint matches, which is what
    /// makes writing a container across multiple payload sections safe.
    /// The all-occur-once requirement keeps the element count exact.
    fn maybeEmitFragFns(self: *Gen, cname: []const u8, framing: Framing, walk: *Walk, storage: bool, depth: usize) Error!void {
        if (framing == .group or !storage or !walk.all_one or !walk.last_direct) return;
        // The fragmented API is public, so it follows --entry restrictions.
        if (!try self.isEntryCname(cname)) return;
        if (self.opts.xcode.frag_rules) |rules| {
            var listed = false;
            for (rules) |rule| {
                if (std.mem.eql(u8, try sanitize(self.gpa, rule), cname)) {
                    listed = true;
                    break;
                }
            }
            if (!listed) return;
        }
        const key: ?ast.Key = if (framing == .map) walk.last_key orelse return else null;
        const frag_dec = self.fragDecSlice(walk);

        // `bstr .cbor X` / `bstr .cborseq X`: CBOR-in-CBOR streaming.
        if (walk.last_ctype.cbor_item) |item| {
            if (item.storage) {
                try self.emitCborFragFns(cname, framing, walk, key, walk.enc_hint, depth, item, frag_dec);
            }
            return;
        }

        const p = switch (walk.last_ctype.x) {
            .prim => |p| p,
            else => return,
        };
        const fragkind: []const u8 = switch (p.kind) {
            .tstr => "tstr",
            .bstr => "bstr",
            else => return,
        };
        try self.emitFragFns(cname, framing, walk, fragkind, key, walk.enc_hint, depth, frag_dec);
    }

    /// The ordered decode statements preceding the last member, for the
    /// fragmented begin function. Unordered map structs keep a separate
    /// ordered variant (searches need the whole map in the buffer, which is
    /// exactly what fragmented payloads don't have).
    fn fragDecSlice(self: *Gen, walk: *Walk) []const u8 {
        _ = self;
        if (walk.search) return walk.dec_frag.items[0..walk.last_dec_frag_mark];
        return walk.dec.items[0..walk.last_dec_mark];
    }

    fn intCheck(self: *Gen, out: *std.ArrayList(u8), comptime callfmt: []const u8, args: anytype) Error!void {
        const call = try std.fmt.allocPrint(self.gpa, callfmt, args);
        try appendFmt(out, self.gpa,
            \\    if (!{s}) {{
            \\        int err = zcbor_pop_error(states);
            \\
            \\        return (err == ZCBOR_SUCCESS) ? ZCBOR_ERR_UNKNOWN : err;
            \\    }}
            \\
        , .{call});
    }

    fn emitFragFns(
        self: *Gen,
        cname: []const u8,
        framing: Framing,
        walk: *Walk,
        fragkind: []const u8,
        key: ?ast.Key,
        n_elems: u64,
        depth: usize,
        frag_dec: []const u8,
    ) Error!void {
        const gpa = self.gpa;
        const upper = try upperName(gpa, cname);
        const member = walk.last_name;
        const n_states = depth + 2;

        const doc = try std.fmt.allocPrint(gpa,
            \\
            \\/* Fragmented-payload API for '{s}': '{s}' streams through as fragments
            \\ * instead of residing in memory (large files, logs, firmware images).
            \\ * Call *_frag_begin with the first payload section (it must contain
            \\ * everything up to and including the '{s}' string header), then call
            \\ * *_frag_next/_frag_feed repeatedly. Whenever the current section is
            \\ * exhausted (zcbor_payload_at_end), feed the next one with
            \\ * zcbor_update_state(states, buf, len). Finish with *_frag_end.
            \\ * 'states' must hold at least {s}_FRAG_N_STATES elements and stay
            \\ * alive between these calls. */
            \\#define {s}_FRAG_N_STATES {d}
            \\
        , .{ cname, member, member, upper, upper, n_states });

        // Key statements for the fragmented member (map framing only).
        var dec_key: std.ArrayList(u8) = .empty;
        var enc_key: std.ArrayList(u8) = .empty;
        if (key) |k| {
            try self.keyStmts(&dec_key, .decode, k, cname, "    ");
            try self.keyStmts(&enc_key, .encode, k, cname, "    ");
        }

        // --- Decode side -----------------------------------------------------
        {
            const helper_sig = try std.fmt.allocPrint(gpa, "static bool decode_frag_begin_{s}(zcbor_state_t *state, struct {s} *result)", .{ cname, cname });
            try appendFmt(&self.dec_protos, gpa, "{s};\n", .{helper_sig});
            const out = &self.dec_fns;
            try appendFmt(out, gpa, "{s}\n{{\n    (void)result;\n", .{helper_sig});
            switch (framing) {
                .map => try self.stmtCheck(out, "    ", "zcbor_map_start_decode(state)", .{}),
                .array => try self.stmtCheck(out, "    ", "zcbor_list_start_decode(state)", .{}),
                .group => unreachable,
            }
            try out.appendSlice(gpa, frag_dec);
            try out.appendSlice(gpa, dec_key.items);
            try self.stmtCheck(out, "    ", "zcbor_{s}_fragments_start_decode(state)", .{fragkind});
            try appendFmt(out, gpa, "    return true;\n}}\n\n", .{});

            try self.dec_pub_protos.appendSlice(gpa, doc);
            const begin_sig = try std.fmt.allocPrint(gpa,
                "int cbor_decode_{s}_frag_begin(zcbor_state_t *states, size_t n_states,\n        const uint8_t *payload, size_t payload_len, struct {s} *result)", .{ cname, cname });
            const next_sig = try std.fmt.allocPrint(gpa,
                "int cbor_decode_{s}_frag_next(zcbor_state_t *states, struct zcbor_string_fragment *frag)", .{cname});
            const end_sig = try std.fmt.allocPrint(gpa,
                "int cbor_decode_{s}_frag_end(zcbor_state_t *states, size_t *payload_len_out)", .{cname});
            try appendFmt(&self.dec_pub_protos, gpa, "{s};\n{s};\n{s};\n", .{ begin_sig, next_sig, end_sig });

            const pub_out = &self.dec_pub_fns;
            try appendFmt(pub_out, gpa, "{s}\n{{\n    zcbor_new_decode_state(states, n_states, payload, payload_len, ZCBOR_LARGE_ELEM_COUNT, NULL, 0);\n", .{begin_sig});
            try self.intCheck(pub_out, "decode_frag_begin_{s}(states, result)", .{cname});
            try appendFmt(pub_out, gpa, "    return ZCBOR_SUCCESS;\n}}\n\n", .{});

            try appendFmt(pub_out, gpa, "{s}\n{{\n", .{next_sig});
            try self.intCheck(pub_out, "zcbor_str_fragment_decode(states, frag)", .{});
            try appendFmt(pub_out, gpa, "    return ZCBOR_SUCCESS;\n}}\n\n", .{});

            try appendFmt(pub_out, gpa, "{s}\n{{\n", .{end_sig});
            try self.intCheck(pub_out, "zcbor_str_fragments_end_decode(states)", .{});
            switch (framing) {
                .map => try self.intCheck(pub_out, "zcbor_map_end_decode(states)", .{}),
                .array => try self.intCheck(pub_out, "zcbor_list_end_decode(states)", .{}),
                .group => unreachable,
            }
            try appendFmt(pub_out, gpa,
                \\    if (payload_len_out != NULL) {{
                \\        *payload_len_out = (size_t)(states->payload - states->constant_state->curr_payload_section);
                \\    }}
                \\    return ZCBOR_SUCCESS;
                \\}}
                \\
                \\
            , .{});
        }

        // --- Encode side -----------------------------------------------------
        {
            const helper_sig = try std.fmt.allocPrint(gpa, "static bool encode_frag_begin_{s}(zcbor_state_t *state, const struct {s} *input, size_t total_len)", .{ cname, cname });
            try appendFmt(&self.enc_protos, gpa, "{s};\n", .{helper_sig});
            const out = &self.enc_fns;
            try appendFmt(out, gpa, "{s}\n{{\n    (void)input;\n", .{helper_sig});
            switch (framing) {
                .map => try self.stmtCheck(out, "    ", "zcbor_map_start_encode(state, {d})", .{n_elems}),
                .array => try self.stmtCheck(out, "    ", "zcbor_list_start_encode(state, {d})", .{n_elems}),
                .group => unreachable,
            }
            try out.appendSlice(gpa, walk.enc.items[0..walk.last_enc_mark]);
            try out.appendSlice(gpa, enc_key.items);
            try self.stmtCheck(out, "    ", "zcbor_{s}_fragments_start_encode(state, total_len)", .{fragkind});
            try appendFmt(out, gpa, "    return true;\n}}\n\n", .{});

            try self.enc_pub_protos.appendSlice(gpa, doc);
            const begin_sig = try std.fmt.allocPrint(gpa,
                "int cbor_encode_{s}_frag_begin(zcbor_state_t *states, size_t n_states,\n        uint8_t *payload, size_t payload_len, const struct {s} *input, size_t {s}_total_len)", .{ cname, cname, member });
            const feed_sig = try std.fmt.allocPrint(gpa,
                "int cbor_encode_{s}_frag_feed(zcbor_state_t *states, const uint8_t *data, size_t data_len, size_t *enc_len)", .{cname});
            const end_sig = try std.fmt.allocPrint(gpa,
                "int cbor_encode_{s}_frag_end(zcbor_state_t *states, size_t *payload_len_out)", .{cname});
            try appendFmt(&self.enc_pub_protos, gpa, "{s};\n{s};\n{s};\n", .{ begin_sig, feed_sig, end_sig });

            const pub_out = &self.enc_pub_fns;
            try appendFmt(pub_out, gpa, "{s}\n{{\n    zcbor_new_encode_state(states, n_states, payload, payload_len, 0);\n", .{begin_sig});
            try self.intCheck(pub_out, "encode_frag_begin_{s}(states, input, {s}_total_len)", .{ cname, member });
            try appendFmt(pub_out, gpa, "    return ZCBOR_SUCCESS;\n}}\n\n", .{});

            try appendFmt(pub_out, gpa,
                \\{s}
                \\{{
                \\    struct zcbor_string frag = {{ .value = data, .len = data_len }};
                \\
                \\
            , .{feed_sig});
            try self.intCheck(pub_out, "zcbor_str_fragment_encode(states, &frag, enc_len)", .{});
            try appendFmt(pub_out, gpa, "    return ZCBOR_SUCCESS;\n}}\n\n", .{});

            try appendFmt(pub_out, gpa, "{s}\n{{\n", .{end_sig});
            try self.intCheck(pub_out, "zcbor_str_fragments_end_encode(states)", .{});
            switch (framing) {
                .map => try self.intCheck(pub_out, "zcbor_map_end_encode(states, {d})", .{n_elems}),
                .array => try self.intCheck(pub_out, "zcbor_list_end_encode(states, {d})", .{n_elems}),
                .group => unreachable,
            }
            try appendFmt(pub_out, gpa,
                \\    if (payload_len_out != NULL) {{
                \\        *payload_len_out = (size_t)(states->payload - states->constant_state->curr_payload_section);
                \\    }}
                \\    return ZCBOR_SUCCESS;
                \\}}
                \\
                \\
            , .{});
        }
    }

    /// "//" group choices: one sub-struct per choice + a choice enum, decoded
    /// by trying each alternative.
    fn emitGroupChoiceStruct(self: *Gen, cname: []const u8, group: ast.Group, framing: Framing, keyed: bool) Error!Resolved {
        const gpa = self.gpa;
        var union_body: std.ArrayList(u8) = .empty;
        var enum_body: std.ArrayList(u8) = .empty;
        var uchoices: std.ArrayList(UChoice) = .empty;
        var max_child: usize = 0;
        var enc_hint: u64 = 0;

        for (group.choices, 0..) |choice, i| {
            const label = try self.choiceLabel(choice, i);
            const sub_name = try std.fmt.allocPrint(gpa, "{s}_{s}", .{ cname, label });
            const sub = try self.emitStruct(sub_name, .{
                .choices = @constCast(&[_]ast.GroupChoice{choice}),
            }, .group, keyed);
            var target: ?[]const u8 = null;
            var x: XCall = .none;
            switch (sub) {
                .c_struct => |named| {
                    try appendFmt(&union_body, gpa, "        struct {s} {s};\n", .{ sub_name, label });
                    target = label;
                    x = .{ .call = .{ .stem = named.stem } };
                    max_child = @max(max_child, named.depth);
                },
                .validator => |named| {
                    x = .{ .call = .{ .stem = named.stem, .validator = true } };
                    max_child = @max(max_child, named.depth);
                },
                else => {},
            }
            var hint: u64 = 0;
            for (choice.entries) |entry| hint +|= entry.occur.max orelse self.opts.default_max_qty;
            enc_hint = @max(enc_hint, hint);
            try appendFmt(&enum_body, gpa, "        {s}_{s}_c,\n", .{ cname, label });
            try uchoices.append(gpa, .{ .label = label, .x = x, .target = target });
        }

        try self.print("struct {s} {{\n    union {{\n{s}    }};\n    enum {s}_choice {{\n{s}    }} choice;\n}};\n\n", .{
            cname, union_body.items, cname, enum_body.items,
        });

        const container: usize = if (framing == .group) 0 else 1;
        const depth = container + 1 + max_child;
        if (self.xc) {
            try self.emitUnionFns(cname, framing, uchoices.items, enc_hint);
        }
        return .{ .c_struct = .{ .name = cname, .stem = cname, .depth = depth, .framing = framing } };
    }

    fn choiceLabel(self: *Gen, choice: ast.GroupChoice, index: usize) Error![]const u8 {
        if (choice.entries.len > 0) {
            if (choice.entries[0].key) |key| switch (key) {
                .bareword => |w| return sanitize(self.gpa, w),
                .value => |v| switch (v) {
                    .tstr => |s| return sanitize(self.gpa, s),
                    else => {},
                },
                else => {},
            };
        }
        return std.fmt.allocPrint(self.gpa, "alt{d}", .{index});
    }

    fn addMember(self: *Gen, walk: *Walk, parent: []const u8, entry: ast.Entry, index: usize) Error!void {
        const entry_type: ast.Type = switch (entry.value) {
            .inline_group => |g| {
                if (entry.occur.isOne() and g.choices.len == 1) {
                    // Plain "( ... )" splices its entries into the parent.
                    for (g.choices[0].entries, 0..) |sub_entry, i| {
                        try self.addMember(walk, parent, sub_entry, index * 100 + i);
                    }
                    return;
                }
                // Repeated or choice group: emit it as its own struct.
                const sub_name = try std.fmt.allocPrint(self.gpa, "{s}_group{d}", .{ parent, index });
                const member_name = try std.fmt.allocPrint(self.gpa, "group{d}", .{index});
                const sub = try self.emitStruct(sub_name, g.*, .group, walk.keyed);
                const ctype: CType = switch (sub) {
                    .c_struct => |named| .{
                        .text = try std.fmt.allocPrint(self.gpa, "struct {s}", .{sub_name}),
                        .x = .{ .call = .{ .stem = named.stem } },
                        .depth = named.depth,
                    },
                    .validator => |named| .{
                        .storage = false,
                        .x = .{ .call = .{ .stem = named.stem, .validator = true } },
                        .depth = named.depth,
                    },
                    else => .{ .storage = false, .x = .skip },
                };
                try self.emitMemberLines(&walk.members, entry.occur, ctype, member_name);
                walk.last_direct = false;
                if (!entry.occur.isOne()) walk.all_one = false;
                if (self.xc) try self.memberXcode(walk, parent, member_name, sub_name, ctype, entry.occur, null);
                walk.max_depth = @max(walk.max_depth, ctype.depth);
                if (!entry.occur.isOne()) walk.has_repeat = true;
                walk.enc_hint +|= entry.occur.max orelse self.opts.default_max_qty;
                return;
            },
            .type => |t| t,
        };

        // A repeated type-keyed entry ("* any => any", "* tstr => any", ...)
        // is a CDDL extension point: it declares the map open. No storage is
        // generated; unknown pairs are skipped at decode time (their types
        // are not validated) and never emitted at encode time.
        if (walk.keyed and !entry.occur.isOne()) {
            if (entry.key) |k| {
                if (k == .type) {
                    walk.open_map = true;
                    walk.all_one = false; // disqualifies the fragmented API
                    return;
                }
            }
        }

        const member_name = try self.memberName(entry, entry_type, index);
        const hint = try std.fmt.allocPrint(self.gpa, "{s}_{s}", .{ parent, member_name });
        const ctype = try self.typeCType(entry_type, hint);
        try self.emitMemberLines(&walk.members, entry.occur, ctype, member_name);

        walk.last_direct = true;
        walk.last_ctype = ctype;
        walk.last_name = member_name;
        walk.last_key = entry.key;
        walk.last_dec_mark = walk.dec.items.len;
        walk.last_dec_frag_mark = walk.dec_frag.items.len;
        walk.last_enc_mark = walk.enc.items.len;
        if (!entry.occur.isOne()) walk.all_one = false;

        if (self.xc) {
            const key: ?ast.Key = if (walk.keyed) entry.key else null;
            try self.memberXcode(walk, parent, member_name, hint, ctype, entry.occur, key);
        }
        walk.max_depth = @max(walk.max_depth, ctype.depth);
        if (!entry.occur.isOne()) walk.has_repeat = true;
        walk.enc_hint +|= entry.occur.max orelse self.opts.default_max_qty;
    }

    fn emitMemberLines(
        self: *Gen,
        members: *std.ArrayList(u8),
        occur: ast.Occur,
        ctype: CType,
        name: []const u8,
    ) Error!void {
        const gpa = self.gpa;
        const note_sep: []const u8 = if (ctype.note.len > 0) " /* " else "";
        const note_end: []const u8 = if (ctype.note.len > 0) " */" else "";

        if (occur.isOne()) {
            if (!ctype.storage) {
                try appendFmt(members, gpa, "    /* '{s}' is fully constrained by the CDDL; no storage needed */\n", .{name});
                return;
            }
            try appendFmt(members, gpa, "    {s} {s};{s}{s}{s}\n", .{ ctype.text, name, note_sep, ctype.note, note_end });
        } else if (occur.isOptional()) {
            if (ctype.storage) {
                try appendFmt(members, gpa, "    {s} {s};{s}{s}{s}\n", .{ ctype.text, name, note_sep, ctype.note, note_end });
            }
            try appendFmt(members, gpa, "    bool {s}_present;\n", .{name});
        } else {
            const capped = occur.max == null;
            const max = occur.max orelse self.opts.default_max_qty;
            if (max == 0) return;
            if (ctype.storage) {
                if (capped) {
                    try appendFmt(members, gpa, "    {s} {s}[{d}]; /* unbounded in CDDL; capped */\n", .{ ctype.text, name, max });
                } else {
                    try appendFmt(members, gpa, "    {s} {s}[{d}];{s}{s}{s}\n", .{ ctype.text, name, max, note_sep, ctype.note, note_end });
                }
            }
            try appendFmt(members, gpa, "    size_t {s}_count;\n", .{name});
        }
    }

    fn memberName(self: *Gen, entry: ast.Entry, entry_type: ast.Type, index: usize) Error![]const u8 {
        if (entry.key) |key| switch (key) {
            .bareword => |w| return sanitize(self.gpa, w),
            .value => |v| switch (v) {
                .tstr => |s| return sanitize(self.gpa, s),
                .uint => |u| return std.fmt.allocPrint(self.gpa, "k{d}", .{u}),
                .nint => |n| return std.fmt.allocPrint(self.gpa, "kn{d}", .{-n}),
                else => {},
            },
            .type => {},
        };
        // No usable key: derive from the type.
        if (entry_type.single()) |t1| switch (t1.base) {
            .typename => |n| {
                const sanitized = try sanitize(self.gpa, n);
                if (self.builtinCType(n) != null) {
                    return std.fmt.allocPrint(self.gpa, "_{s}", .{sanitized});
                }
                return sanitized;
            },
            else => {},
        };
        return std.fmt.allocPrint(self.gpa, "field{d}", .{index});
    }

    // --- Member C types ------------------------------------------------------

    fn typeCType(self: *Gen, t: ast.Type, hint: []const u8) Error!CType {
        if (t.choices.len > 1) {
            if (try self.literalChoiceLabels(t)) |lc| {
                try self.emitEnum(hint, lc.labels, lc.kind);
                return .{
                    .text = try std.fmt.allocPrint(self.gpa, "enum {s}", .{hint}),
                    .x = .{ .call = .{ .stem = hint } },
                };
            }
            const depth = try self.emitUnionStruct(hint, t.choices);
            return .{
                .text = try std.fmt.allocPrint(self.gpa, "struct {s}", .{hint}),
                .x = .{ .call = .{ .stem = hint } },
                .depth = depth,
            };
        }
        return self.type1CType(t.single().?.*, hint);
    }

    fn type1CType(self: *Gen, t1: ast.Type1, hint: []const u8) Error!CType {
        if (t1.op) |op| return self.opCType(t1.base, op, hint);

        switch (t1.base) {
            .uint => |v| return .{ .storage = false, .x = .{ .constant = .{ .uint = v } } },
            .nint => |v| return .{ .storage = false, .x = .{ .constant = .{ .nint = v } } },
            .float => |v| return .{ .storage = false, .x = .{ .constant = .{ .float = v } } },
            .tstr => |v| return .{ .storage = false, .x = .{ .constant = .{ .tstr = v } } },
            .bstr => |v| return .{ .storage = false, .x = .{ .constant = .{ .bstr = v } } },
            .typename => |name| return self.typenameCType(name),
            .unwrap => |name| {
                if (self.xc) {
                    return self.err(error.Unsupported, "'~' (unwrap) is not supported for decode/encode generation", name);
                }
                return self.typenameCType(name);
            },
            .paren => |inner| return self.typeCType(inner.*, hint),
            .tagged => |tagged| {
                var inner = try self.typeCType(tagged.inner.*, hint);
                if (tagged.tag) |tag| {
                    const inner_x = try self.gpa.create(XCall);
                    inner_x.* = inner.x;
                    inner.x = .{ .tagged = .{ .tag = tag, .inner = inner_x } };
                } else if (self.xc) {
                    return self.err(error.Unsupported, "'#6' without a tag number is not supported for decode/encode generation", hint);
                }
                return inner;
            },
            .map => |group| {
                const resolved = try self.emitStruct(hint, group, .map, true);
                return self.structRefCType(resolved, hint);
            },
            .array => |group| {
                const resolved = try self.emitStruct(hint, group, .array, false);
                return self.structRefCType(resolved, hint);
            },
            .enum_inline => |group| {
                try self.emitEnumFromGroup(hint, group.*);
                return .{
                    .text = try std.fmt.allocPrint(self.gpa, "enum {s}", .{hint}),
                    .x = .{ .call = .{ .stem = hint } },
                };
            },
            .enum_ref => |ref| {
                const resolved = try self.resolveRule(ref);
                switch (resolved) {
                    .c_enum => |named| return .{
                        .text = try std.fmt.allocPrint(self.gpa, "enum {s}", .{named.name}),
                        .x = .{ .call = .{ .stem = named.stem } },
                    },
                    else => {},
                }
                const group = try self.enumRefGroup(ref);
                try self.emitEnumFromGroup(hint, group);
                return .{
                    .text = try std.fmt.allocPrint(self.gpa, "enum {s}", .{hint}),
                    .x = .{ .call = .{ .stem = hint } },
                };
            },
            .major => |m| return self.majorCType(m),
            .any => return .{ .storage = false, .note = "any: skipped, not stored", .x = .skip },
        }
    }

    fn structRefCType(self: *Gen, resolved: Resolved, hint: []const u8) Error!CType {
        return switch (resolved) {
            .c_struct => |named| .{
                .text = try std.fmt.allocPrint(self.gpa, "struct {s}", .{hint}),
                .x = .{ .call = .{ .stem = named.stem } },
                .depth = named.depth,
            },
            .validator => |named| .{
                .storage = false,
                .x = .{ .call = .{ .stem = named.stem, .validator = true } },
                .depth = named.depth,
            },
            else => .{ .storage = false, .x = .skip },
        };
    }

    fn typenameCType(self: *Gen, name: []const u8) Error!CType {
        if (self.builtinCType(name)) |ct| return ct;
        const resolved = try self.resolveRule(name);
        return switch (resolved) {
            .c_enum => |named| .{
                .text = try std.fmt.allocPrint(self.gpa, "enum {s}", .{named.name}),
                .x = .{ .call = .{ .stem = named.stem } },
            },
            .c_struct => |named| .{
                .text = try std.fmt.allocPrint(self.gpa, "struct {s}", .{named.name}),
                .x = .{ .call = .{ .stem = named.stem } },
                .depth = named.depth,
            },
            .c_typedef => |td| .{
                .text = td.name,
                .x = td.inline_x orelse .{ .call = .{ .stem = td.stem } },
                .depth = td.depth,
            },
            .validator => |named| .{
                .storage = false,
                .x = .{ .call = .{ .stem = named.stem, .validator = true } },
                .depth = named.depth,
            },
            .constant => |con| .{ .storage = false, .x = .{ .constant = constToX(con) } },
            .none => .{ .storage = false, .x = .skip },
        };
    }

    fn builtinCType(self: *Gen, name: []const u8) ?CType {
        const zs_t = CType{ .text = "struct zcbor_string", .x = .{ .prim = .{ .kind = .tstr } } };
        const zs_b = CType{ .text = "struct zcbor_string", .x = .{ .prim = .{ .kind = .bstr } } };
        const map = .{
            .{ "uint", CType{ .text = self.defaultUint(), .x = .{ .prim = .{ .kind = .uint, .bits = self.opts.default_int_bits } } } },
            .{ "nint", CType{ .text = self.defaultInt(), .x = .{ .prim = .{ .kind = .int, .bits = self.opts.default_int_bits, .hi = -1 } } } },
            .{ "int", CType{ .text = self.defaultInt(), .x = .{ .prim = .{ .kind = .int, .bits = self.opts.default_int_bits } } } },
            .{ "bstr", zs_b },
            .{ "bytes", zs_b },
            .{ "tstr", zs_t },
            .{ "text", zs_t },
            .{ "bool", CType{ .text = "bool", .x = .{ .prim = .{ .kind = .boolean } } } },
            .{ "float16", CType{ .text = "float", .x = .{ .prim = .{ .kind = .f16 } } } },
            .{ "float32", CType{ .text = "float", .x = .{ .prim = .{ .kind = .f32 } } } },
            .{ "float64", CType{ .text = "double", .x = .{ .prim = .{ .kind = .f64 } } } },
            .{ "float16-32", CType{ .text = "float", .x = .{ .prim = .{ .kind = .f16_32 } } } },
            .{ "float32-64", CType{ .text = "double", .x = .{ .prim = .{ .kind = .f32_64 } } } },
            .{ "float", CType{ .text = "double", .x = .{ .prim = .{ .kind = .fany } } } },
            .{ "number", CType{ .text = "double", .note = "number: int or float", .x = .{ .prim = .{ .kind = .fany } } } },
            .{ "nil", CType{ .storage = false, .x = .{ .constant = .nil } } },
            .{ "null", CType{ .storage = false, .x = .{ .constant = .nil } } },
            .{ "undefined", CType{ .storage = false, .x = .skip } },
            .{ "true", CType{ .storage = false, .x = .{ .constant = .{ .boolean = true } } } },
            .{ "false", CType{ .storage = false, .x = .{ .constant = .{ .boolean = false } } } },
            .{ "any", CType{ .storage = false, .note = "any: skipped, not stored", .x = .skip } },
            .{ "eb64url", zs_t },
            .{ "eb64legacy", zs_t },
            .{ "eb16", zs_t },
            .{ "encoded-cbor", zs_b },
            .{ "uri", zs_t },
            .{ "b64url", zs_t },
            .{ "b64legacy", zs_t },
            .{ "regexp", zs_t },
            .{ "mime-message", zs_t },
            .{ "tdate", zs_t },
        };
        inline for (map) |pair| {
            if (std.mem.eql(u8, name, pair[0])) return pair[1];
        }
        return null;
    }

    fn defaultUint(self: *Gen) []const u8 {
        return switch (self.opts.default_int_bits) {
            8 => "uint8_t",
            16 => "uint16_t",
            64 => "uint64_t",
            else => "uint32_t",
        };
    }

    fn defaultInt(self: *Gen) []const u8 {
        return switch (self.opts.default_int_bits) {
            8 => "int8_t",
            16 => "int16_t",
            64 => "int64_t",
            else => "int32_t",
        };
    }

    fn majorCType(self: *Gen, m: ast.MajorAi) Error!CType {
        return switch (m.major) {
            0 => .{ .text = self.defaultUint(), .x = .{ .prim = .{ .kind = .uint, .bits = self.opts.default_int_bits } } },
            1 => .{ .text = self.defaultInt(), .x = .{ .prim = .{ .kind = .int, .bits = self.opts.default_int_bits, .hi = -1 } } },
            2 => .{ .text = "struct zcbor_string", .x = .{ .prim = .{ .kind = .bstr } } },
            3 => .{ .text = "struct zcbor_string", .x = .{ .prim = .{ .kind = .tstr } } },
            7 => if (m.ai) |ai| switch (ai) {
                20 => CType{ .storage = false, .x = .{ .constant = .{ .boolean = false } } },
                21 => CType{ .storage = false, .x = .{ .constant = .{ .boolean = true } } },
                22 => CType{ .storage = false, .x = .{ .constant = .nil } },
                23 => CType{ .storage = false, .x = .skip },
                25 => CType{ .text = "float", .x = .{ .prim = .{ .kind = .f16 } } },
                26 => CType{ .text = "float", .x = .{ .prim = .{ .kind = .f32 } } },
                27 => CType{ .text = "double", .x = .{ .prim = .{ .kind = .f64 } } },
                else => CType{ .text = "uint8_t", .note = "CBOR simple value", .x = .skip, .storage = false },
            } else CType{ .text = "uint8_t", .note = "CBOR simple value", .x = .skip, .storage = false },
            else => .{ .storage = false, .note = "unsupported major type; skipped", .x = .skip },
        };
    }

    /// Apply a range or control operator, narrowing integer widths.
    fn opCType(self: *Gen, base: ast.Type2, op: ast.OpExpr, hint: []const u8) Error!CType {
        switch (op.kind) {
            .range_incl, .range_excl => {
                const lo = intValueOf(base) orelse
                    return self.err(error.Unsupported, "range bounds must be integer literals", hint);
                var hi = intValueOf(op.rhs.*) orelse
                    return self.err(error.Unsupported, "range bounds must be integer literals", hint);
                if (op.kind == .range_excl) hi -= 1;
                if (hi < lo) {
                    return self.err(error.Unsupported, "empty integer range", hint);
                }
                return self.intCType(lo, hi);
            },
            .ctl => {
                if (std.mem.eql(u8, op.ctl, "size")) {
                    if (isIntBase(base)) {
                        const bytes = intValueOf(op.rhs.*) orelse
                            return self.err(error.Unsupported, ".size on an integer needs an integer literal", hint);
                        if (bytes < 0 or bytes > 8) {
                            return self.err(error.Unsupported, ".size on an integer must be between 0 and 8", hint);
                        }
                        const signed = isSignedBase(base);
                        const bits = bitsForSize(@intCast(bytes));
                        return .{
                            .text = intTypeForSize(@intCast(bytes), signed),
                            .x = .{ .prim = .{ .kind = if (signed) .int else .uint, .bits = bits } },
                        };
                    }
                    // .size on strings constrains the byte length; both
                    // `.size N` and `.size (lo..hi)` are supported.
                    const bounds = try self.sizeBounds(op.rhs.*, hint);
                    var inner = try self.type1CType(.{ .base = base }, hint);
                    switch (inner.x) {
                        .prim => |*p| {
                            p.len_lo = @intCast(bounds.lo);
                            p.len_hi = @intCast(bounds.hi);
                        },
                        else => {},
                    }
                    return inner;
                }
                if (std.mem.eql(u8, op.ctl, "cbor")) {
                    // `bstr .cbor X`: the member IS the typed inner value;
                    // one-shot decode/encode enters and exits the wrapping
                    // byte string. The inner type also serves as the item
                    // type of the CBOR-in-CBOR fragmented API.
                    const item_hint = try std.fmt.allocPrint(self.gpa, "{s}_item", .{hint});
                    const item_ct = try self.gpa.create(CType);
                    item_ct.* = try self.type1CType(.{ .base = op.rhs.* }, item_hint);
                    const inner_x = try self.gpa.create(XCall);
                    inner_x.* = item_ct.x;
                    return .{
                        .text = item_ct.text,
                        .storage = item_ct.storage,
                        .x = .{ .cbor_wrap = .{ .inner = inner_x } },
                        .depth = item_ct.depth + 1, // bstr enter/exit takes a backup
                        .cbor_item = item_ct,
                    };
                }
                if (std.mem.eql(u8, op.ctl, "cborseq")) {
                    // `bstr .cborseq [* T]`: an unbounded CBOR sequence of T.
                    // Stored opaque (zero copy); streamed item by item via
                    // the CBOR-in-CBOR fragmented API.
                    const item_hint = try std.fmt.allocPrint(self.gpa, "{s}_item", .{hint});
                    const item_ct = try self.gpa.create(CType);
                    if (seqElementType(op.rhs.*)) |elem_type| {
                        item_ct.* = try self.typeCType(elem_type, item_hint);
                    } else {
                        item_ct.* = try self.type1CType(.{ .base = op.rhs.* }, item_hint);
                    }
                    return .{
                        .text = "struct zcbor_string",
                        .note = "holds a CBOR sequence; stream it via the *_frag_* API",
                        .x = .{ .prim = .{ .kind = .bstr } },
                        .cbor_item = item_ct,
                    };
                }
                if (std.mem.eql(u8, op.ctl, "le") or std.mem.eql(u8, op.ctl, "lt")) {
                    var hi = intValueOf(op.rhs.*) orelse
                        return self.err(error.Unsupported, "bound needs an integer literal", hint);
                    if (std.mem.eql(u8, op.ctl, "lt")) hi -= 1;
                    const lo: i128 = if (isSignedBase(base)) std.math.minInt(i64) else 0;
                    if (isIntBase(base)) return self.intCType(lo, hi);
                }
                if (std.mem.eql(u8, op.ctl, "ge") or std.mem.eql(u8, op.ctl, "gt")) {
                    var lo = intValueOf(op.rhs.*) orelse
                        return self.err(error.Unsupported, "bound needs an integer literal", hint);
                    if (std.mem.eql(u8, op.ctl, "gt")) lo += 1;
                    const hi: i128 = if (isSignedBase(base)) std.math.maxInt(i64) else std.math.maxInt(u64);
                    if (isIntBase(base)) return self.intCType(lo, hi);
                }
                // Unknown/validation-only control: keep the base representation.
                return self.type1CType(.{ .base = base }, hint);
            },
        }
    }

    /// Length bounds from a `.size` controller: an integer literal or a
    /// parenthesized integer range (`.size (1..32)`).
    fn sizeBounds(self: *Gen, rhs: ast.Type2, hint: []const u8) Error!struct { lo: i128, hi: i128 } {
        if (intValueOf(rhs)) |v| {
            if (v < 0) return self.err(error.Unsupported, ".size must not be negative", hint);
            return .{ .lo = v, .hi = v };
        }
        if (rhs == .paren) {
            if (rhs.paren.single()) |t1| {
                if (t1.op) |op| {
                    if (op.kind == .range_incl or op.kind == .range_excl) {
                        const lo = intValueOf(t1.base) orelse
                            return self.err(error.Unsupported, ".size range bounds must be integer literals", hint);
                        var hi = intValueOf(op.rhs.*) orelse
                            return self.err(error.Unsupported, ".size range bounds must be integer literals", hint);
                        if (op.kind == .range_excl) hi -= 1;
                        if (lo < 0 or hi < lo) {
                            return self.err(error.Unsupported, "invalid .size range", hint);
                        }
                        return .{ .lo = lo, .hi = hi };
                    }
                }
            }
        }
        return self.err(error.Unsupported, ".size needs an integer literal or (lo..hi) range", hint);
    }

    fn intCType(self: *Gen, lo: i128, hi: i128) Error!CType {
        _ = self;
        const text = intTypeForBounds(lo, hi);
        const signed = lo < 0;
        const bits: u8 = if (std.mem.eql(u8, text, "uint8_t") or std.mem.eql(u8, text, "int8_t"))
            8
        else if (std.mem.eql(u8, text, "uint16_t") or std.mem.eql(u8, text, "int16_t"))
            16
        else if (std.mem.eql(u8, text, "uint32_t") or std.mem.eql(u8, text, "int32_t"))
            32
        else
            64;
        var p = Prim{ .kind = if (signed) .int else .uint, .bits = bits };
        // Only keep bounds that the C type itself does not already enforce.
        const tmin: i128 = if (signed) -(@as(i128, 1) << @intCast(bits - 1)) else 0;
        const tmax: i128 = if (signed)
            (@as(i128, 1) << @intCast(bits - 1)) - 1
        else
            (@as(i128, 1) << @intCast(bits)) - 1;
        if (lo > tmin) p.lo = lo;
        if (hi < tmax) p.hi = hi;
        return .{ .text = text, .x = .{ .prim = p } };
    }

    // --- Union structs (type-level "/" choices) ------------------------------

    const UChoice = struct {
        label: []const u8,
        x: XCall,
        target: ?[]const u8, // union member name, or null when no storage
    };

    fn emitUnionStruct(self: *Gen, cname: []const u8, choices: []const ast.Type1) Error!usize {
        const gpa = self.gpa;
        var union_body: std.ArrayList(u8) = .empty;
        var enum_body: std.ArrayList(u8) = .empty;
        var uchoices: std.ArrayList(UChoice) = .empty;
        var max_child: usize = 0;

        for (choices, 0..) |t1, i| {
            const label = try self.unionLabel(t1, i);
            const hint = try std.fmt.allocPrint(gpa, "{s}_{s}", .{ cname, label });
            const ctype = try self.type1CType(t1, hint);
            max_child = @max(max_child, ctype.depth);
            if (ctype.storage) {
                try appendFmt(&union_body, gpa, "        {s} {s};\n", .{ ctype.text, label });
            }
            try appendFmt(&enum_body, gpa, "        {s}_{s}_c,\n", .{ cname, label });
            try uchoices.append(gpa, .{
                .label = label,
                .x = ctype.x,
                .target = if (ctype.storage) label else null,
            });
        }

        if (union_body.items.len == 0) {
            return self.err(error.Unsupported, "type choice has no storable alternative; use literals of one kind to form an enum", cname);
        }
        try self.print("struct {s} {{\n    union {{\n{s}    }};\n    enum {s}_choice {{\n{s}    }} choice;\n}};\n\n", .{
            cname, union_body.items, cname, enum_body.items,
        });

        if (self.xc) {
            try self.emitUnionFns(cname, .group, uchoices.items, 1);
        }
        return 1 + max_child;
    }

    fn unionLabel(self: *Gen, t1: ast.Type1, index: usize) Error![]const u8 {
        switch (t1.base) {
            .typename => |n| {
                const sanitized = try sanitize(self.gpa, n);
                if (self.builtinCType(n) != null) {
                    return std.fmt.allocPrint(self.gpa, "_{s}", .{sanitized});
                }
                return sanitized;
            },
            .uint => |v| return std.fmt.allocPrint(self.gpa, "v{d}", .{v}),
            .nint => |v| return std.fmt.allocPrint(self.gpa, "n{d}", .{-v}),
            .tstr => |s| return sanitize(self.gpa, s),
            .map => return std.fmt.allocPrint(self.gpa, "map{d}", .{index}),
            .array => return std.fmt.allocPrint(self.gpa, "array{d}", .{index}),
            else => return std.fmt.allocPrint(self.gpa, "alt{d}", .{index}),
        }
    }

    // --- Xcode emission ------------------------------------------------------

    /// Statements for decoding/encoding one value.
    /// `target` is a pointer expression (e.g. "&result->name"), or null when
    /// the value needs no storage.
    fn valueStmts(
        self: *Gen,
        out: *std.ArrayList(u8),
        mode: Mode,
        x: XCall,
        target: ?[]const u8,
        indent: []const u8,
    ) Error!void {
        const gpa = self.gpa;
        switch (x) {
            .none, .skip => switch (mode) {
                .decode => try self.stmtCheck(out, indent, "zcbor_any_skip(state, NULL)", .{}),
                .encode => try self.stmtCheck(out, indent, "zcbor_nil_put(state, NULL) /* 'any': encoded as nil */", .{}),
            },
            .call => |ref| {
                const arg = if (ref.validator) "NULL" else target orelse "NULL";
                try self.stmtCheck(out, indent, "{s}_{s}(state, {s})", .{ mode.prefix(), ref.stem, arg });
            },
            .tagged => |tx| {
                if (tx.tag > std.math.maxInt(u32)) {
                    return self.err(error.Unsupported, "CBOR tag exceeds zcbor's uint32 tag API", "");
                }
                switch (mode) {
                    .decode => try self.stmtCheck(out, indent, "zcbor_tag_expect(state, {d})", .{tx.tag}),
                    .encode => try self.stmtCheck(out, indent, "zcbor_tag_put(state, {d})", .{tx.tag}),
                }
                try self.valueStmts(out, mode, tx.inner.*, target, indent);
            },
            .cbor_wrap => |cw| {
                switch (mode) {
                    .decode => try self.stmtCheck(out, indent, "zcbor_bstr_start_decode(state, NULL)", .{}),
                    .encode => try self.stmtCheck(out, indent, "zcbor_bstr_start_encode(state)", .{}),
                }
                try self.valueStmts(out, mode, cw.inner.*, target, indent);
                switch (mode) {
                    .decode => try self.stmtCheck(out, indent, "zcbor_bstr_end_decode(state)", .{}),
                    .encode => try self.stmtCheck(out, indent, "zcbor_bstr_end_encode(state, NULL)", .{}),
                }
            },
            .constant => |con| switch (con) {
                .uint => |v| switch (mode) {
                    .decode => try self.stmtCheck(out, indent, "zcbor_uint64_expect(state, {d})", .{v}),
                    .encode => try self.stmtCheck(out, indent, "zcbor_uint64_put(state, {d})", .{v}),
                },
                .nint => |v| switch (mode) {
                    .decode => try self.stmtCheck(out, indent, "zcbor_int64_expect(state, {d})", .{v}),
                    .encode => try self.stmtCheck(out, indent, "zcbor_int64_put(state, {d})", .{v}),
                },
                .float => |v| switch (mode) {
                    .decode => try self.stmtCheck(out, indent, "zcbor_float_expect(state, {d})", .{v}),
                    .encode => try self.stmtCheck(out, indent, "zcbor_float64_put(state, {d})", .{v}),
                },
                .boolean => |v| switch (mode) {
                    .decode => try self.stmtCheck(out, indent, "zcbor_bool_expect(state, {})", .{v}),
                    .encode => try self.stmtCheck(out, indent, "zcbor_bool_put(state, {})", .{v}),
                },
                .nil => switch (mode) {
                    .decode => try self.stmtCheck(out, indent, "zcbor_nil_expect(state, NULL)", .{}),
                    .encode => try self.stmtCheck(out, indent, "zcbor_nil_put(state, NULL)", .{}),
                },
                .tstr => |s| switch (mode) {
                    .decode => try self.stmtCheck(out, indent, "zcbor_tstr_expect_ptr(state, \"{s}\", {d})", .{ try cEscape(gpa, s), s.len }),
                    .encode => try self.stmtCheck(out, indent, "zcbor_tstr_encode_ptr(state, \"{s}\", {d})", .{ try cEscape(gpa, s), s.len }),
                },
                .bstr => |b| {
                    const lit = try bstrLiteral(gpa, b);
                    switch (mode) {
                        .decode => try self.stmtCheck(out, indent, "zcbor_bstr_expect(state, &(struct zcbor_string){{ .value = {s}, .len = {d} }})", .{ lit, b.len }),
                        .encode => try self.stmtCheck(out, indent, "zcbor_bstr_encode(state, &(struct zcbor_string){{ .value = {s}, .len = {d} }})", .{ lit, b.len }),
                    }
                },
            },
            .prim => |p| try self.primStmts(out, mode, p, target.?, indent),
        }
    }

    fn primStmts(self: *Gen, out: *std.ArrayList(u8), mode: Mode, p: Prim, target: []const u8, indent: []const u8) Error!void {
        const val = try derefExpr(self.gpa, target);

        if (mode == .encode) try self.primChecks(out, p, val, indent);

        const call: []const u8 = switch (p.kind) {
            .uint => try std.fmt.allocPrint(self.gpa, "zcbor_uint{d}_{s}(state, {s})", .{ p.bits, mode.prefix(), target }),
            .int => try std.fmt.allocPrint(self.gpa, "zcbor_int{d}_{s}(state, {s})", .{ p.bits, mode.prefix(), target }),
            .boolean => try std.fmt.allocPrint(self.gpa, "zcbor_bool_{s}(state, {s})", .{ mode.prefix(), target }),
            .f16 => try std.fmt.allocPrint(self.gpa, "zcbor_float16_{s}(state, {s})", .{ mode.prefix(), target }),
            .f32 => try std.fmt.allocPrint(self.gpa, "zcbor_float32_{s}(state, {s})", .{ mode.prefix(), target }),
            .f64 => try std.fmt.allocPrint(self.gpa, "zcbor_float64_{s}(state, {s})", .{ mode.prefix(), target }),
            .f16_32 => switch (mode) {
                .decode => try std.fmt.allocPrint(self.gpa, "zcbor_float16_32_decode(state, {s})", .{target}),
                .encode => try std.fmt.allocPrint(self.gpa, "zcbor_float32_encode(state, {s})", .{target}),
            },
            .f32_64 => switch (mode) {
                .decode => try std.fmt.allocPrint(self.gpa, "zcbor_float32_64_decode(state, {s})", .{target}),
                .encode => try std.fmt.allocPrint(self.gpa, "zcbor_float64_encode(state, {s})", .{target}),
            },
            .fany => switch (mode) {
                .decode => try std.fmt.allocPrint(self.gpa, "zcbor_float_decode(state, {s})", .{target}),
                .encode => try std.fmt.allocPrint(self.gpa, "zcbor_float64_encode(state, {s})", .{target}),
            },
            .tstr => try std.fmt.allocPrint(self.gpa, "zcbor_tstr_{s}(state, {s})", .{ mode.prefix(), target }),
            .bstr => try std.fmt.allocPrint(self.gpa, "zcbor_bstr_{s}(state, {s})", .{ mode.prefix(), target }),
        };
        try self.stmtCheck(out, indent, "{s}", .{call});

        if (mode == .decode) try self.primChecks(out, p, val, indent);
    }

    fn primChecks(self: *Gen, out: *std.ArrayList(u8), p: Prim, val: []const u8, indent: []const u8) Error!void {
        const gpa = self.gpa;
        if (p.lo) |lo| {
            try appendFmt(out, gpa,
                "{s}if ({s} < {d}) {{\n{s}    zcbor_error(state, ZCBOR_ERR_WRONG_RANGE);\n{s}    {s}\n{s}}}\n",
                .{ indent, val, lo, indent, indent, self.fail_action, indent },
            );
        }
        if (p.hi) |hi| {
            try appendFmt(out, gpa,
                "{s}if ({s} > {d}) {{\n{s}    zcbor_error(state, ZCBOR_ERR_WRONG_RANGE);\n{s}    {s}\n{s}}}\n",
                .{ indent, val, hi, indent, indent, self.fail_action, indent },
            );
        }
        if (p.len_lo) |lo| {
            if (lo > 0) {
                try appendFmt(out, gpa,
                    "{s}if ({s}.len < {d}) {{\n{s}    zcbor_error(state, ZCBOR_ERR_WRONG_RANGE);\n{s}    {s}\n{s}}}\n",
                    .{ indent, val, lo, indent, indent, self.fail_action, indent },
                );
            }
        }
        if (p.len_hi) |hi| {
            try appendFmt(out, gpa,
                "{s}if ({s}.len > {d}) {{\n{s}    zcbor_error(state, ZCBOR_ERR_WRONG_RANGE);\n{s}    {s}\n{s}}}\n",
                .{ indent, val, hi, indent, indent, self.fail_action, indent },
            );
        }
    }

    fn stmtCheck(self: *Gen, out: *std.ArrayList(u8), indent: []const u8, comptime callfmt: []const u8, args: anytype) Error!void {
        const call = try std.fmt.allocPrint(self.gpa, callfmt, args);
        try appendFmt(out, self.gpa, "{s}if (!{s}) {{\n{s}    {s}\n{s}}}\n", .{ indent, call, indent, self.fail_action, indent });
    }

    fn keyStmts(self: *Gen, out: *std.ArrayList(u8), mode: Mode, key: ast.Key, ctx: []const u8, indent: []const u8) Error!void {
        const gpa = self.gpa;
        switch (key) {
            .bareword => |w| switch (mode) {
                .decode => try self.stmtCheck(out, indent, "zcbor_tstr_expect_ptr(state, \"{s}\", {d})", .{ try cEscape(gpa, w), w.len }),
                .encode => try self.stmtCheck(out, indent, "zcbor_tstr_encode_ptr(state, \"{s}\", {d})", .{ try cEscape(gpa, w), w.len }),
            },
            .value => |v| switch (v) {
                .tstr => |s| switch (mode) {
                    .decode => try self.stmtCheck(out, indent, "zcbor_tstr_expect_ptr(state, \"{s}\", {d})", .{ try cEscape(gpa, s), s.len }),
                    .encode => try self.stmtCheck(out, indent, "zcbor_tstr_encode_ptr(state, \"{s}\", {d})", .{ try cEscape(gpa, s), s.len }),
                },
                .uint => |u| switch (mode) {
                    .decode => try self.stmtCheck(out, indent, "zcbor_uint64_expect(state, {d})", .{u}),
                    .encode => try self.stmtCheck(out, indent, "zcbor_uint64_put(state, {d})", .{u}),
                },
                .nint => |n| switch (mode) {
                    .decode => try self.stmtCheck(out, indent, "zcbor_int64_expect(state, {d})", .{n}),
                    .encode => try self.stmtCheck(out, indent, "zcbor_int64_put(state, {d})", .{n}),
                },
                .bstr => |b| {
                    const lit = try bstrLiteral(gpa, b);
                    switch (mode) {
                        .decode => try self.stmtCheck(out, indent, "zcbor_bstr_expect(state, &(struct zcbor_string){{ .value = {s}, .len = {d} }})", .{ lit, b.len }),
                        .encode => try self.stmtCheck(out, indent, "zcbor_bstr_encode(state, &(struct zcbor_string){{ .value = {s}, .len = {d} }})", .{ lit, b.len }),
                    }
                },
                else => return self.err(error.Unsupported, "unsupported member key type", ctx),
            },
            .type => return self.err(error.Unsupported, "type member keys need map-search decoding (unsupported)", ctx),
        }
    }

    /// Xcode statements for one struct member (both modes).
    fn memberXcode(
        self: *Gen,
        walk: *Walk,
        parent: []const u8,
        name: []const u8,
        hint: []const u8,
        ctype: CType,
        occur: ast.Occur,
        key: ?ast.Key,
    ) Error!void {
        _ = parent;
        const gpa = self.gpa;
        const x: XCall = if (ctype.x == .none) .skip else ctype.x;
        const min = occur.min;
        const max = occur.max orelse self.opts.default_max_qty;
        if (!occur.isOne() and !occur.isOptional() and max == 0) return;

        // --- Encode (identical in ordered and unordered modes) --------------
        if (occur.isOne()) {
            if (key) |k| try self.keyStmts(&walk.enc, .encode, k, hint, "    ");
            const enc_target = if (ctype.storage)
                try std.fmt.allocPrint(gpa, "&input->{s}", .{name})
            else
                null;
            try self.valueStmts(&walk.enc, .encode, x, enc_target, "    ");
        } else if (occur.isOptional()) {
            try appendFmt(&walk.enc, gpa, "    if (input->{s}_present) {{\n", .{name});
            if (key) |k| try self.keyStmts(&walk.enc, .encode, k, hint, "        ");
            const enc_target = if (ctype.storage)
                try std.fmt.allocPrint(gpa, "&input->{s}", .{name})
            else
                null;
            try self.valueStmts(&walk.enc, .encode, x, enc_target, "        ");
            try appendFmt(&walk.enc, gpa, "    }}\n", .{});
        } else {
            try self.emitRepeatedFn(.encode, hint, ctype, key, x);
            if (ctype.storage) {
                try self.stmtCheck(&walk.enc, "    ", "zcbor_multi_encode_minmax({d}, {d}, &input->{s}_count, encode_repeated_{s}, state, input->{s}, sizeof(input->{s}[0]))", .{ min, max, name, hint, name, name });
            } else {
                try self.stmtCheck(&walk.enc, "    ", "zcbor_multi_encode_minmax({d}, {d}, &input->{s}_count, encode_repeated_{s}, state, NULL, 0)", .{ min, max, name, hint });
            }
        }

        if (walk.keyed and key == null) {
            // A bare type cannot form a key-value pair; the encoding would
            // produce an odd number of map elements.
            return self.err(error.Unsupported, "map members need literal keys", hint);
        }

        // --- Decode: key search (unordered maps) ----------------------------
        if (walk.search) {
            const k = key.?;
            try self.memberDecSearch(&walk.dec, name, ctype, occur, k, x);
            // Ordered variant of the occur-once members, for the fragmented
            // begin function (searches need the whole map in one buffer).
            if (occur.isOne()) {
                try self.keyStmts(&walk.dec_frag, .decode, k, hint, "    ");
                const t = if (ctype.storage)
                    try std.fmt.allocPrint(gpa, "&result->{s}", .{name})
                else
                    null;
                try self.valueStmts(&walk.dec_frag, .decode, x, t, "    ");
            }
            return;
        }

        // --- Decode: strict wire order --------------------------------------
        if (occur.isOne()) {
            if (key) |k| try self.keyStmts(&walk.dec, .decode, k, hint, "    ");
            const dec_target = if (ctype.storage)
                try std.fmt.allocPrint(gpa, "&result->{s}", .{name})
            else
                null;
            try self.valueStmts(&walk.dec, .decode, x, dec_target, "    ");
        } else if (occur.isOptional()) {
            // Inline attempt with rollback: payload, element count, and any
            // state backups pushed by a partially decoded value.
            try appendFmt(&walk.dec, gpa,
                \\    {{
                \\        zcbor_state_t state_bak = *state;
                \\        size_t backup_num = (state->constant_state != NULL)
                \\                ? state->constant_state->current_backup : 0;
                \\        bool present = false;
                \\
                \\        do {{
                \\
            , .{});
            self.fail_action = "break;";
            if (key) |k| try self.keyStmts(&walk.dec, .decode, k, hint, "            ");
            const dec_target = if (ctype.storage)
                try std.fmt.allocPrint(gpa, "&result->{s}", .{name})
            else
                null;
            try self.valueStmts(&walk.dec, .decode, x, dec_target, "            ");
            self.fail_action = "return false;";
            try appendFmt(&walk.dec, gpa,
                \\            present = true;
                \\        }} while (0);
                \\        if (!present) {{
                \\            /* Roll back everything a partial attempt may have
                \\             * touched: payload position, element counts, map
                \\             * bookkeeping, and any state backups it pushed. */
                \\            if (state->constant_state != NULL) {{
                \\                state->constant_state->current_backup = backup_num;
                \\            }}
                \\            *state = state_bak;
                \\        }}
                \\        result->{s}_present = present;
                \\    }}
                \\
            , .{name});
        } else {
            try self.emitRepeatedFn(.decode, hint, ctype, key, x);
            if (ctype.storage) {
                try self.stmtCheck(&walk.dec, "    ", "zcbor_multi_decode_w_backup({d}, {d}, &result->{s}_count, decode_repeated_{s}, state, result->{s}, sizeof(result->{s}[0]))", .{ min, max, name, hint, name, name });
            } else {
                try self.stmtCheck(&walk.dec, "    ", "zcbor_multi_decode_w_backup({d}, {d}, &result->{s}_count, decode_repeated_{s}, state, NULL, 0)", .{ min, max, name, hint });
            }
        }
    }

    /// C expression that searches the current unordered map for `key`,
    /// leaving the state at the corresponding value when found.
    fn searchExpr(self: *Gen, key: ast.Key, ctx: []const u8) Error![]const u8 {
        const gpa = self.gpa;
        switch (key) {
            .bareword => |w| return std.fmt.allocPrint(gpa, "zcbor_search_key_tstr_ptr(state, \"{s}\", {d})", .{ try cEscape(gpa, w), w.len }),
            .value => |v| switch (v) {
                .tstr => |s| return std.fmt.allocPrint(gpa, "zcbor_search_key_tstr_ptr(state, \"{s}\", {d})", .{ try cEscape(gpa, s), s.len }),
                .bstr => |b| return std.fmt.allocPrint(gpa, "zcbor_search_key_bstr_ptr(state, (const char *){s}, {d})", .{ try bstrLiteral(gpa, b), b.len }),
                .uint => |u| return std.fmt.allocPrint(gpa, "zcbor_search_key_uint(state, {d})", .{u}),
                .nint => |n| return std.fmt.allocPrint(gpa, "zcbor_search_key_int(state, {d})", .{n}),
                else => return self.err(error.Unsupported, "unsupported member key type", ctx),
            },
            .type => return self.err(error.Unsupported, "type member keys need a custom key decoder (unsupported)", ctx),
        }
    }

    /// Search-based decode of one map member (unordered maps). Runs under
    /// manually_process_elem, so every consumed pair is marked explicitly.
    fn memberDecSearch(
        self: *Gen,
        out: *std.ArrayList(u8),
        name: []const u8,
        ctype: CType,
        occur: ast.Occur,
        key: ast.Key,
        x: XCall,
    ) Error!void {
        const gpa = self.gpa;
        const expr = try self.searchExpr(key, name);

        if (occur.isOne()) {
            try self.stmtCheck(out, "    ", "{s}", .{expr});
            const t = if (ctype.storage)
                try std.fmt.allocPrint(gpa, "&result->{s}", .{name})
            else
                null;
            try self.valueStmts(out, .decode, x, t, "    ");
            try self.stmtCheck(out, "    ", "zcbor_elem_processed(state)", .{});
            return;
        }

        if (occur.isOptional()) {
            try appendFmt(out, gpa, "    result->{s}_present = {s};\n    if (result->{s}_present) {{\n", .{ name, expr, name });
            const t = if (ctype.storage)
                try std.fmt.allocPrint(gpa, "&result->{s}", .{name})
            else
                null;
            try self.valueStmts(out, .decode, x, t, "        ");
            try self.stmtCheck(out, "        ", "zcbor_elem_processed(state)", .{});
            try appendFmt(out, gpa, "    }}\n", .{});
            return;
        }

        const max = occur.max orelse self.opts.default_max_qty;
        try appendFmt(out, gpa, "    result->{s}_count = 0;\n    while (result->{s}_count < {d} && {s}) {{\n", .{ name, name, max, expr });
        const t = if (ctype.storage)
            try std.fmt.allocPrint(gpa, "&result->{s}[result->{s}_count]", .{ name, name })
        else
            null;
        try self.valueStmts(out, .decode, x, t, "        ");
        try self.stmtCheck(out, "        ", "zcbor_elem_processed(state)", .{});
        try appendFmt(out, gpa, "        result->{s}_count++;\n    }}\n", .{name});
        if (occur.min > 0) {
            try appendFmt(out, gpa, "    if (result->{s}_count < {d}) {{\n        zcbor_error(state, ZCBOR_ERR_ITERATIONS);\n        return false;\n    }}\n", .{ name, occur.min });
        }
    }

    /// Helper handling one occurrence of a (possibly keyed) member.
    fn emitRepeatedFn(self: *Gen, mode: Mode, stem: []const u8, ctype: CType, key: ?ast.Key, x: XCall) Error!void {
        const gpa = self.gpa;
        const constness: []const u8 = if (mode == .encode) "const " else "";
        const argname: []const u8 = if (mode == .encode) "input" else "result";
        const sig = try std.fmt.allocPrint(gpa, "static bool {s}_repeated_{s}(zcbor_state_t *state, {s}void *void_{s})", .{ mode.prefix(), stem, constness, argname });

        try appendFmt(self.protos(mode), gpa, "{s};\n", .{sig});
        const out = self.fns(mode);
        try appendFmt(out, gpa, "{s}\n{{\n", .{sig});
        if (ctype.storage) {
            try appendFmt(out, gpa, "    {s}{s} *{s} = void_{s};\n", .{ constness, ctype.text, argname, argname });
        } else {
            try appendFmt(out, gpa, "    (void)void_{s};\n", .{argname});
        }
        if (key) |k| try self.keyStmts(out, mode, k, stem, "    ");
        const target = if (ctype.storage) argname else null;
        try self.valueStmts(out, mode, x, target, "    ");
        try appendFmt(out, gpa, "    return true;\n}}\n\n", .{});
    }

    /// Emit both mode functions for a struct with the given walked bodies.
    fn emitStructFns(self: *Gen, cname: []const u8, framing: Framing, walk: *Walk, storage: bool, enc_hint: u64) Error!void {
        const gpa = self.gpa;
        inline for (.{ Mode.decode, Mode.encode }) |mode| {
            const constness: []const u8 = if (mode == .encode) "const " else "";
            const argname: []const u8 = if (mode == .encode) "input" else "result";
            // Exact zcbor_decoder_t/zcbor_encoder_t signatures: these
            // functions are passed to zcbor's function-pointer APIs, and a
            // call through a mismatched pointer type is undefined behavior
            // (flagged by -fsanitize=function). The typed view is a local.
            const sig = try std.fmt.allocPrint(gpa, "static bool {s}_{s}(zcbor_state_t *state, {s}void *void_{s})", .{ mode.prefix(), cname, constness, argname });

            try appendFmt(self.protos(mode), gpa, "{s};\n", .{sig});
            const out = self.fns(mode);
            try appendFmt(out, gpa, "{s}\n{{\n", .{sig});
            if (storage) {
                try appendFmt(out, gpa, "    {s}struct {s} *{s} = void_{s};\n", .{ constness, cname, argname, argname });
            } else {
                try appendFmt(out, gpa, "    (void)void_{s};\n", .{argname});
            }
            switch (framing) {
                .map => switch (mode) {
                    .decode => {
                        if (walk.search) {
                            // Key searching keeps a running processed-count;
                            // this code marks pairs explicitly, so make sure
                            // the state agrees regardless of how it was set up.
                            try appendFmt(out, gpa,
                                "    if (state->constant_state != NULL) {{\n        state->constant_state->manually_process_elem = true;\n    }}\n", .{});
                            try self.stmtCheck(out, "    ", "zcbor_unordered_map_start_decode(state)", .{});
                        } else {
                            try self.stmtCheck(out, "    ", "zcbor_map_start_decode(state)", .{});
                        }
                    },
                    .encode => try self.stmtCheck(out, "    ", "zcbor_map_start_encode(state, {d})", .{enc_hint}),
                },
                .array => switch (mode) {
                    .decode => try self.stmtCheck(out, "    ", "zcbor_list_start_decode(state)", .{}),
                    .encode => try self.stmtCheck(out, "    ", "zcbor_list_start_encode(state, {d})", .{enc_hint}),
                },
                .group => {},
            }
            const body = switch (mode) {
                .decode => &walk.dec,
                .encode => &walk.enc,
            };
            try out.appendSlice(gpa, body.items);
            switch (framing) {
                .map => switch (mode) {
                    .decode => {
                        if (walk.open_map) {
                            try self.stmtCheck(out, "    ", "zcbor_map_end_decode_skip_unknown(state)", .{});
                        } else if (walk.search) {
                            try self.stmtCheck(out, "    ", "zcbor_unordered_map_end_decode(state)", .{});
                        } else {
                            try self.stmtCheck(out, "    ", "zcbor_map_end_decode(state)", .{});
                        }
                    },
                    .encode => try self.stmtCheck(out, "    ", "zcbor_map_end_encode(state, {d})", .{enc_hint}),
                },
                .array => switch (mode) {
                    .decode => try self.stmtCheck(out, "    ", "zcbor_list_end_decode(state)", .{}),
                    .encode => try self.stmtCheck(out, "    ", "zcbor_list_end_encode(state, {d})", .{enc_hint}),
                },
                .group => {},
            }
            try appendFmt(out, gpa, "    return true;\n}}\n\n", .{});
        }
    }

    /// Union decode (try each choice) and encode (switch on choice).
    fn emitUnionFns(self: *Gen, cname: []const u8, framing: Framing, uchoices: []const UChoice, enc_hint: u64) Error!void {
        const gpa = self.gpa;

        // Decode: one try-helper per choice, then the chain.
        for (uchoices) |uc| {
            const sig = try std.fmt.allocPrint(gpa, "static bool decode_try_{s}_{s}(zcbor_state_t *state, struct {s} *result)", .{ cname, uc.label, cname });
            try appendFmt(&self.dec_protos, gpa, "{s};\n", .{sig});
            try appendFmt(&self.dec_fns, gpa, "{s}\n{{\n", .{sig});
            const target = if (uc.target) |t|
                try std.fmt.allocPrint(gpa, "&result->{s}", .{t})
            else
                null;
            try self.valueStmts(&self.dec_fns, .decode, uc.x, target, "    ");
            try appendFmt(&self.dec_fns, gpa, "    result->choice = {s}_{s}_c;\n    return true;\n}}\n\n", .{ cname, uc.label });
        }

        {
            const sig = try std.fmt.allocPrint(gpa, "static bool decode_{s}(zcbor_state_t *state, void *void_result)", .{cname});
            try appendFmt(&self.dec_protos, gpa, "{s};\n", .{sig});
            const out = &self.dec_fns;
            try appendFmt(out, gpa, "{s}\n{{\n    struct {s} *result = void_result;\n", .{ sig, cname });
            switch (framing) {
                .map => try self.stmtCheck(out, "    ", "zcbor_map_start_decode(state)", .{}),
                .array => try self.stmtCheck(out, "    ", "zcbor_list_start_decode(state)", .{}),
                .group => {},
            }
            try self.stmtCheck(out, "    ", "zcbor_union_start_code(state)", .{});
            try appendFmt(out, gpa, "    size_t union_backup = state->constant_state->current_backup;\n    bool ok = false;\n\n", .{});
            for (uchoices) |uc| {
                // A failed alternative can leave orphaned state backups
                // (e.g. from an entered container); drop them so the
                // restore in zcbor_union_elem_code acts on the union's own
                // backup.
                try appendFmt(out, gpa, "    if (!ok) {{\n        state->constant_state->current_backup = union_backup;\n        if (zcbor_union_elem_code(state) && decode_try_{s}_{s}(state, result)) {{\n            ok = true;\n        }}\n    }}\n", .{ cname, uc.label });
            }
            try appendFmt(out, gpa, "    state->constant_state->current_backup = union_backup;\n", .{});
            try appendFmt(out, gpa,
                \\    if (!zcbor_union_end_code(state)) {{
                \\        return false;
                \\    }}
                \\    if (!ok) {{
                \\        zcbor_error(state, ZCBOR_ERR_WRONG_TYPE);
                \\        return false;
                \\    }}
                \\
            , .{});
            switch (framing) {
                .map => try self.stmtCheck(out, "    ", "zcbor_map_end_decode(state)", .{}),
                .array => try self.stmtCheck(out, "    ", "zcbor_list_end_decode(state)", .{}),
                .group => {},
            }
            try appendFmt(out, gpa, "    return true;\n}}\n\n", .{});
        }

        // Encode: switch dispatch.
        {
            const sig = try std.fmt.allocPrint(gpa, "static bool encode_{s}(zcbor_state_t *state, const void *void_input)", .{cname});
            try appendFmt(&self.enc_protos, gpa, "{s};\n", .{sig});
            const out = &self.enc_fns;
            try appendFmt(out, gpa, "{s}\n{{\n    const struct {s} *input = void_input;\n", .{ sig, cname });
            switch (framing) {
                .map => try self.stmtCheck(out, "    ", "zcbor_map_start_encode(state, {d})", .{enc_hint}),
                .array => try self.stmtCheck(out, "    ", "zcbor_list_start_encode(state, {d})", .{enc_hint}),
                .group => {},
            }
            try appendFmt(out, gpa, "    switch (input->choice) {{\n", .{});
            for (uchoices) |uc| {
                try appendFmt(out, gpa, "    case {s}_{s}_c:\n", .{ cname, uc.label });
                const target = if (uc.target) |t|
                    try std.fmt.allocPrint(gpa, "&input->{s}", .{t})
                else
                    null;
                try self.valueStmts(out, .encode, uc.x, target, "        ");
                try appendFmt(out, gpa, "        break;\n", .{});
            }
            try appendFmt(out, gpa,
                \\    default:
                \\        zcbor_error(state, ZCBOR_ERR_BAD_ARG);
                \\        return false;
                \\    }}
                \\
            , .{});
            switch (framing) {
                .map => try self.stmtCheck(out, "    ", "zcbor_map_end_encode(state, {d})", .{enc_hint}),
                .array => try self.stmtCheck(out, "    ", "zcbor_list_end_encode(state, {d})", .{enc_hint}),
                .group => {},
            }
            try appendFmt(out, gpa, "    return true;\n}}\n\n", .{});
        }
    }

    /// CBOR-in-CBOR fragmented API: the wrapped string's contents are CBOR
    /// items decoded/encoded one at a time with regular zcbor calls, while
    /// the payload arrives/leaves in sections. Item calls are made atomic
    /// with a state backup so a payload-exhausted item can be retried after
    /// feeding more data.
    fn emitCborFragFns(
        self: *Gen,
        cname: []const u8,
        framing: Framing,
        walk: *Walk,
        key: ?ast.Key,
        n_elems: u64,
        depth: usize,
        item: *const CType,
        frag_dec: []const u8,
    ) Error!void {
        const gpa = self.gpa;
        const upper = try upperName(gpa, cname);
        const member = walk.last_name;
        // + 2 zcbor extra states, + 1 backup held by the open wrapped string,
        // + 1 transient backup per item call, + backups the item needs itself.
        const n_states = depth + item.depth + 4;

        const doc = try std.fmt.allocPrint(gpa,
            \\
            \\/* CBOR-in-CBOR fragmented API for '{s}': '{s}' wraps CBOR data that is
            \\ * decoded/encoded item by item ({s}) while the payload arrives or
            \\ * leaves in sections. Call *_frag_begin with the first payload section
            \\ * (it must contain everything up to and including the '{s}' string
            \\ * header), then *_frag_item per wrapped item. An item call that fails
            \\ * with ZCBOR_ERR_NO_PAYLOAD leaves the state at the item's start:
            \\ * feed more payload with zcbor_update_state(states, buf, len) and
            \\ * retry it (bytes already consumed from the old section are NOT
            \\ * carried over -- copy the tail plus the next chunk into a staging
            \\ * buffer first, see the README). Finish with *_frag_end.
            \\ * 'states' must hold at least {s}_FRAG_N_STATES elements and stay
            \\ * alive between these calls. */
            \\#define {s}_FRAG_N_STATES {d}
            \\
        , .{ cname, member, item.text, member, upper, upper, n_states });

        var dec_key: std.ArrayList(u8) = .empty;
        var enc_key: std.ArrayList(u8) = .empty;
        if (key) |k| {
            try self.keyStmts(&dec_key, .decode, k, cname, "    ");
            try self.keyStmts(&enc_key, .encode, k, cname, "    ");
        }

        // --- Decode side -----------------------------------------------------
        {
            const begin_helper = try std.fmt.allocPrint(gpa, "static bool decode_frag_begin_{s}(zcbor_state_t *state, struct {s} *result)", .{ cname, cname });
            const item_helper = try std.fmt.allocPrint(gpa, "static bool decode_frag_item_{s}(zcbor_state_t *state, {s} *item)", .{ cname, item.text });
            try appendFmt(&self.dec_protos, gpa, "{s};\n{s};\n", .{ begin_helper, item_helper });

            const out = &self.dec_fns;
            try appendFmt(out, gpa, "{s}\n{{\n    (void)result;\n", .{begin_helper});
            switch (framing) {
                .map => try self.stmtCheck(out, "    ", "zcbor_map_start_decode(state)", .{}),
                .array => try self.stmtCheck(out, "    ", "zcbor_list_start_decode(state)", .{}),
                .group => unreachable,
            }
            try out.appendSlice(gpa, frag_dec);
            try out.appendSlice(gpa, dec_key.items);
            try self.stmtCheck(out, "    ", "zcbor_cbor_bstr_fragments_start_decode(state)", .{});
            try appendFmt(out, gpa, "    return true;\n}}\n\n", .{});

            try appendFmt(out, gpa, "{s}\n{{\n", .{item_helper});
            try self.valueStmts(out, .decode, item.x, "item", "    ");
            try appendFmt(out, gpa, "    return true;\n}}\n\n", .{});

            try self.dec_pub_protos.appendSlice(gpa, doc);
            const begin_sig = try std.fmt.allocPrint(gpa,
                "int cbor_decode_{s}_frag_begin(zcbor_state_t *states, size_t n_states,\n        const uint8_t *payload, size_t payload_len, struct {s} *result)", .{ cname, cname });
            const item_sig = try std.fmt.allocPrint(gpa,
                "int cbor_decode_{s}_frag_item(zcbor_state_t *states, {s} *item)", .{ cname, item.text });
            const at_end_sig = try std.fmt.allocPrint(gpa,
                "bool cbor_decode_{s}_frag_at_end(zcbor_state_t *states)", .{cname});
            const end_sig = try std.fmt.allocPrint(gpa,
                "int cbor_decode_{s}_frag_end(zcbor_state_t *states, size_t *payload_len_out)", .{cname});
            try appendFmt(&self.dec_pub_protos, gpa, "{s};\n{s};\n{s};\n{s};\n", .{ begin_sig, item_sig, at_end_sig, end_sig });

            const pub_out = &self.dec_pub_fns;
            try appendFmt(pub_out, gpa, "{s}\n{{\n    zcbor_new_decode_state(states, n_states, payload, payload_len, ZCBOR_LARGE_ELEM_COUNT, NULL, 0);\n", .{begin_sig});
            try self.intCheck(pub_out, "decode_frag_begin_{s}(states, result)", .{cname});
            try appendFmt(pub_out, gpa, "    return ZCBOR_SUCCESS;\n}}\n\n", .{});

            try appendFmt(pub_out, gpa, "{s}\n{{\n", .{item_sig});
            try self.intCheck(pub_out, "zcbor_new_backup(states, states->elem_count)", .{});
            try appendFmt(pub_out, gpa,
                \\    size_t backup_num = states->constant_state->current_backup;
                \\
                \\    if (!decode_frag_item_{s}(states, item)) {{
                \\        int err = zcbor_pop_error(states);
                \\
                \\        /* Drop backups left inside the partially processed item, then
                \\         * roll back to the item's start so it can be retried. */
                \\        states->constant_state->current_backup = backup_num;
                \\        (void)zcbor_process_backup(states,
                \\                ZCBOR_FLAG_RESTORE | ZCBOR_FLAG_CONSUME, ZCBOR_MAX_ELEM_COUNT);
                \\        return (err == ZCBOR_SUCCESS) ? ZCBOR_ERR_UNKNOWN : err;
                \\    }}
                \\
            , .{cname});
            try self.intCheck(pub_out, "zcbor_process_backup(states, ZCBOR_FLAG_CONSUME, ZCBOR_MAX_ELEM_COUNT)", .{});
            try appendFmt(pub_out, gpa, "    return ZCBOR_SUCCESS;\n}}\n\n", .{});

            try appendFmt(pub_out, gpa,
                \\{s}
                \\{{
                \\    size_t remainder;
                \\
                \\    if (!zcbor_current_string_remainder(states, &remainder)) {{
                \\        return false;
                \\    }}
                \\    return remainder == 0;
                \\}}
                \\
                \\
            , .{at_end_sig});

            try appendFmt(pub_out, gpa, "{s}\n{{\n", .{end_sig});
            try self.intCheck(pub_out, "zcbor_str_fragments_end_decode(states)", .{});
            switch (framing) {
                .map => try self.intCheck(pub_out, "zcbor_map_end_decode(states)", .{}),
                .array => try self.intCheck(pub_out, "zcbor_list_end_decode(states)", .{}),
                .group => unreachable,
            }
            try appendFmt(pub_out, gpa,
                \\    if (payload_len_out != NULL) {{
                \\        *payload_len_out = (size_t)(states->payload - states->constant_state->curr_payload_section);
                \\    }}
                \\    return ZCBOR_SUCCESS;
                \\}}
                \\
                \\
            , .{});
        }

        // --- Encode side -----------------------------------------------------
        {
            const begin_helper = try std.fmt.allocPrint(gpa, "static bool encode_frag_begin_{s}(zcbor_state_t *state, const struct {s} *input, size_t total_len)", .{ cname, cname });
            const item_helper = try std.fmt.allocPrint(gpa, "static bool encode_frag_item_{s}(zcbor_state_t *state, const {s} *item)", .{ cname, item.text });
            try appendFmt(&self.enc_protos, gpa, "{s};\n{s};\n", .{ begin_helper, item_helper });

            const out = &self.enc_fns;
            try appendFmt(out, gpa, "{s}\n{{\n    (void)input;\n", .{begin_helper});
            switch (framing) {
                .map => try self.stmtCheck(out, "    ", "zcbor_map_start_encode(state, {d})", .{n_elems}),
                .array => try self.stmtCheck(out, "    ", "zcbor_list_start_encode(state, {d})", .{n_elems}),
                .group => unreachable,
            }
            try out.appendSlice(gpa, walk.enc.items[0..walk.last_enc_mark]);
            try out.appendSlice(gpa, enc_key.items);
            try self.stmtCheck(out, "    ", "zcbor_cbor_bstr_fragments_start_encode(state, total_len)", .{});
            try appendFmt(out, gpa, "    return true;\n}}\n\n", .{});

            try appendFmt(out, gpa, "{s}\n{{\n", .{item_helper});
            try self.valueStmts(out, .encode, item.x, "item", "    ");
            try appendFmt(out, gpa, "    return true;\n}}\n\n", .{});

            try self.enc_pub_protos.appendSlice(gpa, doc);
            const begin_sig = try std.fmt.allocPrint(gpa,
                "int cbor_encode_{s}_frag_begin(zcbor_state_t *states, size_t n_states,\n        uint8_t *payload, size_t payload_len, const struct {s} *input, size_t {s}_total_len)", .{ cname, cname, member });
            const item_sig = try std.fmt.allocPrint(gpa,
                "int cbor_encode_{s}_frag_item(zcbor_state_t *states, const {s} *item)", .{ cname, item.text });
            const end_sig = try std.fmt.allocPrint(gpa,
                "int cbor_encode_{s}_frag_end(zcbor_state_t *states, size_t *payload_len_out)", .{cname});
            try appendFmt(&self.enc_pub_protos, gpa, "{s};\n{s};\n{s};\n", .{ begin_sig, item_sig, end_sig });

            const pub_out = &self.enc_pub_fns;
            try appendFmt(pub_out, gpa, "{s}\n{{\n    zcbor_new_encode_state(states, n_states, payload, payload_len, 0);\n", .{begin_sig});
            try self.intCheck(pub_out, "encode_frag_begin_{s}(states, input, {s}_total_len)", .{ cname, member });
            try appendFmt(pub_out, gpa, "    return ZCBOR_SUCCESS;\n}}\n\n", .{});

            try appendFmt(pub_out, gpa, "{s}\n{{\n", .{item_sig});
            try self.intCheck(pub_out, "zcbor_new_backup(states, states->elem_count)", .{});
            try appendFmt(pub_out, gpa,
                \\    size_t backup_num = states->constant_state->current_backup;
                \\
                \\    if (!encode_frag_item_{s}(states, item)) {{
                \\        int err = zcbor_pop_error(states);
                \\
                \\        /* Drop backups left inside the partially processed item, then
                \\         * roll back to the item's start so it can be retried. */
                \\        states->constant_state->current_backup = backup_num;
                \\        (void)zcbor_process_backup(states,
                \\                ZCBOR_FLAG_RESTORE | ZCBOR_FLAG_CONSUME, ZCBOR_MAX_ELEM_COUNT);
                \\        return (err == ZCBOR_SUCCESS) ? ZCBOR_ERR_UNKNOWN : err;
                \\    }}
                \\
            , .{cname});
            try self.intCheck(pub_out, "zcbor_process_backup(states, ZCBOR_FLAG_CONSUME, ZCBOR_MAX_ELEM_COUNT)", .{});
            try appendFmt(pub_out, gpa, "    return ZCBOR_SUCCESS;\n}}\n\n", .{});

            try appendFmt(pub_out, gpa, "{s}\n{{\n", .{end_sig});
            try self.intCheck(pub_out, "zcbor_str_fragments_end_encode(states)", .{});
            switch (framing) {
                .map => try self.intCheck(pub_out, "zcbor_map_end_encode(states, {d})", .{n_elems}),
                .array => try self.intCheck(pub_out, "zcbor_list_end_encode(states, {d})", .{n_elems}),
                .group => unreachable,
            }
            try appendFmt(pub_out, gpa,
                \\    if (payload_len_out != NULL) {{
                \\        *payload_len_out = (size_t)(states->payload - states->constant_state->curr_payload_section);
                \\    }}
                \\    return ZCBOR_SUCCESS;
                \\}}
                \\
                \\
            , .{});
        }
    }

    fn emitTypedefFns(self: *Gen, stem: []const u8, typedef_name: []const u8, ctype: CType) Error!void {
        const gpa = self.gpa;
        inline for (.{ Mode.decode, Mode.encode }) |mode| {
            const constness: []const u8 = if (mode == .encode) "const " else "";
            const argname: []const u8 = if (mode == .encode) "input" else "result";
            const sig = try std.fmt.allocPrint(gpa, "static bool {s}_{s}(zcbor_state_t *state, {s}void *void_{s})", .{ mode.prefix(), stem, constness, argname });
            try appendFmt(self.protos(mode), gpa, "{s};\n", .{sig});
            const out = self.fns(mode);
            try appendFmt(out, gpa, "{s}\n{{\n    {s}{s} *{s} = void_{s};\n", .{ sig, constness, typedef_name, argname, argname });
            try self.valueStmts(out, mode, ctype.x, argname, "    ");
            try appendFmt(out, gpa, "    return true;\n}}\n\n", .{});
        }
    }

    /// Public API wrappers using zcbor_entry_function.
    fn emitEntryFunctions(self: *Gen, resolved: Resolved) Error!void {
        const gpa = self.gpa;
        const info: struct { stem: []const u8, ctext: ?[]const u8, depth: usize } = switch (resolved) {
            .c_struct => |n| .{ .stem = n.stem, .ctext = try std.fmt.allocPrint(gpa, "struct {s}", .{n.name}), .depth = n.depth },
            .c_enum => |n| .{ .stem = n.stem, .ctext = try std.fmt.allocPrint(gpa, "enum {s}", .{n.name}), .depth = n.depth },
            .c_typedef => |n| .{ .stem = n.stem, .ctext = n.name, .depth = n.depth },
            .validator => |n| .{ .stem = n.stem, .ctext = null, .depth = n.depth },
            .constant, .none => return,
        };
        const n_states = info.depth + 2;

        // zcbor_entry_function takes a zcbor_decoder_t; encoders have a
        // const parameter, so give each entry a decoder-typed shim instead
        // of casting the function pointer (undefined behavior).
        try appendFmt(&self.enc_protos, gpa, "static bool encode_{s}_entry(zcbor_state_t *state, void *input);\n", .{info.stem});
        try appendFmt(&self.enc_fns, gpa,
            \\static bool encode_{s}_entry(zcbor_state_t *state, void *input)
            \\{{
            \\    return encode_{s}(state, input);
            \\}}
            \\
            \\
        , .{ info.stem, info.stem });

        if (info.ctext) |ctext| {
            const dec_sig = try std.fmt.allocPrint(gpa, "int cbor_decode_{s}(const uint8_t *payload, size_t payload_len, {s} *result, size_t *payload_len_out)", .{ info.stem, ctext });
            try appendFmt(&self.dec_pub_protos, gpa, "{s};\n", .{dec_sig});
            try appendFmt(&self.dec_pub_fns, gpa,
                \\{s}
                \\{{
                \\    zcbor_state_t states[{d}];
                \\    size_t consumed = 0;
                \\    int res = zcbor_entry_function(payload, payload_len, (void *)result, &consumed, states,
                \\            decode_{s}, sizeof(states) / sizeof(zcbor_state_t), ZCBOR_LARGE_ELEM_COUNT);
                \\
                \\    /* Trailing data after a valid document is an error. */
                \\    if (res == ZCBOR_SUCCESS && consumed != payload_len) {{
                \\        res = ZCBOR_ERR_PAYLOAD_NOT_CONSUMED;
                \\    }}
                \\    if (payload_len_out != NULL) {{
                \\        *payload_len_out = consumed;
                \\    }}
                \\    return res;
                \\}}
                \\
                \\
            , .{ dec_sig, n_states, info.stem });

            const enc_sig = try std.fmt.allocPrint(gpa, "int cbor_encode_{s}(uint8_t *payload, size_t payload_len, const {s} *input, size_t *payload_len_out)", .{ info.stem, ctext });
            try appendFmt(&self.enc_pub_protos, gpa, "{s};\n", .{enc_sig});
            try appendFmt(&self.enc_pub_fns, gpa,
                \\{s}
                \\{{
                \\    zcbor_state_t states[{d}];
                \\
                \\    return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
                \\            encode_{s}_entry, sizeof(states) / sizeof(zcbor_state_t), 0);
                \\}}
                \\
                \\
            , .{ enc_sig, n_states, info.stem });
        } else {
            const dec_sig = try std.fmt.allocPrint(gpa, "int cbor_decode_{s}(const uint8_t *payload, size_t payload_len, size_t *payload_len_out)", .{info.stem});
            try appendFmt(&self.dec_pub_protos, gpa, "{s};\n", .{dec_sig});
            try appendFmt(&self.dec_pub_fns, gpa,
                \\{s}
                \\{{
                \\    zcbor_state_t states[{d}];
                \\    size_t consumed = 0;
                \\    int res = zcbor_entry_function(payload, payload_len, NULL, &consumed, states,
                \\            decode_{s}, sizeof(states) / sizeof(zcbor_state_t), ZCBOR_LARGE_ELEM_COUNT);
                \\
                \\    /* Trailing data after a valid document is an error. */
                \\    if (res == ZCBOR_SUCCESS && consumed != payload_len) {{
                \\        res = ZCBOR_ERR_PAYLOAD_NOT_CONSUMED;
                \\    }}
                \\    if (payload_len_out != NULL) {{
                \\        *payload_len_out = consumed;
                \\    }}
                \\    return res;
                \\}}
                \\
                \\
            , .{ dec_sig, n_states, info.stem });

            const enc_sig = try std.fmt.allocPrint(gpa, "int cbor_encode_{s}(uint8_t *payload, size_t payload_len, size_t *payload_len_out)", .{info.stem});
            try appendFmt(&self.enc_pub_protos, gpa, "{s};\n", .{enc_sig});
            try appendFmt(&self.enc_pub_fns, gpa,
                \\{s}
                \\{{
                \\    zcbor_state_t states[{d}];
                \\
                \\    return zcbor_entry_function(payload, payload_len, NULL, payload_len_out, states,
                \\            encode_{s}_entry, sizeof(states) / sizeof(zcbor_state_t), 0);
                \\}}
                \\
                \\
            , .{ enc_sig, n_states, info.stem });
        }
    }
};

fn constToX(con: Constant) ConstX {
    return switch (con) {
        .int => |v| if (v < 0) .{ .nint = @intCast(v) } else .{ .uint = @intCast(v) },
        .text => |t| .{ .tstr = t },
        .bytes => |b| .{ .bstr = b },
        .float => |f| .{ .float = f },
    };
}

/// "&result->x" -> "result->x"; "result" -> "(*result)".
fn derefExpr(gpa: std.mem.Allocator, target: []const u8) Error![]const u8 {
    if (target.len > 0 and target[0] == '&') return target[1..];
    return std.fmt.allocPrint(gpa, "(*{s})", .{target});
}

/// Escape text for use inside a C string literal. Uses 3-digit octal escapes
/// for non-printable bytes (unambiguous, unlike \x).
fn cEscape(gpa: std.mem.Allocator, s: []const u8) Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (s) |ch| {
        switch (ch) {
            '"' => try out.appendSlice(gpa, "\\\""),
            '\\' => try out.appendSlice(gpa, "\\\\"),
            '\n' => try out.appendSlice(gpa, "\\n"),
            '\r' => try out.appendSlice(gpa, "\\r"),
            '\t' => try out.appendSlice(gpa, "\\t"),
            else => {
                if (ch >= 0x20 and ch < 0x7f) {
                    try out.append(gpa, ch);
                } else {
                    try appendFmt(&out, gpa, "\\{o:0>3}", .{ch});
                }
            },
        }
    }
    return out.toOwnedSlice(gpa);
}

/// C expression for a byte-string constant's data pointer.
fn bstrLiteral(gpa: std.mem.Allocator, bytes: []const u8) Error![]const u8 {
    if (bytes.len == 0) return "(const uint8_t *)\"\"";
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(gpa, "(const uint8_t[]){");
    for (bytes, 0..) |b, i| {
        if (i > 0) try out.appendSlice(gpa, ", ");
        try appendFmt(&out, gpa, "0x{x:0>2}", .{b});
    }
    try out.appendSlice(gpa, "}");
    return out.toOwnedSlice(gpa);
}

// --- Name sanitizing ----------------------------------------------------------

const c_keywords = [_][]const u8{
    "auto",     "break",    "case",     "char",   "const",    "continue",
    "default",  "do",       "double",   "else",   "enum",     "extern",
    "float",    "for",      "goto",     "if",     "inline",   "int",
    "long",     "register", "restrict", "return", "short",    "signed",
    "sizeof",   "static",   "struct",   "switch", "typedef",  "union",
    "unsigned", "void",     "volatile", "while",  "bool",     "true",
    "false",
};

/// Make a CDDL identifier or text literal usable as a C identifier.
fn sanitize(gpa: std.mem.Allocator, name: []const u8) Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (name, 0..) |ch, i| {
        if (std.ascii.isAlphanumeric(ch) or ch == '_') {
            if (i == 0 and std.ascii.isDigit(ch)) try out.append(gpa, '_');
            try out.append(gpa, ch);
        } else {
            try out.append(gpa, '_');
        }
    }
    if (out.items.len == 0) try out.append(gpa, '_');
    for (c_keywords) |kw| {
        if (std.mem.eql(u8, out.items, kw)) {
            try out.append(gpa, '_');
            break;
        }
    }
    return out.toOwnedSlice(gpa);
}

/// For `.cborseq [* T]` / `.cborseq [+ T]`: the element type T describing
/// the items of the CBOR sequence. Null when the controller has another
/// shape (then the controller itself is treated as the item type).
fn seqElementType(t2: ast.Type2) ?ast.Type {
    const group = switch (t2) {
        .array => |g| g,
        else => return null,
    };
    if (group.choices.len != 1 or group.choices[0].entries.len != 1) return null;
    const entry = group.choices[0].entries[0];
    if (entry.key != null) return null;
    if (entry.occur.max != null) return null; // only unbounded * / +
    return switch (entry.value) {
        .type => |t| t,
        .inline_group => null,
    };
}

/// "file_msg" -> "FILE_MSG" (for generated macro names).
fn upperName(gpa: std.mem.Allocator, name: []const u8) Error![]const u8 {
    const out = try gpa.alloc(u8, name.len);
    for (name, out) |ch, *o| o.* = std.ascii.toUpper(ch);
    return out;
}

fn intValueOf(t2: ast.Type2) ?i128 {
    return switch (t2) {
        .uint => |v| v,
        .nint => |v| v,
        else => null,
    };
}

fn isIntBase(base: ast.Type2) bool {
    return switch (base) {
        .uint, .nint => true,
        .typename => |n| std.mem.eql(u8, n, "uint") or std.mem.eql(u8, n, "int") or
            std.mem.eql(u8, n, "nint"),
        .major => |m| m.major == 0 or m.major == 1,
        else => false,
    };
}

fn isSignedBase(base: ast.Type2) bool {
    return switch (base) {
        .nint => true,
        .uint => false,
        .typename => |n| std.mem.eql(u8, n, "int") or std.mem.eql(u8, n, "nint"),
        .major => |m| m.major == 1,
        else => false,
    };
}

fn intTypeForBounds(lo: i128, hi: i128) []const u8 {
    if (lo < 0) {
        if (lo >= std.math.minInt(i8) and hi <= std.math.maxInt(i8)) return "int8_t";
        if (lo >= std.math.minInt(i16) and hi <= std.math.maxInt(i16)) return "int16_t";
        if (lo >= std.math.minInt(i32) and hi <= std.math.maxInt(i32)) return "int32_t";
        return "int64_t";
    }
    if (hi <= std.math.maxInt(u8)) return "uint8_t";
    if (hi <= std.math.maxInt(u16)) return "uint16_t";
    if (hi <= std.math.maxInt(u32)) return "uint32_t";
    return "uint64_t";
}

fn bitsForSize(bytes: u8) u8 {
    return switch (bytes) {
        0, 1 => 8,
        2 => 16,
        3, 4 => 32,
        else => 64,
    };
}

fn intTypeForSize(bytes: u8, signed: bool) []const u8 {
    if (signed) {
        return switch (bytes) {
            0, 1 => "int8_t",
            2 => "int16_t",
            3, 4 => "int32_t",
            else => "int64_t",
        };
    }
    return switch (bytes) {
        0, 1 => "uint8_t",
        2 => "uint16_t",
        3, 4 => "uint32_t",
        else => "uint64_t",
    };
}

// --- Tests --------------------------------------------------------------------

const testing = std.testing;

fn generateTest(arena: std.mem.Allocator, source: []const u8) ![]const u8 {
    var pdiag: Parser.Diagnostic = .{};
    const doc = Parser.parse(arena, source, &pdiag) catch |e| {
        std.debug.print("parse error at {d}:{d}: {s}\n", .{ pdiag.line, pdiag.column, pdiag.message });
        return e;
    };
    var gdiag: Diagnostic = .{};
    return generateDiag(arena, doc, .{ .guard = "TEST_H__" }, &gdiag) catch |e| {
        std.debug.print("codegen error: {s} ({s})\n", .{ gdiag.message, gdiag.context });
        return e;
    };
}

fn generateXcodeTest(arena: std.mem.Allocator, source: []const u8) !Output {
    var pdiag: Parser.Diagnostic = .{};
    const doc = Parser.parse(arena, source, &pdiag) catch |e| {
        std.debug.print("parse error at {d}:{d}: {s}\n", .{ pdiag.line, pdiag.column, pdiag.message });
        return e;
    };
    var gdiag: Diagnostic = .{};
    return generateAll(arena, doc, .{
        .guard = "TEST_H__",
        .xcode = .{ .decode = true, .encode = true },
    }, &gdiag) catch |e| {
        std.debug.print("codegen error: {s} ({s})\n", .{ gdiag.message, gdiag.context });
        return e;
    };
}

fn expectContains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) == null) {
        std.debug.print("--- expected to find:\n{s}\n--- in:\n{s}\n", .{ needle, haystack });
        return error.TestExpectedContains;
    }
}

fn expectNotContains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) != null) {
        std.debug.print("--- expected NOT to find:\n{s}\n--- in:\n{s}\n", .{ needle, haystack });
        return error.TestExpectedNotContains;
    }
}

test "CDDL enum (&group) maps to C enum" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateTest(arena.allocator(),
        \\colors = &( red: 0, green: 1, blue: 4 )
    );
    try expectContains(out,
        \\enum colors {
        \\    colors_red_c = 0,
        \\    colors_green_c = 1,
        \\    colors_blue_c = 4,
        \\};
    );
}

test "&groupname enumeration maps to C enum" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateTest(arena.allocator(),
        \\colors-group = ( red: 0, green: 1, blue: 2 )
        \\colors = &colors-group
    );
    try expectContains(out,
        \\enum colors {
        \\    colors_red_c = 0,
        \\    colors_green_c = 1,
        \\    colors_blue_c = 2,
        \\};
    );
}

test "choice of named int literals maps to C enum" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateTest(arena.allocator(),
        \\err-ok = 0
        \\err-crc = 1
        \\err-timeout = 2
        \\error-code = err-ok / err-crc / err-timeout
    );
    try expectContains(out,
        \\enum error_code {
        \\    error_code_err_ok_c = 0,
        \\    error_code_err_crc_c = 1,
        \\    error_code_err_timeout_c = 2,
        \\};
    );
}

test "choice of bstr literals maps to positional C enum" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateXcodeTest(arena.allocator(),
        \\vat = 'F' / 'L' / 'R'
    );
    try expectContains(out.types_h,
        \\enum vat {
        \\    vat_F_c = 0,
        \\    vat_L_c = 1,
        \\    vat_R_c = 2,
        \\};
    );
    try expectContains(out.decode_c.?, "zcbor_bstr_decode(state, &val)");
    try expectContains(out.decode_c.?, "memcmp(val.value, \"F\", 1)");
    try expectContains(out.encode_c.?, "zcbor_bstr_encode_ptr(state, \"L\", 1)");
}

test "range-valued .size constrains string length" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateXcodeTest(arena.allocator(),
        \\v = { label: tstr .size (1..32) }
    );
    const dec = out.decode_c.?;
    try expectContains(dec, "result->label.len < 1");
    try expectContains(dec, "result->label.len > 32");
    try expectContains(out.types_h, "struct zcbor_string label;");
}

test "storage-less mixed-constant choices are rejected, not empty unions" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var pdiag: Parser.Diagnostic = .{};
    const doc = try Parser.parse(arena.allocator(), "x = 1.5 / \"a\"", &pdiag);
    var gdiag: Diagnostic = .{};
    try testing.expectError(error.Unsupported, generateAll(arena.allocator(), doc, .{
        .xcode = .{ .decode = true, .encode = true },
    }, &gdiag));
}

test "choice of tstr literals maps to positional C enum" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateTest(arena.allocator(),
        \\mode = "slow" / "fast"
    );
    try expectContains(out,
        \\enum mode {
        \\    mode_slow_c = 0,
        \\    mode_fast_c = 1,
        \\};
    );
}

test "map rule maps to C struct with optional and repeated members" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateTest(arena.allocator(),
        \\config = {
        \\    name: tstr,
        \\    ? retries: uint,
        \\    0*4 ports: uint,
        \\}
    );
    try expectContains(out,
        \\struct config {
        \\    struct zcbor_string name;
        \\    uint32_t retries;
        \\    bool retries_present;
        \\    uint32_t ports[4];
        \\    size_t ports_count;
        \\};
    );
}

test "array rule maps to C struct in field order" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateTest(arena.allocator(),
        \\point = [ x: int, y: int ]
    );
    try expectContains(out,
        \\struct point {
        \\    int32_t x;
        \\    int32_t y;
        \\};
    );
}

test "heterogeneous choice maps to union with choice enum" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateTest(arena.allocator(),
        \\value = uint / tstr
    );
    try expectContains(out,
        \\struct value {
        \\    union {
        \\        uint32_t _uint;
        \\        struct zcbor_string _tstr;
        \\    };
        \\    enum value_choice {
        \\        value__uint_c,
        \\        value__tstr_c,
        \\    } choice;
        \\};
    );
}

test "scalar aliases map to typedefs with narrowed widths" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateTest(arena.allocator(),
        \\port = uint .size 2
        \\byte = 0..255
        \\temperature = -128..127
        \\sensor-id = uint
    );
    try expectContains(out, "typedef uint16_t port_t;");
    try expectContains(out, "typedef uint8_t byte_t;");
    try expectContains(out, "typedef int8_t temperature_t;");
    try expectContains(out, "typedef uint32_t sensor_id_t;");
}

test "rules referencing rules use the generated C types" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateTest(arena.allocator(),
        \\colors = &( red: 0, green: 1 )
        \\port = uint .size 2
        \\config = { color: colors, port: port }
    );
    try expectContains(out,
        \\struct config {
        \\    enum colors color;
        \\    port_t port;
        \\};
    );
}

test "nested inline containers become named sub-structs" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateTest(arena.allocator(),
        \\outer = { inner: { a: uint } }
    );
    try expectContains(out,
        \\struct outer_inner {
        \\    uint32_t a;
        \\};
    );
    try expectContains(out,
        \\struct outer {
        \\    struct outer_inner inner;
        \\};
    );
}

test "constant members need no storage" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateTest(arena.allocator(),
        \\version = 1
        \\msg = [ version, payload: bstr ]
    );
    try expectContains(out,
        \\struct msg {
        \\    /* 'version' is fully constrained by the CDDL; no storage needed */
        \\    struct zcbor_string payload;
        \\};
    );
}

test "group choices inside a map become a union" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateTest(arena.allocator(),
        \\msg = { variant: 1, body: tstr // variant: 2, code: uint }
    );
    try expectContains(out, "enum msg_choice");
    try expectContains(out, "struct msg_variant");
}

test "recursive types are rejected" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var pdiag: Parser.Diagnostic = .{};
    const doc = try Parser.parse(arena.allocator(),
        \\node = { next: node }
    , &pdiag);
    var gdiag: Diagnostic = .{};
    try testing.expectError(
        error.RecursiveType,
        generateDiag(arena.allocator(), doc, .{}, &gdiag),
    );
}

test "unknown types are reported" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var pdiag: Parser.Diagnostic = .{};
    const doc = try Parser.parse(arena.allocator(), "a = { b: missing }", &pdiag);
    var gdiag: Diagnostic = .{};
    try testing.expectError(error.UnknownType, generateDiag(arena.allocator(), doc, .{}, &gdiag));
    try testing.expectEqualStrings("missing", gdiag.context);
}

test "out-of-range .size is rejected, not a crash" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var pdiag: Parser.Diagnostic = .{};
    var gdiag: Diagnostic = .{};
    {
        const doc = try Parser.parse(arena.allocator(), "x = uint .size 9999", &pdiag);
        try testing.expectError(error.Unsupported, generateDiag(arena.allocator(), doc, .{}, &gdiag));
    }
    {
        const doc = try Parser.parse(arena.allocator(), "y = tstr .size -3", &pdiag);
        try testing.expectError(error.Unsupported, generateDiag(arena.allocator(), doc, .{}, &gdiag));
    }
}

test "long alias chains are rejected, not a stack overflow" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var source: std.ArrayList(u8) = .empty;
    for (0..300) |i| {
        try appendFmt(&source, arena.allocator(), "t{d} = t{d}\n", .{ i, i + 1 });
    }
    try source.appendSlice(arena.allocator(), "t300 = uint\n");
    var pdiag: Parser.Diagnostic = .{};
    const doc = try Parser.parse(arena.allocator(), source.items, &pdiag);
    var gdiag: Diagnostic = .{};
    try testing.expectError(error.RecursiveType, generateDiag(arena.allocator(), doc, .{}, &gdiag));
}

test "fuzz: codegen survives any parseable document" {
    try testing.fuzz({}, fuzzParseAndGenerate, .{ .corpus = &.{
        "config = { name: tstr, ? d: tstr, 0*4 e: uint }",
        "colors = &( red: 0, green: 1 )\nc = { x: colors }",
        "v = 1\nu = v / \"s\" / h'00'\nw = [ v, u, * uint ]",
        "f = { n: tstr, d: bstr }",
        "q = { m: bstr .cborseq [* uint] }",
        "g = ( a: 1, b: 2 )\nh = { g }\ni = &g",
    } });
}

fn fuzzParseAndGenerate(_: void, smith: *testing.Smith) !void {
    var buf: [2048]u8 = undefined;
    const len = smith.slice(&buf);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var pdiag: Parser.Diagnostic = .{};
    const doc = Parser.parse(arena.allocator(), buf[0..len], &pdiag) catch return;
    // Any document that parses must generate cleanly or fail with a
    // diagnostic -- never crash.
    var gdiag: Diagnostic = .{};
    _ = generateAll(arena.allocator(), doc, .{
        .xcode = .{ .decode = true, .encode = true },
    }, &gdiag) catch return;
}

test "complete header output for a small document" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateTest(arena.allocator(),
        \\pair = [ a: uint, b: uint ]
    );
    try testing.expectEqualStrings(
        \\/* Generated by cddl2c. Do not edit. */
        \\#ifndef TEST_H__
        \\#define TEST_H__
        \\
        \\#include <stdint.h>
        \\#include <stdbool.h>
        \\#include <stddef.h>
        \\#include "zcbor_common.h"
        \\
        \\struct pair {
        \\    uint32_t a;
        \\    uint32_t b;
        \\};
        \\
        \\#endif /* TEST_H__ */
        \\
    , out);
}

// --- Xcode generation tests ---------------------------------------------------

test "map decode: unordered key search and value decodes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateXcodeTest(arena.allocator(),
        \\config = { name: tstr, port: uint }
    );
    const dec = out.decode_c.?;
    try expectContains(dec, "static bool decode_config(zcbor_state_t *state, void *void_result)");
    try expectContains(dec, "struct config *result = void_result;");
    try expectContains(dec, "state->constant_state->manually_process_elem = true;");
    try expectContains(dec, "zcbor_unordered_map_start_decode(state)");
    try expectContains(dec, "zcbor_search_key_tstr_ptr(state, \"name\", 4)");
    try expectContains(dec, "zcbor_tstr_decode(state, &result->name)");
    try expectContains(dec, "zcbor_uint32_decode(state, &result->port)");
    try expectContains(dec, "zcbor_elem_processed(state)");
    try expectContains(dec, "zcbor_unordered_map_end_decode(state)");
    try expectContains(dec, "int cbor_decode_config(const uint8_t *payload, size_t payload_len, struct config *result, size_t *payload_len_out)");
    try expectContains(dec, "ZCBOR_LARGE_ELEM_COUNT");

    const enc = out.encode_c.?;
    try expectContains(enc, "static bool encode_config(zcbor_state_t *state, const void *void_input)");
    try expectContains(enc, "zcbor_map_start_encode(state, 2)");
    try expectContains(enc, "zcbor_tstr_encode_ptr(state, \"name\", 4)");
    try expectContains(enc, "zcbor_tstr_encode(state, &input->name)");
    try expectContains(enc, "int cbor_encode_config(uint8_t *payload, size_t payload_len, const struct config *input, size_t *payload_len_out)");
}

test "ordered-maps option keeps strict-order decode" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var pdiag: Parser.Diagnostic = .{};
    const doc = try Parser.parse(arena.allocator(),
        \\config = { name: tstr, port: uint }
    , &pdiag);
    var gdiag: Diagnostic = .{};
    const out = try generateAll(arena.allocator(), doc, .{
        .xcode = .{ .decode = true, .encode = true, .unordered_maps = false },
    }, &gdiag);
    const dec = out.decode_c.?;
    try expectContains(dec, "zcbor_map_start_decode(state)");
    try expectContains(dec, "zcbor_tstr_expect_ptr(state, \"name\", 4)");
    try expectNotContains(dec, "zcbor_search_key_tstr_ptr");
    try expectNotContains(dec, "zcbor_unordered_map_start_decode");
}

test "uint map keys search via pexpect" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateXcodeTest(arena.allocator(),
        \\m = { 1 => tstr, -2 => uint }
    );
    const dec = out.decode_c.?;
    try expectContains(dec, "zcbor_search_key_uint(state, 1)");
    try expectContains(dec, "zcbor_search_key_int(state, -2)");
}

test "optional map members decode by search, encode conditionally" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateXcodeTest(arena.allocator(),
        \\config = { ? description: tstr }
    );
    const dec = out.decode_c.?;
    try expectContains(dec,
        \\    result->description_present = zcbor_search_key_tstr_ptr(state, "description", 11);
        \\    if (result->description_present) {
        \\        if (!zcbor_tstr_decode(state, &result->description)) {
        \\            return false;
        \\        }
        \\        if (!zcbor_elem_processed(state)) {
        \\            return false;
        \\        }
        \\    }
    );
    // No helper functions or function-pointer paths.
    try expectNotContains(dec, "zcbor_present_decode");
    try expectNotContains(dec, "decode_repeated_config_description");

    const enc = out.encode_c.?;
    try expectContains(enc, "if (input->description_present) {");
    try expectContains(enc, "zcbor_tstr_encode_ptr(state, \"description\", 11)");
}

test "optional array members decode with inline rollback" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateXcodeTest(arena.allocator(),
        \\a = [ x: uint, ? y: tstr ]
    );
    const dec = out.decode_c.?;
    try expectContains(dec,
        \\    {
        \\        zcbor_state_t state_bak = *state;
        \\        size_t backup_num = (state->constant_state != NULL)
        \\                ? state->constant_state->current_backup : 0;
        \\        bool present = false;
        \\
        \\        do {
        \\            if (!zcbor_tstr_decode(state, &result->y)) {
        \\                break;
        \\            }
        \\            present = true;
        \\        } while (0);
    );
}

test "repeated map members decode by search loop, encode via multi" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateXcodeTest(arena.allocator(),
        \\config = { 1*4 extra: uint }
    );
    const dec = out.decode_c.?;
    try expectContains(dec,
        \\    result->extra_count = 0;
        \\    while (result->extra_count < 4 && zcbor_search_key_tstr_ptr(state, "extra", 5)) {
        \\        if (!zcbor_uint32_decode(state, &result->extra[result->extra_count])) {
        \\            return false;
        \\        }
        \\        if (!zcbor_elem_processed(state)) {
        \\            return false;
        \\        }
        \\        result->extra_count++;
        \\    }
        \\    if (result->extra_count < 1) {
        \\        zcbor_error(state, ZCBOR_ERR_ITERATIONS);
        \\        return false;
        \\    }
    );
    const enc = out.encode_c.?;
    try expectContains(enc, "zcbor_multi_encode_minmax(1, 4, &input->extra_count, encode_repeated_config_extra, state, input->extra, sizeof(input->extra[0]))");
}

test "repeated array members use multi_decode" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateXcodeTest(arena.allocator(),
        \\l = [ 0*4 uint ]
    );
    try expectContains(out.decode_c.?, "zcbor_multi_decode_w_backup(0, 4, &result->_uint_count, decode_repeated_l__uint, state, result->_uint, sizeof(result->_uint[0]))");
}

test "bstr .cbor X decodes into a typed member one-shot" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateXcodeTest(arena.allocator(),
        \\point = [ x: int, y: int ]
        \\env = { kind: uint, inner: bstr .cbor point }
    );
    try expectContains(out.types_h,
        \\struct env {
        \\    uint32_t kind;
        \\    struct point inner;
        \\};
    );
    const dec = out.decode_c.?;
    try expectContains(dec, "zcbor_bstr_start_decode(state, NULL)");
    try expectContains(dec, "decode_point(state, &result->inner)");
    try expectContains(dec, "zcbor_bstr_end_decode(state)");
    const enc = out.encode_c.?;
    try expectContains(enc, "zcbor_bstr_start_encode(state)");
    try expectContains(enc, "encode_point(state, &input->inner)");
    try expectContains(enc, "zcbor_bstr_end_encode(state, NULL)");
}

test "int-valued enum functions validate membership" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateXcodeTest(arena.allocator(),
        \\e-ok = 0
        \\e-bad = 1
        \\status = e-ok / e-bad
    );
    const dec = out.decode_c.?;
    try expectContains(dec, "static bool decode_status(zcbor_state_t *state, void *void_result)");
    try expectContains(dec, "enum status *result = void_result;");
    try expectContains(dec, "zcbor_int64_decode(state, &val)");
    try expectContains(dec, "case 0:");
    try expectContains(dec, "case 1:");
    try expectContains(dec, "*result = (enum status)val;");
    try expectContains(dec, "ZCBOR_ERR_WRONG_VALUE");

    const enc = out.encode_c.?;
    try expectContains(enc, "case status_e_ok_c:");
    try expectContains(enc, "zcbor_int64_put(state, (int64_t)*input)");
}

test "tstr enum functions compare and emit strings" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateXcodeTest(arena.allocator(),
        \\mode = "slow" / "fast"
    );
    const dec = out.decode_c.?;
    try expectContains(dec, "memcmp(val.value, \"slow\", 4)");
    try expectContains(dec, "*result = mode_slow_c;");
    const enc = out.encode_c.?;
    try expectContains(enc, "case mode_fast_c:");
    try expectContains(enc, "zcbor_tstr_encode_ptr(state, \"fast\", 4)");
}

test "union decode tries choices, encode switches on choice" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateXcodeTest(arena.allocator(),
        \\value = uint / tstr
    );
    const dec = out.decode_c.?;
    try expectContains(dec, "zcbor_union_start_code(state)");
    try expectContains(dec, "decode_try_value__uint(state, result)");
    try expectContains(dec, "result->choice = value__uint_c;");
    try expectContains(dec, "zcbor_union_end_code(state)");
    const enc = out.encode_c.?;
    try expectContains(enc, "switch (input->choice) {");
    try expectContains(enc, "case value__tstr_c:");
}

test "union decode drops orphaned backups between alternatives" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateXcodeTest(arena.allocator(),
        \\a = { x: uint }
        \\b = { y: uint }
        \\u = a / b
    );
    const dec = out.decode_c.?;
    try expectContains(dec, "size_t union_backup = state->constant_state->current_backup;");
    try expectContains(dec, "state->constant_state->current_backup = union_backup;");
}

test "decode entry wrappers reject trailing data" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateXcodeTest(arena.allocator(),
        \\pair = [ a: uint, b: uint ]
    );
    try expectContains(out.decode_c.?, "res = ZCBOR_ERR_PAYLOAD_NOT_CONSUMED;");
}

test "generation-time validation rejects unrepresentable constructs" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const cases = [_][]const u8{
        "e = &( a: 5000000000 )", // enum value > INT_MAX
        "w = { k: #6.5000000000(uint) }", // tag > UINT32_MAX
        "r = 5..2", // empty range
        "m = { uint }", // keyless map member
    };
    for (cases) |source| {
        var pdiag: Parser.Diagnostic = .{};
        const doc = try Parser.parse(arena.allocator(), source, &pdiag);
        var gdiag: Diagnostic = .{};
        try testing.expectError(error.Unsupported, generateAll(arena.allocator(), doc, .{
            .xcode = .{ .decode = true, .encode = true },
        }, &gdiag));
    }
}

test "constants are expected on decode and put on encode" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateXcodeTest(arena.allocator(),
        \\version = 1
        \\msg = [ version, payload: bstr ]
    );
    const dec = out.decode_c.?;
    try expectContains(dec, "zcbor_uint64_expect(state, 1)");
    try expectContains(dec, "zcbor_list_start_decode(state)");
    const enc = out.encode_c.?;
    try expectContains(enc, "zcbor_uint64_put(state, 1)");
}

test "range typedefs validate bounds" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateXcodeTest(arena.allocator(),
        \\percentage = 0..100
    );
    const dec = out.decode_c.?;
    try expectContains(dec, "static bool decode_percentage(zcbor_state_t *state, void *void_result)");
    try expectContains(dec, "percentage_t *result = void_result;");
    try expectContains(dec, "zcbor_uint8_decode(state, result)");
    try expectContains(dec, "if ((*result) > 100) {");
    try expectContains(dec, "ZCBOR_ERR_WRONG_RANGE");
    const enc = out.encode_c.?;
    try expectContains(enc, "if ((*input) > 100) {");
}

test "tagged values expect and put the tag" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateXcodeTest(arena.allocator(),
        \\when = #6.1(uint)
    );
    try expectContains(out.decode_c.?, "zcbor_tag_expect(state, 1)");
    try expectContains(out.encode_c.?, "zcbor_tag_put(state, 1)");
}

test "fragmented API is generated for trailing-bstr rules" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateXcodeTest(arena.allocator(),
        \\file-msg = {
        \\    filename: tstr,
        \\    file-size: uint,
        \\    data: bstr,
        \\}
    );
    const dec = out.decode_c.?;
    try expectContains(dec, "static bool decode_frag_begin_file_msg(zcbor_state_t *state, struct file_msg *result)");
    try expectContains(dec, "zcbor_bstr_fragments_start_decode(state)");
    try expectContains(dec, "zcbor_tstr_expect_ptr(state, \"data\", 4)");
    try expectContains(dec, "int cbor_decode_file_msg_frag_begin(zcbor_state_t *states, size_t n_states,");
    try expectContains(dec, "zcbor_str_fragment_decode(states, frag)");
    try expectContains(dec, "zcbor_str_fragments_end_decode(states)");
    // The begin helper decodes the leading members, then opens the fragment
    // stream instead of decoding the blob.
    try expectContains(dec, "zcbor_tstr_decode(state, &result->filename)");
    try expectContains(dec,
        \\    if (!zcbor_tstr_expect_ptr(state, "data", 4)) {
        \\        return false;
        \\    }
        \\    if (!zcbor_bstr_fragments_start_decode(state)) {
        \\        return false;
        \\    }
        \\    return true;
        \\}
    );

    const dec_h = out.decode_h.?;
    try expectContains(dec_h, "#define FILE_MSG_FRAG_N_STATES 3");
    try expectContains(dec_h, "cbor_decode_file_msg_frag_next");

    const enc = out.encode_c.?;
    try expectContains(enc, "zcbor_bstr_fragments_start_encode(state, total_len)");
    try expectContains(enc, "int cbor_encode_file_msg_frag_begin(zcbor_state_t *states, size_t n_states,");
    try expectContains(enc, "size_t data_total_len)");
    try expectContains(enc, "zcbor_str_fragment_encode(states, &frag, enc_len)");
    try expectContains(enc, "zcbor_str_fragments_end_encode(states)");
    try expectContains(out.encode_h.?, "#define FILE_MSG_FRAG_N_STATES 3");
}

test "CBOR-in-CBOR fragmented API for bstr .cborseq" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateXcodeTest(arena.allocator(),
        \\log-entry = [ seq: uint, msg: tstr ]
        \\log-file = {
        \\    name: tstr,
        \\    entries: bstr .cborseq [* log-entry],
        \\}
    );
    const dec = out.decode_c.?;
    try expectContains(dec, "zcbor_cbor_bstr_fragments_start_decode(state)");
    try expectContains(dec, "static bool decode_frag_item_log_file(zcbor_state_t *state, struct log_entry *item)");
    try expectContains(dec, "decode_log_entry(state, item)");
    try expectContains(dec, "int cbor_decode_log_file_frag_item(zcbor_state_t *states, struct log_entry *item)");
    try expectContains(dec, "zcbor_new_backup(states, states->elem_count)");
    try expectContains(dec, "ZCBOR_FLAG_RESTORE | ZCBOR_FLAG_CONSUME");
    try expectContains(dec, "bool cbor_decode_log_file_frag_at_end(zcbor_state_t *states)");
    try expectContains(dec, "zcbor_current_string_remainder(states, &remainder)");

    const enc = out.encode_c.?;
    try expectContains(enc, "zcbor_cbor_bstr_fragments_start_encode(state, total_len)");
    try expectContains(enc, "int cbor_encode_log_file_frag_item(zcbor_state_t *states, const struct log_entry *item)");
    try expectContains(enc, "size_t entries_total_len)");

    // depth(log_file)=1 + depth(log_entry)=1 + 4 = 6
    try expectContains(out.decode_h.?, "#define LOG_FILE_FRAG_N_STATES 6");
    try expectContains(out.encode_h.?, "#define LOG_FILE_FRAG_N_STATES 6");
}

test "bstr .cbor of a scalar streams the scalar as the item" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateXcodeTest(arena.allocator(),
        \\wrapped = [ meta: uint, body: bstr .cbor uint ]
    );
    const dec = out.decode_c.?;
    try expectContains(dec, "int cbor_decode_wrapped_frag_item(zcbor_state_t *states, uint32_t *item)");
    try expectContains(dec, "zcbor_uint32_decode(state, item)");
}

test "entry_rules tree-shakes and restricts public wrappers" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var pdiag: Parser.Diagnostic = .{};
    const doc = try Parser.parse(arena.allocator(),
        \\a = { x: b, y: uint }
        \\b = [ q: uint ]
        \\c = { z: uint }
    , &pdiag);
    var gdiag: Diagnostic = .{};
    const out = try generateAll(arena.allocator(), doc, .{
        .guard = "TEST_H__",
        .entry_rules = &.{"a"},
        .xcode = .{ .decode = true, .encode = true },
    }, &gdiag);

    // 'a' is public; 'b' is generated (referenced) but static-only;
    // 'c' is unreachable and not generated at all.
    const dec = out.decode_c.?;
    try expectContains(dec, "int cbor_decode_a(");
    try expectContains(dec, "static bool decode_b(");
    try expectNotContains(dec, "int cbor_decode_b(");
    try expectNotContains(dec, "decode_c");
    try expectContains(out.types_h, "struct b {");
    try expectNotContains(out.types_h, "struct c {");
}

test "pure scalar aliases inline at member sites" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    {
        const out = try generateXcodeTest(arena.allocator(),
            \\port = uint .size 2
            \\cfg = { p: port }
        );
        const dec = out.decode_c.?;
        // Member site calls the primitive directly...
        try expectContains(dec, "zcbor_uint16_decode(state, &result->p)");
        // ...while the alias keeps its own function and public wrapper
        // because it is an entry itself (no --entry restriction).
        try expectContains(dec, "static bool decode_port(");
        try expectContains(dec, "int cbor_decode_port(");
    }
    {
        // With --entry, the trivial alias function disappears entirely.
        var pdiag: Parser.Diagnostic = .{};
        const doc = try Parser.parse(arena.allocator(),
            \\port = uint .size 2
            \\cfg = { p: port }
        , &pdiag);
        var gdiag: Diagnostic = .{};
        const out = try generateAll(arena.allocator(), doc, .{
            .entry_rules = &.{"cfg"},
            .xcode = .{ .decode = true, .encode = true },
        }, &gdiag);
        const dec = out.decode_c.?;
        try expectContains(dec, "zcbor_uint16_decode(state, &result->p)");
        try expectNotContains(dec, "decode_port");
        // Validated aliases keep their function (single copy of the checks).
        try expectContains(out.types_h, "typedef uint16_t port_t;");
    }
    {
        // An alias with validation still decodes through its function.
        const out = try generateXcodeTest(arena.allocator(),
            \\pct = 0..100
            \\cfg = { p: pct }
        );
        try expectContains(out.decode_c.?, "decode_pct(state, &result->p)");
    }
}

test "extension point makes a map tolerate unknown keys" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateXcodeTest(arena.allocator(),
        \\open-msg = { 0 => uint, * any => any }
        \\closed-msg = { 0 => uint }
    );
    const dec = out.decode_c.?;
    // The open map skips unknown pairs; the closed map stays strict.
    try expectContains(dec, "static bool decode_open_msg");
    try expectContains(dec, "zcbor_map_end_decode_skip_unknown(state)");
    try expectContains(dec, "zcbor_unordered_map_end_decode(state)");
    // The extension point generates no storage.
    try expectNotContains(out.types_h, "any");
    // Encode side never emits unknown pairs.
    try expectContains(out.encode_c.?, "zcbor_map_end_encode(state, 1)");
}

test "frag_rules restricts which rules get the fragmented API" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var pdiag: Parser.Diagnostic = .{};
    const doc = try Parser.parse(arena.allocator(),
        \\file-msg = { name: tstr, data: bstr }
        \\log-entry = [ seq: uint, msg: tstr ]
    , &pdiag);
    var gdiag: Diagnostic = .{};
    const out = try generateAll(arena.allocator(), doc, .{
        .xcode = .{
            .decode = true,
            .encode = true,
            .frag_rules = &.{"file-msg"},
        },
    }, &gdiag);
    try expectContains(out.decode_c.?, "cbor_decode_file_msg_frag_begin");
    try expectNotContains(out.decode_c.?, "cbor_decode_log_entry_frag_begin");
    try expectNotContains(out.encode_c.?, "cbor_encode_log_entry_frag_begin");
}

test "no fragmented API without a trailing string member" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateXcodeTest(arena.allocator(),
        \\a = { x: tstr, y: uint }
        \\b = { ? x: tstr, data: bstr }
    );
    // 'a' ends in a uint; 'b' has an optional member (element count not
    // fixed, which fragmented encode requires). Neither qualifies.
    try expectNotContains(out.decode_c.?, "_frag_begin");
    try expectNotContains(out.encode_c.?, "_frag_begin");
}

test "decode and encode headers declare the public API" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try generateXcodeTest(arena.allocator(),
        \\pair = [ a: uint, b: uint ]
    );
    try expectContains(out.decode_h.?, "int cbor_decode_pair(const uint8_t *payload, size_t payload_len, struct pair *result, size_t *payload_len_out);");
    try expectContains(out.encode_h.?, "int cbor_encode_pair(uint8_t *payload, size_t payload_len, const struct pair *input, size_t *payload_len_out);");
    try expectContains(out.decode_h.?, "#include \"cddl_types.h\"");
}
