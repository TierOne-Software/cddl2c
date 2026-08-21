//! Union disjointness validation.
//!
//! Generated decoders try union ("/") arms in declaration order with
//! backtracking: the FIRST arm that parses wins, and a later arm whose
//! encodings also satisfy an earlier arm is silently unreachable for those
//! inputs (probed: a union of two uint enums misdecoded with no error).
//!
//! This pass rejects such unions before codegen. For every type-level "/"
//! union (rule-level or member-level) it computes, per arm, a signature of
//! the CBOR items the arm can match -- possible outer major types, concrete
//! literal value sets, integer/size ranges, tag numbers, and for maps the
//! required literal keys with their value signatures plus map closedness --
//! and errors when two arms cannot be proven disjoint.
//!
//! Provable disjointness, per shared major type:
//!   uint/nint:  disjoint concrete value sets, or disjoint ranges
//!   tstr/bstr:  disjoint literal sets, or disjoint .size ranges
//!   tag:        different tag numbers
//!   array:      different fixed element counts
//!   map:        a literal key required in both arms with disjoint value
//!               signatures, or one arm closed (no "* any => any", no type
//!               keys) while the other requires a key the closed arm lacks
//!   simple:     disjoint literal sets (true/false/nil/undefined/float lit)
//!
//! "any" as a non-final arm swallows everything after it and is rejected;
//! as the final arm it is accepted as an intentional catch-all.
//!
//! Limitations (documented, conservative = treated as ambiguous):
//!   - group-level "//" choices are not analyzed
//!   - bstr .cbor inner types are not compared (the bstr itself is compared)
//!   - ~typename group unwraps and unresolvable references analyze as "any"

const std = @import("std");
const ast = @import("ast.zig");
const Parser = @import("Parser.zig");

pub const Diagnostic = struct {
    message: []const u8 = "",
    context: []const u8 = "",
};

pub const Error = error{AmbiguousUnion} || std.mem.Allocator.Error;

const MAX_DEPTH = 24;

// Major-type bitmask bits, indexed by CBOR major number 0..7.
const M_UINT: u8 = 1 << 0;
const M_NINT: u8 = 1 << 1;
const M_BSTR: u8 = 1 << 2;
const M_TSTR: u8 = 1 << 3;
const M_ARRAY: u8 = 1 << 4;
const M_MAP: u8 = 1 << 5;
const M_TAG: u8 = 1 << 6;
const M_SIMPLE: u8 = 1 << 7;
const M_ALL: u8 = 0xFF;

const INT_LO: i128 = -(@as(i128, 1) << 64);
const INT_HI: i128 = (@as(i128, 1) << 64) - 1;

const Simple = enum { true_, false_, nil_, undefined_ };

const MapKey = struct {
    int_key: ?i128 = null,
    text_key: ?[]const u8 = null,
    val: Sig,

    fn eql(a: MapKey, b: MapKey) bool {
        if (a.int_key) |ai| {
            if (b.int_key) |bi| return ai == bi;
            return false;
        }
        if (a.text_key) |at| {
            if (b.text_key) |bt| return std.mem.eql(u8, at, bt);
            return false;
        }
        return false;
    }
};

const Sig = struct {
    majors: u8 = 0,
    /// Concrete integer values when fully enumerable (literals, enum groups).
    ints: ?std.ArrayList(i128) = null,
    int_lo: i128 = INT_LO,
    int_hi: i128 = INT_HI,
    /// Concrete text values when fully enumerable.
    texts: ?std.ArrayList([]const u8) = null,
    tstr_lo: u64 = 0,
    tstr_hi: u64 = std.math.maxInt(u64),
    /// Concrete bstr literal contents when fully enumerable (single-quoted
    /// literals like 'F' are byte strings in this parser).
    bytes: ?std.ArrayList([]const u8) = null,
    bstr_lo: u64 = 0,
    bstr_hi: u64 = std.math.maxInt(u64),
    /// Concrete tag numbers when fully enumerable.
    tags: ?std.ArrayList(u64) = null,
    /// Map refinement: all declared literal keys, and the required subset
    /// with value signatures. Closed maps reject undeclared keys.
    map_declared: std.ArrayList(MapKey) = .empty,
    map_required: std.ArrayList(MapKey) = .empty,
    map_open: bool = false,
    /// Fixed array element count, if definite.
    array_len: ?u64 = null,
    /// Concrete simple values when fully enumerable.
    simples: ?std.ArrayList(Simple) = null,
    floats: ?std.ArrayList(f64) = null,

    fn merge(a: *Sig, gpa: std.mem.Allocator, b: Sig) Error!void {
        a.majors |= b.majors;
        if (a.ints != null and b.ints != null) {
            try a.ints.?.appendSlice(gpa, b.ints.?.items);
        } else {
            a.ints = null;
        }
        a.int_lo = @min(a.int_lo, b.int_lo);
        a.int_hi = @max(a.int_hi, b.int_hi);
        if (a.texts != null and b.texts != null) {
            try a.texts.?.appendSlice(gpa, b.texts.?.items);
        } else {
            a.texts = null;
        }
        a.tstr_lo = @min(a.tstr_lo, b.tstr_lo);
        a.tstr_hi = @max(a.tstr_hi, b.tstr_hi);
        if (a.bytes != null and b.bytes != null) {
            try a.bytes.?.appendSlice(gpa, b.bytes.?.items);
        } else {
            a.bytes = null;
        }
        a.bstr_lo = @min(a.bstr_lo, b.bstr_lo);
        a.bstr_hi = @max(a.bstr_hi, b.bstr_hi);
        if (a.tags != null and b.tags != null) {
            try a.tags.?.appendSlice(gpa, b.tags.?.items);
        } else {
            a.tags = null;
        }
        if (a.simples != null and b.simples != null) {
            try a.simples.?.appendSlice(gpa, b.simples.?.items);
        } else {
            a.simples = null;
        }
        if (a.floats != null and b.floats != null) {
            try a.floats.?.appendSlice(gpa, b.floats.?.items);
        } else {
            a.floats = null;
        }
        // Map/array refinements do not merge: a merged sig is only used for
        // outer-type analysis, so drop them.
        a.map_declared = .empty;
        a.map_required = .empty;
        a.map_open = true;
        a.array_len = null;
    }

    fn any() Sig {
        return .{ .majors = M_ALL };
    }
};

const Checker = struct {
    gpa: std.mem.Allocator,
    doc: *const ast.Document,
    diag: *Diagnostic,

    fn fail(self: *Checker, comptime fmt: []const u8, args: anytype, context: []const u8) Error {
        self.diag.message = try std.fmt.allocPrint(self.gpa, fmt, args);
        self.diag.context = context;
        return error.AmbiguousUnion;
    }

    // --- Signature computation ----------------------------------------------

    fn sigOfType(self: *Checker, t: *const ast.Type, depth: usize) Error!Sig {
        if (t.choices.len == 1) return self.sigOfType1(&t.choices[0], depth);
        // Start with empty CONCRETE sets: merge concatenates them, and a
        // single non-enumerable arm drops the set to null (conservative).
        var out = Sig{
            .ints = .empty,
            .texts = .empty,
            .bytes = .empty,
            .tags = .empty,
            .simples = .empty,
            .floats = .empty,
        };
        for (t.choices) |*t1| {
            const s = try self.sigOfType1(t1, depth);
            try out.merge(self.gpa, s);
        }
        return out;
    }

    fn sigOfType1(self: *Checker, t1: *const ast.Type1, depth: usize) Error!Sig {
        var s = try self.sigOfType2(&t1.base, depth);
        if (t1.op) |op| {
            switch (op.kind) {
                .range_incl, .range_excl => {
                    if (self.intFromType2(op.rhs)) |hi_raw| {
                        const hi: i128 = if (op.kind == .range_excl) hi_raw - 1 else hi_raw;
                        if (s.majors & (M_UINT | M_NINT) != 0) {
                            const lo = if (s.ints != null and s.ints.?.items.len == 1)
                                s.ints.?.items[0]
                            else
                                s.int_lo;
                            s.ints = null;
                            s.int_lo = lo;
                            s.int_hi = hi;
                        }
                    }
                },
                .ctl => {
                    if (std.mem.eql(u8, op.ctl, "size")) {
                        if (self.sizeRange(op.rhs)) |r| {
                            if (s.majors & M_TSTR != 0) {
                                s.tstr_lo = r[0];
                                s.tstr_hi = r[1];
                                s.texts = null;
                            }
                            if (s.majors & M_BSTR != 0) {
                                s.bstr_lo = r[0];
                                s.bstr_hi = r[1];
                            }
                            if (s.majors & (M_UINT | M_NINT) != 0 and r[0] == r[1] and r[1] < 16) {
                                s.ints = null;
                                s.int_lo = 0;
                                s.int_hi = (@as(i128, 1) << @intCast(8 * r[1])) - 1;
                            }
                            s.array_len = null;
                        }
                    }
                    // .cbor/.cborseq keep the outer bstr; the inner type is
                    // intentionally not compared (conservative).
                },
            }
        }
        return s;
    }

    fn intFromType2(self: *Checker, t2: *const ast.Type2) ?i128 {
        _ = self;
        return switch (t2.*) {
            .uint => |v| @intCast(v),
            .nint => |v| v,
            else => null,
        };
    }

    /// Extract a [lo, hi] u64 range from a .size right-hand side:
    /// `(1..64)` or a plain uint literal.
    fn sizeRange(self: *Checker, t2: *const ast.Type2) ?[2]u64 {
        switch (t2.*) {
            .uint => |v| return .{ v, v },
            .paren => |t| {
                if (t.single()) |t1| {
                    if (t1.op) |op| {
                        switch (op.kind) {
                            .range_incl, .range_excl => {
                                const lo = self.intFromType2(&t1.base) orelse return null;
                                var hi = self.intFromType2(op.rhs) orelse return null;
                                if (op.kind == .range_excl) hi -= 1;
                                if (lo < 0 or hi < 0) return null;
                                return .{ @intCast(lo), @intCast(hi) };
                            },
                            else => {},
                        }
                    }
                    return switch (t1.base) {
                        .uint => |v| .{ v, v },
                        else => null,
                    };
                }
                return null;
            },
            else => return null,
        }
    }

    fn sigOfType2(self: *Checker, t2: *const ast.Type2, depth: usize) Error!Sig {
        if (depth > MAX_DEPTH) return Sig.any();
        switch (t2.*) {
            .uint => |v| {
                var s = Sig{ .majors = M_UINT, .int_lo = 0, .int_hi = INT_HI };
                s.ints = .empty;
                try s.ints.?.append(self.gpa, @intCast(v));
                return s;
            },
            .nint => |v| {
                var s = Sig{ .majors = M_NINT, .int_lo = INT_LO, .int_hi = -1 };
                s.ints = .empty;
                try s.ints.?.append(self.gpa, v);
                return s;
            },
            .float => |v| {
                var s = Sig{ .majors = M_SIMPLE };
                s.floats = .empty;
                try s.floats.?.append(self.gpa, v);
                return s;
            },
            .tstr => |v| {
                var s = Sig{ .majors = M_TSTR };
                s.texts = .empty;
                try s.texts.?.append(self.gpa, v);
                s.tstr_lo = @intCast(v.len);
                s.tstr_hi = @intCast(v.len);
                return s;
            },
            .bstr => |v| {
                var s = Sig{ .majors = M_BSTR };
                s.bytes = .empty;
                try s.bytes.?.append(self.gpa, v);
                s.bstr_lo = @intCast(v.len);
                s.bstr_hi = @intCast(v.len);
                return s;
            },
            .typename => |name| return self.sigOfTypename(name, depth),
            .paren => |t| return self.sigOfType(t, depth + 1),
            .map => |g| return self.sigOfMap(g, depth),
            .array => |g| return self.sigOfArray(g, depth),
            .enum_inline => |g| return self.sigOfEnumGroup(g.*, depth),
            .enum_ref => |ref| {
                const rule = self.doc.find(ref) orelse return Sig.any();
                return switch (rule.value) {
                    .group => |g| self.sigOfEnumGroup(g, depth + 1),
                    .type => Sig.any(),
                };
            },
            .unwrap => return Sig.any(),
            .tagged => |tg| {
                var s = Sig{ .majors = M_TAG };
                if (tg.tag) |n| {
                    s.tags = .empty;
                    try s.tags.?.append(self.gpa, n);
                }
                return s;
            },
            .major => |m| {
                var s = Sig{ .majors = 0 };
                if (m.major < 8) s.majors = @as(u8, 1) << @intCast(m.major);
                return s;
            },
            .any => return Sig.any(),
        }
    }

    fn sigOfTypename(self: *Checker, name: []const u8, depth: usize) Error!Sig {
        const Builtin = struct { name: []const u8, majors: u8 };
        const builtins = [_]Builtin{
            .{ .name = "uint", .majors = M_UINT },
            .{ .name = "nint", .majors = M_NINT },
            .{ .name = "int", .majors = M_UINT | M_NINT },
            .{ .name = "bstr", .majors = M_BSTR },
            .{ .name = "bytes", .majors = M_BSTR },
            .{ .name = "encoded-cbor", .majors = M_BSTR },
            .{ .name = "tstr", .majors = M_TSTR },
            .{ .name = "text", .majors = M_TSTR },
            .{ .name = "uri", .majors = M_TSTR },
            .{ .name = "tdate", .majors = M_TSTR },
            .{ .name = "eb64url", .majors = M_TSTR },
            .{ .name = "eb64legacy", .majors = M_TSTR },
            .{ .name = "eb16", .majors = M_TSTR },
            .{ .name = "b64url", .majors = M_TSTR },
            .{ .name = "b64legacy", .majors = M_TSTR },
            .{ .name = "regexp", .majors = M_TSTR },
            .{ .name = "mime-message", .majors = M_TSTR },
            .{ .name = "bool", .majors = M_SIMPLE },
            .{ .name = "float", .majors = M_SIMPLE },
            .{ .name = "float16", .majors = M_SIMPLE },
            .{ .name = "float32", .majors = M_SIMPLE },
            .{ .name = "float64", .majors = M_SIMPLE },
            .{ .name = "float16-32", .majors = M_SIMPLE },
            .{ .name = "float32-64", .majors = M_SIMPLE },
            .{ .name = "number", .majors = M_UINT | M_NINT | M_SIMPLE },
            .{ .name = "any", .majors = M_ALL },
        };
        for (builtins) |b| {
            if (std.mem.eql(u8, name, b.name)) {
                var s = Sig{ .majors = b.majors };
                if (b.majors == M_UINT) {
                    s.int_lo = 0;
                } else if (b.majors == M_NINT) {
                    s.int_hi = -1;
                }
                return s;
            }
        }
        // Simple literals are typenames at the AST level.
        const simples = [_]struct { name: []const u8, v: Simple }{
            .{ .name = "true", .v = .true_ },
            .{ .name = "false", .v = .false_ },
            .{ .name = "nil", .v = .nil_ },
            .{ .name = "null", .v = .nil_ },
            .{ .name = "undefined", .v = .undefined_ },
        };
        for (simples) |b| {
            if (std.mem.eql(u8, name, b.name)) {
                var s = Sig{ .majors = M_SIMPLE };
                s.simples = .empty;
                try s.simples.?.append(self.gpa, b.v);
                return s;
            }
        }
        const rule = self.doc.find(name) orelse return Sig.any();
        return switch (rule.value) {
            .type => |*t| self.sigOfType(t, depth + 1),
            .group => Sig.any(), // group rules appear via ~unwrap; not analyzable here
        };
    }

    /// Integer/text values of an enumeration group (&(...) or &ref).
    fn sigOfEnumGroup(self: *Checker, g: ast.Group, depth: usize) Error!Sig {
        var s = Sig{};
        s.ints = .empty;
        s.texts = .empty;
        var next_value: i128 = 0;
        for (g.choices) |choice| {
            for (choice.entries) |entry| {
                const et = switch (entry.value) {
                    .type => |et| et,
                    .inline_group => return Sig.any(),
                };
                const t1 = et.single() orelse return Sig.any();
                var value: i128 = next_value;
                var got_int = true;
                switch (t1.base) {
                    .uint => |v| value = @intCast(v),
                    .nint => |v| value = v,
                    .tstr => |txt| {
                        try s.texts.?.append(self.gpa, txt);
                        s.majors |= M_TSTR;
                        got_int = false;
                    },
                    .typename => |ref| {
                        // Reference to a named literal rule.
                        const rule = self.doc.find(ref) orelse return Sig.any();
                        const rt = switch (rule.value) {
                            .type => |*t| t.*,
                            .group => return Sig.any(),
                        };
                        const rt1 = rt.single() orelse return Sig.any();
                        switch (rt1.base) {
                            .uint => |v| value = @intCast(v),
                            .nint => |v| value = v,
                            else => return Sig.any(),
                        }
                    },
                    else => return Sig.any(),
                }
                if (got_int) {
                    try s.ints.?.append(self.gpa, value);
                    s.majors |= if (value >= 0) M_UINT else M_NINT;
                    next_value = value + 1;
                }
            }
        }
        _ = depth;
        return s;
    }

    fn sigOfMap(self: *Checker, g: ast.Group, depth: usize) Error!Sig {
        var s = Sig{ .majors = M_MAP };
        if (g.choices.len > 1) return s; // "//" alternatives: not analyzed
        for (g.choices[0].entries) |entry| {
            var k = MapKey{ .val = Sig.any() };
            switch (entry.key orelse continue) {
                .bareword => |w| k.text_key = w,
                .value => |v| switch (v) {
                    .uint => |n| k.int_key = @intCast(n),
                    .nint => |n| k.int_key = n,
                    .tstr => |txt| k.text_key = txt,
                    else => continue,
                },
                .type => {
                    // Non-literal key (tstr => ..., * any => any): the map
                    // accepts keys we cannot enumerate. Checked BEFORE the
                    // required-filter: the extension point has occur 0*.
                    s.map_open = true;
                    continue;
                },
            }
            try s.map_declared.append(self.gpa, k);
            if (entry.occur.min > 0) {
                k.val = switch (entry.value) {
                    .type => |*et| try self.sigOfType(et, depth + 1),
                    .inline_group => Sig.any(),
                };
                try s.map_required.append(self.gpa, k);
            }
        }
        return s;
    }

    fn sigOfArray(self: *Checker, g: ast.Group, depth: usize) Error!Sig {
        _ = self;
        _ = depth;
        var s = Sig{ .majors = M_ARRAY };
        if (g.choices.len == 1) {
            var fixed = true;
            for (g.choices[0].entries) |entry| {
                if (!entry.occur.isOne()) {
                    fixed = false;
                    break;
                }
            }
            if (fixed) s.array_len = @intCast(g.choices[0].entries.len);
        }
        return s;
    }

    // --- Disjointness ---------------------------------------------------------

    fn intsDisjoint(a: *const Sig, b: *const Sig) bool {
        if (a.ints != null and b.ints != null) {
            for (a.ints.?.items) |x| {
                for (b.ints.?.items) |y| {
                    if (x == y) return false;
                }
            }
            return true;
        }
        // Fall back to range overlap.
        return a.int_hi < b.int_lo or b.int_hi < a.int_lo;
    }

    fn textsDisjoint(a: []const []const u8, b: []const []const u8) bool {
        for (a) |x| {
            for (b) |y| {
                if (std.mem.eql(u8, x, y)) return false;
            }
        }
        return true;
    }

    fn mapHasKey(declared: []const MapKey, k: MapKey) bool {
        for (declared) |d| {
            if (d.eql(k)) return true;
        }
        return false;
    }

    fn mapsDisjoint(a: *const Sig, b: *const Sig) bool {
        // A literal key required in both arms whose value signatures are
        // disjoint proves no payload can satisfy both.
        for (a.map_required.items) |ka| {
            for (b.map_required.items) |kb| {
                if (ka.eql(kb) and provablyDisjoint(&ka.val, &kb.val)) return true;
            }
        }
        // Missing-key argument, either direction: if arm X requires key k
        // and arm Y is CLOSED (rejects undeclared keys) without declaring k,
        // then no payload can satisfy both -- Y's payloads never carry k
        // (closed maps contain only declared keys), and any payload with k
        // is rejected by Y. Note Y's closedness is essential: an OPEN map's
        // payloads may carry any extra key, including k.
        if (!b.map_open) {
            for (a.map_required.items) |ka| {
                if (!mapHasKey(b.map_declared.items, ka)) return true;
            }
        }
        if (!a.map_open) {
            for (b.map_required.items) |kb| {
                if (!mapHasKey(a.map_declared.items, kb)) return true;
            }
        }
        return false;
    }

    fn simplesDisjoint(a: *const Sig, b: *const Sig) bool {
        if (a.simples != null and b.simples != null) {
            for (a.simples.?.items) |x| {
                for (b.simples.?.items) |y| {
                    if (x == y) return false;
                }
            }
            if (a.floats == null or b.floats == null) return true;
        }
        if (a.floats != null and b.floats != null) {
            for (a.floats.?.items) |x| {
                for (b.floats.?.items) |y| {
                    if (x == y) return false;
                }
            }
            if (a.simples == null or b.simples == null) return true;
            return true;
        }
        return false;
    }

    fn provablyDisjoint(a: *const Sig, b: *const Sig) bool {
        const shared = a.majors & b.majors;
        if (shared == 0) return true;
        if (shared & (M_UINT | M_NINT) != 0 and !intsDisjoint(a, b)) return false;
        if (shared & M_TSTR != 0) {
            const ok = if (a.texts != null and b.texts != null)
                textsDisjoint(a.texts.?.items, b.texts.?.items)
            else
                (a.tstr_hi < b.tstr_lo or b.tstr_hi < a.tstr_lo);
            if (!ok) return false;
        }
        if (shared & M_BSTR != 0) {
            const ok = if (a.bytes != null and b.bytes != null)
                textsDisjoint(a.bytes.?.items, b.bytes.?.items)
            else
                (a.bstr_hi < b.bstr_lo or b.bstr_hi < a.bstr_lo);
            if (!ok) return false;
        }
        if (shared & M_TAG != 0) {
            const ok = if (a.tags != null and b.tags != null) blk: {
                for (a.tags.?.items) |x| {
                    for (b.tags.?.items) |y| {
                        if (x == y) return false;
                    }
                }
                break :blk true;
            } else false;
            if (!ok) return false;
        }
        if (shared & M_MAP != 0 and !mapsDisjoint(a, b)) return false;
        if (shared & M_ARRAY != 0) {
            const ok = if (a.array_len != null and b.array_len != null)
                a.array_len.? != b.array_len.?
            else
                false;
            if (!ok) return false;
        }
        if (shared & M_SIMPLE != 0 and !simplesDisjoint(a, b)) return false;
        return true;
    }

    fn majorNames(self: *Checker, mask: u8) Error![]const u8 {
        const names = [_][]const u8{ "uint", "nint", "bstr", "tstr", "array", "map", "tag", "simple/float" };
        var out: std.ArrayList(u8) = .empty;
        var first = true;
        for (names, 0..) |n, i| {
            if (mask & (@as(u8, 1) << @intCast(i)) != 0) {
                if (!first) try out.appendSlice(self.gpa, "/");
                try out.appendSlice(self.gpa, n);
                first = false;
            }
        }
        return out.items;
    }

    // --- Union discovery and checking -----------------------------------------

    fn checkUnion(self: *Checker, choices: []const ast.Type1, context: []const u8) Error!void {
        var sigs = try self.gpa.alloc(Sig, choices.len);
        for (choices, 0..) |*t1, i| {
            sigs[i] = try self.sigOfType1(t1, 0);
        }
        // A final arm that matches anything is an intentional catch-all;
        // exclude it from pairwise checks.
        const last = choices.len - 1;
        const catch_all = sigs[last].majors == M_ALL;
        for (choices, 0..) |*t1, i| {
            _ = t1;
            // An arm that matches anything swallows every later arm.
            if (sigs[i].majors == M_ALL and i + 1 < choices.len) {
                return self.fail(
                    "union arm {d} ('any'-like) matches every CBOR item, making {d} later arm(s) unreachable; move it last or remove it",
                    .{ i + 1, choices.len - i - 1 },
                    context,
                );
            }
            for (i + 1..choices.len) |j| {
                if (catch_all and j == last) continue;
                if (!provablyDisjoint(&sigs[i], &sigs[j])) {
                    const shared = sigs[i].majors & sigs[j].majors;
                    return self.fail(
                        "union arms {d} and {d} are not provably disjoint (both can start with {s}); the generated decoder tries arms in order and the first match wins silently -- give each arm a distinct outer CBOR type, disjoint values, or its own msg-type",
                        .{ i + 1, j + 1, try self.majorNames(shared) },
                        context,
                    );
                }
            }
        }
    }

    fn walkType(self: *Checker, t: *const ast.Type, context: []const u8, depth: usize) Error!void {
        if (depth > MAX_DEPTH) return;
        if (t.choices.len > 1) try self.checkUnion(t.choices, context);
        for (t.choices) |*t1| try self.walkType1(t1, context, depth);
    }

    fn walkType1(self: *Checker, t1: *const ast.Type1, context: []const u8, depth: usize) Error!void {
        switch (t1.base) {
            .paren => |t| try self.walkType(t, context, depth + 1),
            .map, .array => |g| try self.walkGroup(g, context, depth + 1),
            .enum_inline => |g| try self.walkGroup(g.*, context, depth + 1),
            .tagged => |tg| try self.walkType(tg.inner, context, depth + 1),
            else => {},
        }
    }

    fn walkGroup(self: *Checker, g: ast.Group, context: []const u8, depth: usize) Error!void {
        if (depth > MAX_DEPTH) return;
        for (g.choices) |choice| {
            for (choice.entries) |entry| {
                switch (entry.value) {
                    .type => |*et| try self.walkType(et, context, depth + 1),
                    .inline_group => |ig| try self.walkGroup(ig.*, context, depth + 1),
                }
            }
        }
    }
};

/// Reject unions whose arms are not provably disjoint. Runs over every rule,
/// including member-level unions inside maps and arrays.
pub fn checkAmbiguousUnions(
    gpa: std.mem.Allocator,
    doc: *const ast.Document,
    diag: *Diagnostic,
) Error!void {
    var c = Checker{ .gpa = gpa, .doc = doc, .diag = diag };
    for (doc.rules) |*rule| {
        switch (rule.value) {
            .type => |*t| try c.walkType(t, rule.name, 0),
            .group => |*g| try c.walkGroup(g.*, rule.name, 0),
        }
    }
}

// --- Tests ---------------------------------------------------------------------

fn expectOk(src: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var pdiag: Parser.Diagnostic = .{};
    const doc = Parser.parse(arena.allocator(), src, &pdiag) catch unreachable;
    var vdiag: Diagnostic = .{};
    try checkAmbiguousUnions(arena.allocator(), &doc, &vdiag);
}

fn expectAmbiguous(src: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var pdiag: Parser.Diagnostic = .{};
    const doc = Parser.parse(arena.allocator(), src, &pdiag) catch unreachable;
    var vdiag: Diagnostic = .{};
    try std.testing.expectError(
        error.AmbiguousUnion,
        checkAmbiguousUnions(arena.allocator(), &doc, &vdiag),
    );
}

test "disjoint int enums are accepted" {
    try expectOk(
        \\reset-code = &( power: 1, watchdog: 2 )
        \\net-profile = &( home: 10, guest: 11 )
        \\cmd = reset-code / net-profile
        \\
    );
}

test "overlapping int enums are rejected (the union-probe bug)" {
    try expectAmbiguous(
        \\reset-code = &( power: 1, clear: 2 )
        \\net-profile = &( home: 1, guest: 2 )
        \\cmd = reset-code / net-profile
        \\
    );
}

test "different outer majors are accepted" {
    try expectOk(
        \\event = uint / tstr / [ uint ]
        \\
    );
}

test "same unbounded major is rejected" {
    try expectAmbiguous(
        \\v = uint / int
        \\
    );
}

test "disjoint int ranges are accepted, overlapping rejected" {
    try expectOk(
        \\v = 0..100 / 200..300
        \\
    );
    try expectAmbiguous(
        \\v = 0..100 / 100..200
        \\
    );
}

test "tag numbers discriminate" {
    try expectOk(
        \\v = #6.1(uint) / #6.2(uint)
        \\
    );
    try expectAmbiguous(
        \\v = #6.1(uint) / #6.1(tstr)
        \\
    );
}

test "text literals discriminate; size overlap rejected" {
    try expectOk(
        \\vat = 'F' / 'L' / 'R'
        \\
    );
    try expectAmbiguous(
        \\v = tstr / tstr .size 2
        \\
    );
    try expectOk(
        \\v = tstr .size 1 / tstr .size (2..8)
        \\
    );
}

test "maps: closed arm with missing required key is disjoint" {
    try expectOk(
        \\config = { name: tstr, port: uint }
        \\file-msg = { filename: tstr, data: bstr }
        \\report = config / file-msg
        \\
    );
}

test "maps: same required key with disjoint values is disjoint" {
    try expectOk(
        \\a = { 0 => tstr, 1 => uint }
        \\b = { 0 => bool, 2 => uint }
        \\v = a / b
        \\
    );
}

test "maps: identical shapes are rejected" {
    try expectAmbiguous(
        \\a = { 0 => uint, 1 => tstr }
        \\b = { 0 => uint, 1 => tstr }
        \\v = a / b
        \\
    );
}

test "maps: distinct required key sets are disjoint even when closed" {
    try expectOk(
        \\a = { 0 => uint, 1 => tstr }
        \\b = { 0 => uint, 2 => tstr }
        \\v = a / b
        \\
    );
}

test "maps: open extension point defeats closedness proof" {
    try expectAmbiguous(
        \\a = { 0 => uint, * any => any }
        \\b = { 0 => uint, 1 => tstr }
        \\v = a / b
        \\
    );
}

test "member-level unions are checked" {
    try expectAmbiguous(
        \\m = { 0 => uint, ? 1 => uint / int }
        \\
    );
    try expectOk(
        \\m = { 0 => uint, ? 1 => uint / tstr }
        \\
    );
}

test "fixed-length arrays discriminate by element count" {
    try expectOk(
        \\a = [ uint, uint ]
        \\b = [ uint ]
        \\v = a / b
        \\
    );
    try expectAmbiguous(
        \\a = [ uint, uint ]
        \\b = [ tstr, tstr ]
        \\v = a / b
        \\
    );
}

test "any is only allowed as the final arm" {
    try expectAmbiguous(
        \\v = any / uint
        \\
    );
    try expectOk(
        \\v = uint / any
        \\
    );
}

test "simple literals discriminate" {
    try expectOk(
        \\v = true / false
        \\
    );
    try expectAmbiguous(
        \\v = true / bool
        \\
    );
}

test "named-rule indirection is resolved" {
    try expectOk(
        \\temp = uint
        \\pos = { 0 => uint }
        \\v = temp / pos
        \\
    );
    try expectAmbiguous(
        \\a = uint
        \\b = 0..10
        \\v = a / b
        \\
    );
}

test "maps: named text-literal union discriminates a shared key" {
    // The telemetry-mapping field rule: scalar-field's "type" is a named
    // union of text literals; the object arm's "type" is the literal
    // "object". The literal sets are disjoint -> the arms are disjoint.
    try expectOk(
        \\scalar-type = "ts" / "int" / "bool"
        \\scalar-field = { "key": uint, "type": scalar-type, * any => any }
        \\field = scalar-field / { "key": uint, "type": "object", * any => any }
        \\
    );
}

test "sample-schema-shaped unions pass" {
    try expectOk(
        \\colors = &( red: 0, green: 1, blue: 2 )
        \\reading = [ id: uint, value: float32 ]
        \\config = { name: tstr, color: colors }
        \\file-msg = { filename: tstr, data: bstr }
        \\event = reading / config / 0 / 1
        \\report = config / file-msg
        \\
    );
}
