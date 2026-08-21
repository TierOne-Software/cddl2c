//! AST for the supported subset of CDDL (RFC 8610).
//!
//! All slices are either views into the source text or arena allocations owned
//! by the caller-provided allocator; nothing here is individually freed.

const std = @import("std");

pub const Document = struct {
    rules: []Rule,

    pub fn find(self: *const Document, name: []const u8) ?*Rule {
        for (self.rules) |*rule| {
            if (std.mem.eql(u8, rule.name, name)) return rule;
        }
        return null;
    }
};

pub const Rule = struct {
    name: []const u8,
    value: Value,

    pub const Value = union(enum) {
        type: Type,
        group: Group,
    };
};

/// A type: one or more "/" choices.
pub const Type = struct {
    choices: []Type1,

    /// The single choice, if there is exactly one.
    pub fn single(self: *const Type) ?*Type1 {
        return if (self.choices.len == 1) &self.choices[0] else null;
    }
};

/// type2 with an optional range or control operator.
pub const Type1 = struct {
    base: Type2,
    op: ?OpExpr = null,
};

pub const OpExpr = struct {
    kind: Kind,
    /// Control operator name without the leading dot (e.g. "size", "cbor").
    ctl: []const u8 = "",
    rhs: *Type2,

    pub const Kind = enum { range_incl, range_excl, ctl };
};

pub const Type2 = union(enum) {
    uint: u64,
    nint: i64,
    float: f64,
    /// Text literal; escapes are resolved.
    tstr: []const u8,
    /// Byte string literal; decoded bytes.
    bstr: []const u8,
    typename: []const u8,
    paren: *Type,
    map: Group,
    array: Group,
    /// "&groupname": enumeration built from a named group.
    enum_ref: []const u8,
    /// "&( ... )": enumeration built from an inline group.
    enum_inline: *Group,
    /// "~typename"
    unwrap: []const u8,
    /// "#6.<tag>(type)"
    tagged: Tagged,
    /// "#N" / "#N.M"
    major: MajorAi,
    /// "#"
    any,
};

pub const Tagged = struct {
    tag: ?u64,
    inner: *Type,
};

pub const MajorAi = struct {
    major: u8,
    ai: ?u64,
};

/// One or more "//" choices.
pub const Group = struct {
    choices: []GroupChoice,
};

pub const GroupChoice = struct {
    entries: []Entry,
};

pub const Entry = struct {
    occur: Occur = .{},
    key: ?Key = null,
    value: EntryValue,
};

/// Occurrence: min..max repetitions; max == null means unbounded.
pub const Occur = struct {
    min: u64 = 1,
    max: ?u64 = 1,

    pub fn isOne(self: Occur) bool {
        return self.min == 1 and self.max != null and self.max.? == 1;
    }

    pub fn isOptional(self: Occur) bool {
        return self.min == 0 and self.max != null and self.max.? == 1;
    }
};

pub const Key = union(enum) {
    /// "name: ..." member key.
    bareword: []const u8,
    /// Literal value key: `1 => ...`, `"key" => ...`, `"key": ...`.
    value: Type2,
    /// Full type key: `tstr => ...`.
    type: *Type1,
};

pub const EntryValue = union(enum) {
    type: Type,
    /// "( group )" appearing as a group entry.
    inline_group: *Group,
};
