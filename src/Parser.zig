//! Recursive-descent parser for the supported subset of CDDL (RFC 8610).
//!
//! The whole input is lexed up front so the parser can backtrack cheaply
//! (needed to disambiguate member keys from entry types).

const std = @import("std");
const Tokenizer = @import("Tokenizer.zig");
const ast = @import("ast.zig");

const Token = Tokenizer.Token;
const Parser = @This();

gpa: std.mem.Allocator,
src: []const u8,
tokens: []Token,
index: usize = 0,
diag: *Diagnostic,
nest: usize = 0,

/// Nesting bound for types/groups: keeps hostile input ("((((((...") from
/// overflowing the stack while allowing any realistic schema.
const max_nesting = 128;

pub const Diagnostic = struct {
    line: usize = 0,
    column: usize = 0,
    message: []const u8 = "",
};

pub const Error = error{ ParseError, OutOfMemory };

/// Parse a CDDL document. `gpa` should be an arena; AST nodes are never
/// individually freed. On error.ParseError, `diag` is filled in.
pub fn parse(gpa: std.mem.Allocator, source: []const u8, diag: *Diagnostic) Error!ast.Document {
    var tokens: std.ArrayList(Token) = .empty;
    var tz = Tokenizer.init(source);
    while (true) {
        const tok = tz.next();
        try tokens.append(gpa, tok);
        if (tok.kind == .eof) break;
    }

    var parser = Parser{
        .gpa = gpa,
        .src = source,
        .tokens = tokens.items,
        .diag = diag,
    };
    return parser.parseDocument();
}

fn peek(self: *const Parser) Token {
    return self.tokens[self.index];
}

fn peekKind(self: *const Parser) Token.Kind {
    return self.tokens[self.index].kind;
}

fn peekKindAt(self: *const Parser, offset: usize) Token.Kind {
    const i = @min(self.index + offset, self.tokens.len - 1);
    return self.tokens[i].kind;
}

fn advance(self: *Parser) Token {
    const tok = self.tokens[self.index];
    if (self.index + 1 < self.tokens.len) self.index += 1;
    return tok;
}

fn tokenText(self: *const Parser, tok: Token) []const u8 {
    return self.src[tok.start..tok.end];
}

fn expect(self: *Parser, kind: Token.Kind, message: []const u8) Error!Token {
    if (self.peekKind() != kind) return self.fail(message);
    return self.advance();
}

fn fail(self: *Parser, message: []const u8) Error {
    const tok = self.peek();
    const lc = Tokenizer.lineColumn(self.src, tok.start);
    self.diag.* = .{ .line = lc.line, .column = lc.column, .message = message };
    return error.ParseError;
}

fn parseDocument(self: *Parser) Error!ast.Document {
    var rules: std.ArrayList(ast.Rule) = .empty;

    while (self.peekKind() != .eof) {
        const name_tok = try self.expect(.ident, "expected rule name");
        const name = self.tokenText(name_tok);

        // Generic parameters are recognized but ignored.
        if (self.peekKind() == .langle) try self.skipAngleBrackets();

        const assign_kind = self.peekKind();
        switch (assign_kind) {
            .assign, .type_choice_assign, .group_choice_assign => _ = self.advance(),
            else => return self.fail("expected '=', '/=' or '//=' after rule name"),
        }

        const value: ast.Rule.Value = if (self.peekKind() == .lparen) blk: {
            _ = self.advance();
            const group = try self.parseGroup();
            _ = try self.expect(.rparen, "expected ')' to close group rule");
            break :blk .{ .group = group };
        } else .{ .type = try self.parseType() };

        // "/=" and "//=" extend an existing rule with more choices;
        // a second plain "=" for the same name is an error (RFC 8610).
        var merged = false;
        for (rules.items) |*existing| {
            if (!std.mem.eql(u8, existing.name, name)) continue;
            if (assign_kind == .assign) return self.fail("duplicate rule name");
            try self.mergeRule(existing, value);
            merged = true;
            break;
        }
        if (!merged) {
            try rules.append(self.gpa, .{ .name = name, .value = value });
        }
    }

    return .{ .rules = try rules.toOwnedSlice(self.gpa) };
}

fn mergeRule(self: *Parser, existing: *ast.Rule, addition: ast.Rule.Value) Error!void {
    switch (existing.value) {
        .type => |*t| {
            const extra = switch (addition) {
                .type => |at| at.choices,
                .group => return self.fail("cannot extend a type rule with a group choice"),
            };
            const combined = try self.gpa.alloc(ast.Type1, t.choices.len + extra.len);
            @memcpy(combined[0..t.choices.len], t.choices);
            @memcpy(combined[t.choices.len..], extra);
            t.choices = combined;
        },
        .group => |*g| {
            const extra = switch (addition) {
                .group => |ag| ag.choices,
                .type => return self.fail("cannot extend a group rule with a type choice"),
            };
            const combined = try self.gpa.alloc(ast.GroupChoice, g.choices.len + extra.len);
            @memcpy(combined[0..g.choices.len], g.choices);
            @memcpy(combined[g.choices.len..], extra);
            g.choices = combined;
        },
    }
}

fn skipAngleBrackets(self: *Parser) Error!void {
    _ = try self.expect(.langle, "expected '<'");
    var depth: usize = 1;
    while (depth > 0) {
        switch (self.peekKind()) {
            .langle => depth += 1,
            .rangle => depth -= 1,
            .eof => return self.fail("unterminated '<...>'"),
            else => {},
        }
        _ = self.advance();
    }
}

// --- Types -------------------------------------------------------------------

fn parseType(self: *Parser) Error!ast.Type {
    var choices: std.ArrayList(ast.Type1) = .empty;
    try choices.append(self.gpa, try self.parseType1());
    while (self.peekKind() == .slash) {
        _ = self.advance();
        try choices.append(self.gpa, try self.parseType1());
    }
    return .{ .choices = try choices.toOwnedSlice(self.gpa) };
}

fn parseType1(self: *Parser) Error!ast.Type1 {
    const base = try self.parseType2();
    switch (self.peekKind()) {
        .range_incl, .range_excl => {
            const kind: ast.OpExpr.Kind = if (self.peekKind() == .range_incl) .range_incl else .range_excl;
            _ = self.advance();
            const rhs = try self.gpa.create(ast.Type2);
            rhs.* = try self.parseType2();
            return .{ .base = base, .op = .{ .kind = kind, .rhs = rhs } };
        },
        .ctlop => {
            const tok = self.advance();
            const rhs = try self.gpa.create(ast.Type2);
            rhs.* = try self.parseType2();
            return .{ .base = base, .op = .{
                .kind = .ctl,
                .ctl = self.tokenText(tok)[1..], // strip the dot
                .rhs = rhs,
            } };
        },
        else => return .{ .base = base },
    }
}

fn parseType2(self: *Parser) Error!ast.Type2 {
    self.nest += 1;
    defer self.nest -= 1;
    if (self.nest > max_nesting) return self.fail("nesting too deep");
    switch (self.peekKind()) {
        .uint_lit => {
            const tok = self.advance();
            const val = std.fmt.parseInt(u64, self.tokenText(tok), 0) catch
                return self.fail("invalid unsigned integer literal");
            return .{ .uint = val };
        },
        .int_lit => {
            const tok = self.advance();
            const val = std.fmt.parseInt(i64, self.tokenText(tok), 0) catch
                return self.fail("invalid integer literal");
            return .{ .nint = val };
        },
        .float_lit => {
            const tok = self.advance();
            const val = std.fmt.parseFloat(f64, self.tokenText(tok)) catch
                return self.fail("invalid float literal");
            return .{ .float = val };
        },
        .tstr_lit => {
            const tok = self.advance();
            return .{ .tstr = try self.unescapeText(self.tokenText(tok)) };
        },
        .bstr_lit => {
            const tok = self.advance();
            return .{ .bstr = try self.decodeBytes(self.tokenText(tok)) };
        },
        .ident => {
            const tok = self.advance();
            if (self.peekKind() == .langle) try self.skipAngleBrackets();
            return .{ .typename = self.tokenText(tok) };
        },
        .lparen => {
            _ = self.advance();
            const inner = try self.gpa.create(ast.Type);
            inner.* = try self.parseType();
            _ = try self.expect(.rparen, "expected ')'");
            return .{ .paren = inner };
        },
        .lbrace => {
            _ = self.advance();
            const group = try self.parseGroup();
            _ = try self.expect(.rbrace, "expected '}'");
            return .{ .map = group };
        },
        .lbracket => {
            _ = self.advance();
            const group = try self.parseGroup();
            _ = try self.expect(.rbracket, "expected ']'");
            return .{ .array = group };
        },
        .amp => {
            _ = self.advance();
            if (self.peekKind() == .lparen) {
                _ = self.advance();
                const group = try self.gpa.create(ast.Group);
                group.* = try self.parseGroup();
                _ = try self.expect(.rparen, "expected ')' after '&('");
                return .{ .enum_inline = group };
            }
            const tok = try self.expect(.ident, "expected group name after '&'");
            return .{ .enum_ref = self.tokenText(tok) };
        },
        .tilde => {
            _ = self.advance();
            const tok = try self.expect(.ident, "expected type name after '~'");
            if (self.peekKind() == .langle) try self.skipAngleBrackets();
            return .{ .unwrap = self.tokenText(tok) };
        },
        .hash => {
            const tok = self.advance();
            const spec = self.tokenText(tok)[1..]; // strip '#'
            if (spec.len == 0) return .any;

            const dot = std.mem.indexOfScalar(u8, spec, '.');
            const major = std.fmt.parseInt(u8, if (dot) |d| spec[0..d] else spec, 10) catch
                return self.fail("invalid major type after '#'");
            const ai: ?u64 = if (dot) |d|
                std.fmt.parseInt(u64, spec[d + 1 ..], 10) catch
                    return self.fail("invalid additional info after '#N.'")
            else
                null;

            if (major == 6 and self.peekKind() == .lparen) {
                _ = self.advance();
                const inner = try self.gpa.create(ast.Type);
                inner.* = try self.parseType();
                _ = try self.expect(.rparen, "expected ')' after tag content");
                return .{ .tagged = .{ .tag = ai, .inner = inner } };
            }
            return .{ .major = .{ .major = major, .ai = ai } };
        },
        else => return self.fail("expected a type"),
    }
}

// --- Groups ------------------------------------------------------------------

fn atGroupEnd(self: *const Parser) bool {
    return switch (self.peekKind()) {
        .rparen, .rbrace, .rbracket, .eof => true,
        else => false,
    };
}

fn parseGroup(self: *Parser) Error!ast.Group {
    self.nest += 1;
    defer self.nest -= 1;
    if (self.nest > max_nesting) return self.fail("nesting too deep");
    var group_choices: std.ArrayList(ast.GroupChoice) = .empty;
    var entries: std.ArrayList(ast.Entry) = .empty;

    while (true) {
        if (self.atGroupEnd()) break;
        if (self.peekKind() == .dslash) {
            _ = self.advance();
            try group_choices.append(self.gpa, .{ .entries = try entries.toOwnedSlice(self.gpa) });
            entries = .empty;
            continue;
        }
        try entries.append(self.gpa, try self.parseEntry());
        if (self.peekKind() == .comma) _ = self.advance();
    }

    try group_choices.append(self.gpa, .{ .entries = try entries.toOwnedSlice(self.gpa) });
    return .{ .choices = try group_choices.toOwnedSlice(self.gpa) };
}

fn parseEntry(self: *Parser) Error!ast.Entry {
    const occur = try self.parseOccur();

    // "( group )" as a group entry.
    if (self.peekKind() == .lparen) {
        _ = self.advance();
        const group = try self.gpa.create(ast.Group);
        group.* = try self.parseGroup();
        _ = try self.expect(.rparen, "expected ')'");
        return .{ .occur = occur, .value = .{ .inline_group = group } };
    }

    // "bareword:" member key.
    if (self.peekKind() == .ident and self.peekKindAt(1) == .colon) {
        const tok = self.advance();
        _ = self.advance(); // colon
        return .{
            .occur = occur,
            .key = .{ .bareword = self.tokenText(tok) },
            .value = .{ .type = try self.parseType() },
        };
    }

    // "value:" member key (text/number literal).
    switch (self.peekKind()) {
        .uint_lit, .int_lit, .float_lit, .tstr_lit, .bstr_lit => {
            if (self.peekKindAt(1) == .colon) {
                const key = try self.parseType2();
                _ = self.advance(); // colon
                return .{
                    .occur = occur,
                    .key = .{ .value = key },
                    .value = .{ .type = try self.parseType() },
                };
            }
        },
        else => {},
    }

    // Either "type1 [^] => type" (type member key) or a plain type entry.
    const saved = self.index;
    const maybe_key = try self.parseType1();
    if (self.peekKind() == .caret) _ = self.advance(); // cut marker
    if (self.peekKind() == .arrow) {
        _ = self.advance();
        // Literal keys (`1 => x`, `"k" => x`) normalize to value keys, same
        // as the `:` forms; only genuine type keys (`tstr => x`) stay types.
        const key: ast.Key = if (maybe_key.op == null and isLiteral(maybe_key.base))
            .{ .value = maybe_key.base }
        else key: {
            const key = try self.gpa.create(ast.Type1);
            key.* = maybe_key;
            break :key .{ .type = key };
        };
        return .{
            .occur = occur,
            .key = key,
            .value = .{ .type = try self.parseType() },
        };
    }

    // Not a key: re-parse from the saved position as the entry's type.
    self.index = saved;
    return .{ .occur = occur, .value = .{ .type = try self.parseType() } };
}

fn isLiteral(t2: ast.Type2) bool {
    return switch (t2) {
        .uint, .nint, .float, .tstr, .bstr => true,
        else => false,
    };
}

fn parseOccur(self: *Parser) Error!ast.Occur {
    switch (self.peekKind()) {
        .question => {
            _ = self.advance();
            return .{ .min = 0, .max = 1 };
        },
        .plus => {
            _ = self.advance();
            return .{ .min = 1, .max = null };
        },
        .star => {
            _ = self.advance();
            return .{ .min = 0, .max = try self.occurBound() };
        },
        .uint_lit => {
            // "n*", "n*m": only an occurrence if the uint is followed by '*'.
            if (self.peekKindAt(1) == .star) {
                const min_tok = self.advance();
                const min = std.fmt.parseInt(u64, self.tokenText(min_tok), 0) catch
                    return self.fail("invalid occurrence lower bound");
                _ = self.advance(); // star
                return .{ .min = min, .max = try self.occurBound() };
            }
            return .{};
        },
        else => return .{},
    }
}

fn occurBound(self: *Parser) Error!?u64 {
    if (self.peekKind() != .uint_lit) return null;
    const tok = self.advance();
    return std.fmt.parseInt(u64, self.tokenText(tok), 0) catch
        self.fail("invalid occurrence upper bound");
}

// --- Literal decoding --------------------------------------------------------

fn unescapeText(self: *Parser, raw: []const u8) Error![]const u8 {
    if (std.mem.indexOfScalar(u8, raw, '\\') == null) return raw;
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < raw.len) : (i += 1) {
        if (raw[i] == '\\' and i + 1 < raw.len) {
            i += 1;
            switch (raw[i]) {
                '"', '\\', '/', '\'' => try out.append(self.gpa, raw[i]),
                'n' => try out.append(self.gpa, '\n'),
                't' => try out.append(self.gpa, '\t'),
                'r' => try out.append(self.gpa, '\r'),
                else => {
                    try out.append(self.gpa, '\\');
                    try out.append(self.gpa, raw[i]);
                },
            }
        } else {
            try out.append(self.gpa, raw[i]);
        }
    }
    return out.toOwnedSlice(self.gpa);
}

/// Decode 'raw', h'00ff' and b64'...' literals (full token text passed in).
fn decodeBytes(self: *Parser, raw: []const u8) Error![]const u8 {
    const quote = std.mem.indexOfScalar(u8, raw, '\'') orelse
        return self.fail("malformed byte string literal");
    const prefix = raw[0..quote];
    const content = raw[quote + 1 .. raw.len - 1];

    if (prefix.len == 0) return content;

    if (std.mem.eql(u8, prefix, "h")) {
        var out: std.ArrayList(u8) = .empty;
        var hi: ?u8 = null;
        for (content) |ch| {
            if (std.ascii.isWhitespace(ch)) continue;
            const digit = std.fmt.charToDigit(ch, 16) catch
                return self.fail("invalid hex digit in h'' literal");
            if (hi) |h| {
                try out.append(self.gpa, h * 16 + digit);
                hi = null;
            } else {
                hi = digit;
            }
        }
        if (hi != null) return self.fail("odd number of hex digits in h'' literal");
        return out.toOwnedSlice(self.gpa);
    }

    if (std.mem.eql(u8, prefix, "b64")) {
        const decoder = std.base64.url_safe_no_pad.Decoder;
        const trimmed = std.mem.trimEnd(u8, content, "=");
        const len = decoder.calcSizeForSlice(trimmed) catch
            return self.fail("invalid base64url literal");
        const out = try self.gpa.alloc(u8, len);
        decoder.decode(out, trimmed) catch
            return self.fail("invalid base64url literal");
        return out;
    }

    return self.fail("unknown byte string prefix");
}

// --- Tests -------------------------------------------------------------------

const testing = std.testing;

fn parseTest(arena: std.mem.Allocator, source: []const u8) !ast.Document {
    var diag: Diagnostic = .{};
    return parse(arena, source, &diag) catch |err| {
        std.debug.print("parse error at {d}:{d}: {s}\n", .{ diag.line, diag.column, diag.message });
        return err;
    };
}

test "simple type rules" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const doc = try parseTest(arena.allocator(),
        \\port = uint
        \\name = tstr
        \\ratio = float32
    );
    try testing.expectEqual(@as(usize, 3), doc.rules.len);
    try testing.expectEqualStrings("port", doc.rules[0].name);
    const t = doc.rules[0].value.type;
    try testing.expectEqualStrings("uint", t.single().?.base.typename);
}

test "literal value rules" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const doc = try parseTest(arena.allocator(),
        \\a = 5
        \\b = -17
        \\c = "hi"
        \\d = h'00ff'
        \\e = 1.5
    );
    try testing.expectEqual(@as(u64, 5), doc.rules[0].value.type.single().?.base.uint);
    try testing.expectEqual(@as(i64, -17), doc.rules[1].value.type.single().?.base.nint);
    try testing.expectEqualStrings("hi", doc.rules[2].value.type.single().?.base.tstr);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0xff }, doc.rules[3].value.type.single().?.base.bstr);
    try testing.expectEqual(@as(f64, 1.5), doc.rules[4].value.type.single().?.base.float);
}

test "type choices" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const doc = try parseTest(arena.allocator(), "value = uint / tstr / nil");
    const t = doc.rules[0].value.type;
    try testing.expectEqual(@as(usize, 3), t.choices.len);
    try testing.expectEqualStrings("uint", t.choices[0].base.typename);
    try testing.expectEqualStrings("tstr", t.choices[1].base.typename);
    try testing.expectEqualStrings("nil", t.choices[2].base.typename);
}

test "type choice extension with /=" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const doc = try parseTest(arena.allocator(),
        \\value = uint
        \\value /= tstr
    );
    try testing.expectEqual(@as(usize, 1), doc.rules.len);
    try testing.expectEqual(@as(usize, 2), doc.rules[0].value.type.choices.len);
}

test "ranges and control operators" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const doc = try parseTest(arena.allocator(),
        \\byte = 0..255
        \\port = uint .size 2
        \\payload = bstr .cbor port
    );
    const byte = doc.rules[0].value.type.single().?;
    try testing.expectEqual(ast.OpExpr.Kind.range_incl, byte.op.?.kind);
    try testing.expectEqual(@as(u64, 0), byte.base.uint);
    try testing.expectEqual(@as(u64, 255), byte.op.?.rhs.uint);

    const port = doc.rules[1].value.type.single().?;
    try testing.expectEqual(ast.OpExpr.Kind.ctl, port.op.?.kind);
    try testing.expectEqualStrings("size", port.op.?.ctl);
    try testing.expectEqual(@as(u64, 2), port.op.?.rhs.uint);
}

test "map with member keys" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const doc = try parseTest(arena.allocator(),
        \\config = {
        \\    name: tstr,
        \\    ? retries: uint,
        \\    "legacy" : bool,
        \\    1 => int,
        \\}
    );
    const map = doc.rules[0].value.type.single().?.base.map;
    try testing.expectEqual(@as(usize, 1), map.choices.len);
    const entries = map.choices[0].entries;
    try testing.expectEqual(@as(usize, 4), entries.len);

    try testing.expectEqualStrings("name", entries[0].key.?.bareword);
    try testing.expect(entries[0].occur.isOne());

    try testing.expectEqualStrings("retries", entries[1].key.?.bareword);
    try testing.expect(entries[1].occur.isOptional());

    try testing.expectEqualStrings("legacy", entries[2].key.?.value.tstr);
    try testing.expectEqual(@as(u64, 1), entries[3].key.?.value.uint);
}

test "array with occurrences" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const doc = try parseTest(arena.allocator(),
        \\reading = [ id: uint, 0*4 samples: float32, * tstr ]
    );
    const arr = doc.rules[0].value.type.single().?.base.array;
    const entries = arr.choices[0].entries;
    try testing.expectEqual(@as(usize, 3), entries.len);

    try testing.expectEqual(@as(u64, 0), entries[1].occur.min);
    try testing.expectEqual(@as(u64, 4), entries[1].occur.max.?);

    try testing.expectEqual(@as(u64, 0), entries[2].occur.min);
    try testing.expectEqual(@as(?u64, null), entries[2].occur.max);
    try testing.expect(entries[2].key == null);
}

test "group rules and enumeration" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const doc = try parseTest(arena.allocator(),
        \\colors-group = ( red: 0, green: 1, blue: 2 )
        \\colors = &colors-group
        \\attire = &( bow-tie: 0, necktie: 1 )
    );
    const grp = doc.rules[0].value.group;
    try testing.expectEqual(@as(usize, 3), grp.choices[0].entries.len);
    try testing.expectEqualStrings("colors-group", doc.rules[1].value.type.single().?.base.enum_ref);
    const inline_enum = doc.rules[2].value.type.single().?.base.enum_inline;
    try testing.expectEqual(@as(usize, 2), inline_enum.choices[0].entries.len);
    try testing.expectEqualStrings("bow-tie", inline_enum.choices[0].entries[0].key.?.bareword);
}

test "group choices with //" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const doc = try parseTest(arena.allocator(),
        \\msg = { type: 1, body: tstr // type: 2, code: uint }
    );
    const map = doc.rules[0].value.type.single().?.base.map;
    try testing.expectEqual(@as(usize, 2), map.choices.len);
    try testing.expectEqual(@as(usize, 2), map.choices[0].entries.len);
    try testing.expectEqual(@as(usize, 2), map.choices[1].entries.len);
}

test "tags, major types, and any" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const doc = try parseTest(arena.allocator(),
        \\when = #6.1(uint)
        \\raw = #7.25
        \\anything = #
    );
    const tagged = doc.rules[0].value.type.single().?.base.tagged;
    try testing.expectEqual(@as(u64, 1), tagged.tag.?);
    try testing.expectEqualStrings("uint", tagged.inner.single().?.base.typename);

    const major = doc.rules[1].value.type.single().?.base.major;
    try testing.expectEqual(@as(u8, 7), major.major);
    try testing.expectEqual(@as(u64, 25), major.ai.?);

    try testing.expect(doc.rules[2].value.type.single().?.base == .any);
}

test "nested containers" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const doc = try parseTest(arena.allocator(),
        \\outer = { inner: { a: uint }, list: [ * int ] }
    );
    const map = doc.rules[0].value.type.single().?.base.map;
    const entries = map.choices[0].entries;
    const inner = entries[0].value.type.single().?.base.map;
    try testing.expectEqualStrings("a", inner.choices[0].entries[0].key.?.bareword);
    const list = entries[1].value.type.single().?.base.array;
    try testing.expectEqual(@as(?u64, null), list.choices[0].entries[0].occur.max);
}

test "duplicate rule names are rejected" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var diag: Diagnostic = .{};
    try testing.expectError(error.ParseError, parse(arena.allocator(),
        \\a = uint
        \\a = tstr
    , &diag));
    try testing.expectEqualStrings("duplicate rule name", diag.message);
}

test "deep nesting is rejected instead of overflowing the stack" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    // "x = ((((...uint...))))" with 300 levels of parentheses.
    var source: [4 + 300 + 4 + 300]u8 = undefined;
    @memcpy(source[0..4], "x = ");
    @memset(source[4..304], '(');
    @memcpy(source[304..308], "uint");
    @memset(source[308..], ')');
    var diag: Diagnostic = .{};
    try testing.expectError(error.ParseError, parse(arena.allocator(), &source, &diag));
    try testing.expectEqualStrings("nesting too deep", diag.message);
}

test "fuzz: parser survives arbitrary input" {
    try testing.fuzz({}, fuzzParse, .{ .corpus = &.{
        "config = { name: tstr, ? d: tstr, 0*4 e: uint }",
        "colors = &( red: 0, green: 1 )",
        "x = uint .size 2\ny = 0..100\nz = x / y",
        "l = [ * { a: uint // b: tstr } ]",
        "q = bstr .cborseq [* uint]",
        "t = #6.1(uint) / \"lit\" / h'00ff' / -5..5",
    } });
}

fn fuzzParse(_: void, smith: *std.testing.Smith) !void {
    var buf: [2048]u8 = undefined;
    const len = smith.slice(&buf);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var diag: Diagnostic = .{};
    _ = parse(arena.allocator(), buf[0..len], &diag) catch return;
}

test "the zcbor prelude parses" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    // Inline copy of representative prelude rules (see zcbor/zcbor/prelude.cddl).
    const doc = try parseTest(arena.allocator(),
        \\any = #
        \\uint = #0
        \\nint = #1
        \\int = uint / nint
        \\bstr = #2
        \\bytes = bstr
        \\tstr = #3
        \\text = tstr
        \\tdate = #6.0(tstr)
        \\time = #6.1(number)
        \\number = int / float
        \\biguint = #6.2(bstr)
        \\bignint = #6.3(bstr)
        \\bigint = biguint / bignint
        \\integer = int / bigint
        \\unsigned = uint / biguint
        \\decfrac = #6.4([e10: int, m: integer])
        \\bigfloat = #6.5([e2: int, m: integer])
        \\eb64url = #6.21(any)
        \\eb64legacy = #6.22(any)
        \\eb16 = #6.23(any)
        \\encoded-cbor = #6.24(bstr)
        \\uri = #6.32(tstr)
        \\b64url = #6.33(tstr)
        \\b64legacy = #6.34(tstr)
        \\regexp = #6.35(tstr)
        \\mime-message = #6.36(tstr)
        \\cbor-any = #6.55799(any)
        \\float16 = #7.25
        \\float32 = #7.26
        \\float64 = #7.27
        \\float16-32 = float16 / float32
        \\float32-64 = float32 / float64
        \\float = float16-32 / float64
        \\false = #7.20
        \\true = #7.21
        \\bool = false / true
        \\nil = #7.22
        \\null = nil
        \\undefined = #7.23
    );
    try testing.expect(doc.rules.len > 30);
}
