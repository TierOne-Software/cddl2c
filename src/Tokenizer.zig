//! Tokenizer for CDDL (RFC 8610).
//!
//! Operates on a byte slice and produces position-tagged tokens. Token text is
//! not copied; `text()` returns a slice into the source.

const std = @import("std");
const Tokenizer = @This();

src: []const u8,
pos: usize = 0,

pub const Token = struct {
    kind: Kind,
    start: usize,
    end: usize,

    pub const Kind = enum {
        ident,
        uint_lit, // 17, 0x11, 0b1_0001
        int_lit, // -17
        float_lit, // 1.5, -0.3e4
        tstr_lit, // "text" (span excludes quotes, escapes unresolved)
        bstr_lit, // 'raw', h'00ff', b64'...' (span includes prefix+quotes)
        hash, // #, #0, #6.32 (span includes major/ai text)
        assign, // =
        type_choice_assign, // /=
        group_choice_assign, // //=
        lparen,
        rparen,
        lbrace,
        rbrace,
        lbracket,
        rbracket,
        langle,
        rangle,
        comma,
        colon,
        arrow, // =>
        caret, // ^
        slash, // /
        dslash, // //
        amp, // &
        tilde, // ~
        question, // ?
        plus, // +
        star, // *
        range_incl, // ..
        range_excl, // ...
        ctlop, // .size, .cbor, ... (span includes the dot)
        eof,
        invalid,
    };
};

pub fn init(src: []const u8) Tokenizer {
    return .{ .src = src };
}

pub fn text(self: *const Tokenizer, tok: Token) []const u8 {
    return self.src[tok.start..tok.end];
}

fn isIdentStart(ch: u8) bool {
    return std.ascii.isAlphabetic(ch) or ch == '@' or ch == '_' or ch == '$';
}

fn isIdentInner(ch: u8) bool {
    return std.ascii.isAlphanumeric(ch) or ch == '@' or ch == '_' or ch == '$';
}

fn peekAt(self: *const Tokenizer, offset: usize) u8 {
    const i = self.pos + offset;
    return if (i < self.src.len) self.src[i] else 0;
}

fn skipTrivia(self: *Tokenizer) void {
    while (self.pos < self.src.len) {
        const ch = self.src[self.pos];
        if (ch == ' ' or ch == '\t' or ch == '\r' or ch == '\n') {
            self.pos += 1;
        } else if (ch == ';') {
            while (self.pos < self.src.len and self.src[self.pos] != '\n') self.pos += 1;
        } else {
            break;
        }
    }
}

pub fn next(self: *Tokenizer) Token {
    self.skipTrivia();
    const start = self.pos;
    if (self.pos >= self.src.len) return .{ .kind = .eof, .start = start, .end = start };

    const ch = self.src[self.pos];
    switch (ch) {
        '(' => return self.single(.lparen),
        ')' => return self.single(.rparen),
        '{' => return self.single(.lbrace),
        '}' => return self.single(.rbrace),
        '[' => return self.single(.lbracket),
        ']' => return self.single(.rbracket),
        '<' => return self.single(.langle),
        '>' => return self.single(.rangle),
        ',' => return self.single(.comma),
        ':' => return self.single(.colon),
        '^' => return self.single(.caret),
        '&' => return self.single(.amp),
        '~' => return self.single(.tilde),
        '?' => return self.single(.question),
        '+' => return self.single(.plus),
        '*' => return self.single(.star),
        '=' => {
            if (self.peekAt(1) == '>') {
                self.pos += 2;
                return .{ .kind = .arrow, .start = start, .end = self.pos };
            }
            return self.single(.assign);
        },
        '/' => {
            if (self.peekAt(1) == '/') {
                if (self.peekAt(2) == '=') {
                    self.pos += 3;
                    return .{ .kind = .group_choice_assign, .start = start, .end = self.pos };
                }
                self.pos += 2;
                return .{ .kind = .dslash, .start = start, .end = self.pos };
            }
            if (self.peekAt(1) == '=') {
                self.pos += 2;
                return .{ .kind = .type_choice_assign, .start = start, .end = self.pos };
            }
            return self.single(.slash);
        },
        '.' => {
            if (self.peekAt(1) == '.') {
                if (self.peekAt(2) == '.') {
                    self.pos += 3;
                    return .{ .kind = .range_excl, .start = start, .end = self.pos };
                }
                self.pos += 2;
                return .{ .kind = .range_incl, .start = start, .end = self.pos };
            }
            if (isIdentStart(self.peekAt(1))) {
                self.pos += 1;
                self.scanIdent();
                return .{ .kind = .ctlop, .start = start, .end = self.pos };
            }
            return self.single(.invalid);
        },
        '#' => {
            self.pos += 1;
            // Optional "N" or "N.M" (major type / additional info).
            if (std.ascii.isDigit(self.peekAt(0))) {
                self.pos += 1;
                if (self.peekAt(0) == '.' and std.ascii.isDigit(self.peekAt(1))) {
                    self.pos += 1;
                    while (std.ascii.isDigit(self.peekAt(0))) self.pos += 1;
                }
            }
            return .{ .kind = .hash, .start = start, .end = self.pos };
        },
        '"' => {
            self.pos += 1;
            const content_start = self.pos;
            while (self.pos < self.src.len) {
                const sc = self.src[self.pos];
                if (sc == '\\' and self.pos + 1 < self.src.len) {
                    self.pos += 2;
                } else if (sc == '"') {
                    const tok = Token{ .kind = .tstr_lit, .start = content_start, .end = self.pos };
                    self.pos += 1;
                    return tok;
                } else {
                    self.pos += 1;
                }
            }
            return .{ .kind = .invalid, .start = start, .end = self.pos };
        },
        '\'' => return self.scanQuotedBytes(start),
        else => {},
    }

    if (isIdentStart(ch)) {
        self.scanIdent();
        // h'...' / b64'...' byte string literals.
        const ident_text = self.src[start..self.pos];
        if ((std.mem.eql(u8, ident_text, "h") or std.mem.eql(u8, ident_text, "b64")) and
            self.peekAt(0) == '\'')
        {
            return self.scanQuotedBytes(start);
        }
        return .{ .kind = .ident, .start = start, .end = self.pos };
    }

    if (std.ascii.isDigit(ch) or (ch == '-' and std.ascii.isDigit(self.peekAt(1)))) {
        return self.scanNumber(start);
    }

    return self.single(.invalid);
}

fn single(self: *Tokenizer, kind: Token.Kind) Token {
    const start = self.pos;
    self.pos += 1;
    return .{ .kind = kind, .start = start, .end = self.pos };
}

fn scanIdent(self: *Tokenizer) void {
    // id = EALPHA *(*("-" / ".") EALPHA / DIGIT); '-' and '.' only allowed
    // when followed by another identifier character.
    while (self.pos < self.src.len) {
        const ch = self.src[self.pos];
        if (isIdentInner(ch)) {
            self.pos += 1;
        } else if ((ch == '-' or ch == '.') and isIdentInner(self.peekAt(1))) {
            self.pos += 2;
        } else {
            break;
        }
    }
}

fn scanQuotedBytes(self: *Tokenizer, start: usize) Token {
    // self.pos is at the opening quote (prefix, if any, already consumed).
    std.debug.assert(self.src[self.pos] == '\'');
    self.pos += 1;
    while (self.pos < self.src.len) {
        const sc = self.src[self.pos];
        if (sc == '\\' and self.pos + 1 < self.src.len) {
            self.pos += 2;
        } else if (sc == '\'') {
            self.pos += 1;
            return .{ .kind = .bstr_lit, .start = start, .end = self.pos };
        } else {
            self.pos += 1;
        }
    }
    return .{ .kind = .invalid, .start = start, .end = self.pos };
}

fn scanNumber(self: *Tokenizer, start: usize) Token {
    var kind: Token.Kind = .uint_lit;
    if (self.src[self.pos] == '-') {
        kind = .int_lit;
        self.pos += 1;
    }

    if (self.peekAt(0) == '0' and (self.peekAt(1) == 'x' or self.peekAt(1) == 'b')) {
        self.pos += 2;
        while (std.ascii.isHex(self.peekAt(0)) or self.peekAt(0) == '_') self.pos += 1;
        return .{ .kind = kind, .start = start, .end = self.pos };
    }

    while (std.ascii.isDigit(self.peekAt(0))) self.pos += 1;

    // Fraction: '.' followed by a digit ('..' is a range operator).
    if (self.peekAt(0) == '.' and std.ascii.isDigit(self.peekAt(1))) {
        kind = .float_lit;
        self.pos += 1;
        while (std.ascii.isDigit(self.peekAt(0))) self.pos += 1;
    }
    if (self.peekAt(0) == 'e' or self.peekAt(0) == 'E') {
        const after = self.peekAt(1);
        if (std.ascii.isDigit(after) or ((after == '+' or after == '-') and std.ascii.isDigit(self.peekAt(2)))) {
            kind = .float_lit;
            self.pos += 2;
            while (std.ascii.isDigit(self.peekAt(0))) self.pos += 1;
        }
    }
    return .{ .kind = kind, .start = start, .end = self.pos };
}

/// Line and column (1-based) for a byte offset, for error reporting.
pub fn lineColumn(src: []const u8, offset: usize) struct { line: usize, column: usize } {
    var line: usize = 1;
    var col: usize = 1;
    for (src[0..@min(offset, src.len)]) |ch| {
        if (ch == '\n') {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    return .{ .line = line, .column = col };
}

// --- Tests -------------------------------------------------------------------

const testing = std.testing;

fn expectTokens(src: []const u8, expected: []const Token.Kind) !void {
    var tz = Tokenizer.init(src);
    for (expected) |kind| {
        const tok = tz.next();
        try testing.expectEqual(kind, tok.kind);
    }
    try testing.expectEqual(Token.Kind.eof, tz.next().kind);
}

test "basic rule tokens" {
    try expectTokens("foo = uint", &.{ .ident, .assign, .ident });
    try expectTokens("foo /= tstr", &.{ .ident, .type_choice_assign, .ident });
    try expectTokens("foo //= (a: 1)", &.{
        .ident, .group_choice_assign, .lparen, .ident, .colon, .uint_lit, .rparen,
    });
}

test "identifiers with special characters" {
    var tz = Tokenizer.init("fun-name fun.name $$group @id a1-b2");
    try testing.expectEqualStrings("fun-name", tz.text(tz.next()));
    try testing.expectEqualStrings("fun.name", tz.text(tz.next()));
    try testing.expectEqualStrings("$$group", tz.text(tz.next()));
    try testing.expectEqualStrings("@id", tz.text(tz.next()));
    try testing.expectEqualStrings("a1-b2", tz.text(tz.next()));
    try testing.expectEqual(Token.Kind.eof, tz.next().kind);
}

test "numbers and ranges" {
    try expectTokens("0..10", &.{ .uint_lit, .range_incl, .uint_lit });
    try expectTokens("0...10", &.{ .uint_lit, .range_excl, .uint_lit });
    try expectTokens("-5 1.5 0x1F 0b101 -0.3e4 2e3", &.{
        .int_lit, .float_lit, .uint_lit, .uint_lit, .float_lit, .float_lit,
    });

    var tz = Tokenizer.init("1.5 100..200");
    try testing.expectEqualStrings("1.5", tz.text(tz.next()));
    try testing.expectEqualStrings("100", tz.text(tz.next()));
    try testing.expectEqual(Token.Kind.range_incl, tz.next().kind);
    try testing.expectEqualStrings("200", tz.text(tz.next()));
}

test "control operators vs identifier dots" {
    try expectTokens("uint .size 2", &.{ .ident, .ctlop, .uint_lit });
    var tz = Tokenizer.init("bstr .cbor foo.bar");
    _ = tz.next(); // bstr
    try testing.expectEqualStrings(".cbor", tz.text(tz.next()));
    try testing.expectEqualStrings("foo.bar", tz.text(tz.next()));
}

test "strings and byte strings" {
    var tz = Tokenizer.init(
        \\"text" 'raw' h'00ff' b64'aGk=' "with \" escape"
    );
    const t1 = tz.next();
    try testing.expectEqual(Token.Kind.tstr_lit, t1.kind);
    try testing.expectEqualStrings("text", tz.text(t1));
    const t2 = tz.next();
    try testing.expectEqual(Token.Kind.bstr_lit, t2.kind);
    try testing.expectEqualStrings("'raw'", tz.text(t2));
    const t3 = tz.next();
    try testing.expectEqual(Token.Kind.bstr_lit, t3.kind);
    try testing.expectEqualStrings("h'00ff'", tz.text(t3));
    const t4 = tz.next();
    try testing.expectEqual(Token.Kind.bstr_lit, t4.kind);
    try testing.expectEqualStrings("b64'aGk='", tz.text(t4));
    const t5 = tz.next();
    try testing.expectEqual(Token.Kind.tstr_lit, t5.kind);
    try testing.expectEqualStrings("with \\\" escape", tz.text(t5));
}

test "semicolon comments are skipped" {
    try expectTokens(
        \\; a comment
        \\foo = 1 ; trailing
        \\bar = 2
    , &.{ .ident, .assign, .uint_lit, .ident, .assign, .uint_lit });
}

test "hash tokens" {
    var tz = Tokenizer.init("# #0 #6.32(tstr) #1.5");
    const t1 = tz.next();
    try testing.expectEqual(Token.Kind.hash, t1.kind);
    try testing.expectEqualStrings("#", tz.text(t1));
    const t2 = tz.next();
    try testing.expectEqualStrings("#0", tz.text(t2));
    const t3 = tz.next();
    try testing.expectEqualStrings("#6.32", tz.text(t3));
    try testing.expectEqual(Token.Kind.lparen, tz.next().kind);
    try testing.expectEqual(Token.Kind.ident, tz.next().kind);
    try testing.expectEqual(Token.Kind.rparen, tz.next().kind);
    try testing.expectEqualStrings("#1.5", tz.text(tz.next()));
}

test "occurrence and choice punctuation" {
    try expectTokens("? foo * 0*4 + a / b // c", &.{
        .question, .ident, .star, .uint_lit, .star, .uint_lit, .plus,
        .ident, .slash, .ident, .dslash, .ident,
    });
}

test "member key arrow" {
    try expectTokens("1 => tstr", &.{ .uint_lit, .arrow, .ident });
    try expectTokens("\"key\" : int", &.{ .tstr_lit, .colon, .ident });
}
