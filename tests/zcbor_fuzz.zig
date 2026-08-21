//! Fuzz harnesses for the zcbor decoder.
//!
//! Under `zig build test` these run once over the seed corpus (smoke test).
//! Run `zig build test --fuzz` to fuzz continuously with coverage feedback.

const std = @import("std");
const c = @import("zcbor");

const testing = std.testing;

/// Effectively-unbounded elem_count for decoding an unknown number of
/// top-level elements (mirrors zcbor's ZCBOR_LARGE_ELEM_COUNT).
const large_elem_count: usize = std.math.maxInt(usize) - 15;

/// Feed arbitrary bytes to the decoder's "skip anything" path.
/// Must never crash, hang, or read out of bounds, no matter the input.
fn fuzzAnySkip(_: void, smith: *testing.Smith) !void {
    var buf: [4096]u8 = undefined;
    const len = smith.slice(&buf);
    const payload = buf[0..len];

    var states: [18]c.zcbor_state_t = undefined; // 16 backups: allows deep nesting
    c.zcbor_new_decode_state(&states, states.len, payload.ptr, payload.len, large_elem_count, null, 0);
    states[0].constant_state.*.enforce_canonical = false; // fuzz the lenient paths too

    // Skip elements until the payload is exhausted or decoding fails.
    var iterations: usize = 0;
    while (!c.zcbor_payload_at_end(&states) and iterations < 4096) : (iterations += 1) {
        if (!c.zcbor_any_skip(&states, null)) break;
    }
}

/// Same as above, but with canonical enforcement enabled: exercises the
/// stricter validation paths.
fn fuzzAnySkipCanonical(_: void, smith: *testing.Smith) !void {
    var buf: [4096]u8 = undefined;
    const len = smith.slice(&buf);
    const payload = buf[0..len];

    var states: [18]c.zcbor_state_t = undefined;
    c.zcbor_new_decode_state(&states, states.len, payload.ptr, payload.len, large_elem_count, null, 0);
    states[0].constant_state.*.enforce_canonical = true;

    var iterations: usize = 0;
    while (!c.zcbor_payload_at_end(&states) and iterations < 4096) : (iterations += 1) {
        if (!c.zcbor_any_skip(&states, null)) break;
    }
}

/// Differential roundtrip: build a random-but-valid sequence of scalar
/// encodes, then decode it back and require identical values.
fn fuzzScalarRoundtrip(_: void, smith: *testing.Smith) !void {
    const Op = enum { uint, int, boolean, tstr, float32, float64, nil };
    const max_ops = 64;

    var ops: [max_ops]Op = undefined;
    var uints: [max_ops]u64 = undefined;
    var ints: [max_ops]i64 = undefined;
    var bools: [max_ops]bool = undefined;
    var f32s: [max_ops]u32 = undefined; // stored as bits: NaN-safe comparison
    var f64s: [max_ops]u64 = undefined;
    var strs: [max_ops][16]u8 = undefined;
    var str_lens: [max_ops]u32 = undefined;

    var buf: [8192]u8 = undefined;
    var states: [2]c.zcbor_state_t = undefined;
    c.zcbor_new_encode_state(&states, states.len, &buf, buf.len, 1);

    var n: usize = 0;
    while (n < max_ops and !smith.eos()) {
        const op = smith.value(Op);
        const ok = switch (op) {
            .uint => blk: {
                uints[n] = smith.value(u64);
                break :blk c.zcbor_uint64_put(&states, uints[n]);
            },
            .int => blk: {
                ints[n] = smith.value(i64);
                break :blk c.zcbor_int64_put(&states, ints[n]);
            },
            .boolean => blk: {
                bools[n] = smith.value(bool);
                break :blk c.zcbor_bool_put(&states, bools[n]);
            },
            .tstr => blk: {
                str_lens[n] = smith.slice(&strs[n]);
                break :blk c.zcbor_tstr_encode_ptr(&states, &strs[n], str_lens[n]);
            },
            .float32 => blk: {
                f32s[n] = smith.value(u32);
                break :blk c.zcbor_float32_put(&states, @bitCast(f32s[n]));
            },
            .float64 => blk: {
                f64s[n] = smith.value(u64);
                break :blk c.zcbor_float64_put(&states, @bitCast(f64s[n]));
            },
            .nil => c.zcbor_nil_put(&states, null),
        };
        if (!ok) break; // buffer full; everything before n is still valid
        ops[n] = op;
        n += 1;
    }

    const payload = buf[0 .. @intFromPtr(states[0].payload) - @intFromPtr(&buf)];

    var dstates: [2]c.zcbor_state_t = undefined;
    c.zcbor_new_decode_state(&dstates, dstates.len, payload.ptr, payload.len, n, null, 0);

    for (ops[0..n], 0..) |op, i| {
        switch (op) {
            .uint => {
                var out: u64 = undefined;
                try testing.expect(c.zcbor_uint64_decode(&dstates, &out));
                try testing.expectEqual(uints[i], out);
            },
            .int => {
                var out: i64 = undefined;
                try testing.expect(c.zcbor_int64_decode(&dstates, &out));
                try testing.expectEqual(ints[i], out);
            },
            .boolean => {
                var out: bool = undefined;
                try testing.expect(c.zcbor_bool_decode(&dstates, &out));
                try testing.expectEqual(bools[i], out);
            },
            .tstr => {
                var out: c.struct_zcbor_string = undefined;
                try testing.expect(c.zcbor_tstr_decode(&dstates, &out));
                try testing.expectEqualSlices(u8, strs[i][0..str_lens[i]], out.value[0..out.len]);
            },
            .float32 => {
                var out: f32 = undefined;
                try testing.expect(c.zcbor_float32_decode(&dstates, &out));
                try testing.expectEqual(f32s[i], @as(u32, @bitCast(out)));
            },
            .float64 => {
                var out: f64 = undefined;
                try testing.expect(c.zcbor_float64_decode(&dstates, &out));
                try testing.expectEqual(f64s[i], @as(u64, @bitCast(out)));
            },
            .nil => try testing.expect(c.zcbor_nil_expect(&dstates, null)),
        }
    }
    try testing.expect(c.zcbor_payload_at_end(&dstates));
}

/// Differential fragmented-payload check: a bstr encoded whole, then decoded
/// as fragments across arbitrary chunk boundaries, must reassemble to exactly
/// the original content — no matter where the splits fall.
fn fuzzFragmentedReassembly(_: void, smith: *testing.Smith) !void {
    var content: [2048]u8 = undefined;
    const content_len = smith.slice(&content);

    var wire: [2064]u8 = undefined;
    var enc: [2]c.zcbor_state_t = undefined;
    c.zcbor_new_encode_state(&enc, enc.len, &wire, wire.len, 1);
    if (!c.zcbor_bstr_encode_ptr(&enc, &content, content_len)) return error.EncodeFailed;
    const wire_len = @intFromPtr(enc[0].payload) - @intFromPtr(&wire);
    const header_len = wire_len - content_len;

    // First chunk must at least hold the string header; everything after is
    // split at fuzz-chosen positions.
    const first = smith.valueRangeAtMost(u32, @intCast(header_len), @intCast(wire_len));
    var dec: [2]c.zcbor_state_t = undefined;
    c.zcbor_new_decode_state(&dec, dec.len, &wire, first, large_elem_count, null, 0);
    if (!c.zcbor_bstr_fragments_start_decode(&dec)) return error.StartFailed;

    var out: [2048]u8 = undefined;
    var got: usize = 0;
    var fed: usize = first;
    while (got < content_len) {
        // A payload section must have bytes available before asking for a
        // fragment; feed the next chunk when the current one is exhausted.
        if (c.zcbor_payload_at_end(&dec)) {
            if (fed >= wire_len) return error.RanOutOfPayload;
            const next = smith.valueRangeAtMost(u32, 1, @intCast(wire_len - fed));
            c.zcbor_update_state(&dec, &wire[fed], next);
            fed += next;
        }
        var frag: c.struct_zcbor_string_fragment = undefined;
        try testing.expect(c.zcbor_str_fragment_decode(&dec, &frag));
        try testing.expectEqual(@as(usize, content_len), frag.total_len);
        try testing.expect(frag.fragment.len > 0);
        try testing.expect(frag.offset + frag.fragment.len <= content_len);
        @memcpy(out[frag.offset..][0..frag.fragment.len], frag.fragment.value[0..frag.fragment.len]);
        got += frag.fragment.len;
        if (got == content_len) try testing.expect(c.zcbor_is_last_fragment(&frag));
    }
    try testing.expect(c.zcbor_str_fragments_end_decode(&dec));
    try testing.expectEqual(@as(usize, content_len), got);
    try testing.expectEqualSlices(u8, content[0..content_len], out[0..content_len]);
}

test "fuzz: any_skip survives arbitrary bytes" {
    try testing.fuzz({}, fuzzAnySkip, .{ .corpus = &.{
        "\x00",
        "\x83\x01\x02\x03", // [1, 2, 3]
        "\xa2\x61\x61\x01\x61\x62\x82\x02\x03", // {"a": 1, "b": [2, 3]}
        "\x9f\x01\x02\xff", // indefinite [1, 2]
        "\xfb\x3f\xf1\x99\x99\x99\x99\x99\x9a", // 1.1
        "\xd8\x20\x61\x78", // tag 32, "x"
        "\x5f\x41\x01\x41\x02\xff", // indefinite bstr
        "\x1b\xff\xff\xff\xff\xff\xff\xff\xff", // max u64
    } });
}

test "fuzz: any_skip survives arbitrary bytes (canonical)" {
    try testing.fuzz({}, fuzzAnySkipCanonical, .{ .corpus = &.{
        "\x83\x01\x02\x03",
        "\x18\x17", // non-minimal 23: must be rejected, not crash
        "\x9f\x01\x02\xff", // indefinite: rejected in canonical mode
    } });
}

test "fuzz: scalar encode/decode roundtrip" {
    try testing.fuzz({}, fuzzScalarRoundtrip, .{});
}

test "fuzz: fragmented bstr reassembles across arbitrary chunk splits" {
    try testing.fuzz({}, fuzzFragmentedReassembly, .{});
}
