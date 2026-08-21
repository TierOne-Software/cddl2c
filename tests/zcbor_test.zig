//! Unit tests for the zcbor C CBOR implementation, driven from Zig.
//!
//! The zcbor headers are imported via translate-c (module "zcbor") and the
//! implementation is linked in as a static library built from zcbor/src.
//! Wire-format expectations are taken from RFC 8949 Appendix A.

const std = @import("std");
const c = @import("zcbor");

const testing = std.testing;

const State = c.zcbor_state_t;

/// Set up an encode state over `buf`. `states` needs at least 2 entries
/// (1 working state + 1 constant state); more entries add backup slots.
fn encState(states: []State, buf: []u8) [*c]State {
    c.zcbor_new_encode_state(states.ptr, states.len, buf.ptr, buf.len, 1);
    return states.ptr;
}

/// Set up a decode state. `elem_count` is the number of top-level elements
/// the test will decode. The zcbor library is built with ZCBOR_CANONICAL, so
/// decoding defaults to strict; tests for lenient decoding opt out per state.
fn decState(states: []State, payload: []const u8, elem_count: usize) [*c]State {
    c.zcbor_new_decode_state(states.ptr, states.len, payload.ptr, payload.len, elem_count, null, 0);
    return states.ptr;
}

/// Bytes written so far by an encode state working on `buf`.
fn encoded(state: [*c]const State, buf: []const u8) []const u8 {
    return buf[0 .. @intFromPtr(state.*.payload) - @intFromPtr(buf.ptr)];
}

fn expectHex(expected_hex: []const u8, actual: []const u8) !void {
    var exp_buf: [512]u8 = undefined;
    const exp = try std.fmt.hexToBytes(&exp_buf, expected_hex);
    try testing.expectEqualSlices(u8, exp, actual);
}

// --- RFC 8949 Appendix A vectors: integers ---------------------------------

test "uint encodings match RFC 8949 Appendix A" {
    const cases = [_]struct { val: u64, hex: []const u8 }{
        .{ .val = 0, .hex = "00" },
        .{ .val = 1, .hex = "01" },
        .{ .val = 10, .hex = "0a" },
        .{ .val = 23, .hex = "17" },
        .{ .val = 24, .hex = "1818" },
        .{ .val = 25, .hex = "1819" },
        .{ .val = 100, .hex = "1864" },
        .{ .val = 1000, .hex = "1903e8" },
        .{ .val = 1000000, .hex = "1a000f4240" },
        .{ .val = 1000000000000, .hex = "1b000000e8d4a51000" },
        .{ .val = 18446744073709551615, .hex = "1bffffffffffffffff" },
    };
    for (cases) |case| {
        var buf: [16]u8 = undefined;
        var states: [2]State = undefined;
        const st = encState(&states, &buf);
        try testing.expect(c.zcbor_uint64_put(st, case.val));
        try expectHex(case.hex, encoded(st, &buf));
    }
}

test "negative int encodings match RFC 8949 Appendix A" {
    const cases = [_]struct { val: i64, hex: []const u8 }{
        .{ .val = -1, .hex = "20" },
        .{ .val = -10, .hex = "29" },
        .{ .val = -100, .hex = "3863" },
        .{ .val = -1000, .hex = "3903e7" },
        .{ .val = std.math.minInt(i64), .hex = "3b7fffffffffffffff" },
    };
    for (cases) |case| {
        var buf: [16]u8 = undefined;
        var states: [2]State = undefined;
        const st = encState(&states, &buf);
        try testing.expect(c.zcbor_int64_put(st, case.val));
        try expectHex(case.hex, encoded(st, &buf));
    }
}

test "int roundtrip across widths" {
    const vals64 = [_]i64{ 0, 1, -1, 23, 24, -24, -25, 255, 256, -256, 65535, 65536, -65536, std.math.maxInt(i64), std.math.minInt(i64) };
    for (vals64) |v| {
        var buf: [16]u8 = undefined;
        var states: [2]State = undefined;
        const st = encState(&states, &buf);
        try testing.expect(c.zcbor_int64_put(st, v));

        var dstates: [2]State = undefined;
        const dst = decState(&dstates, encoded(st, &buf), 1);
        var out: i64 = undefined;
        try testing.expect(c.zcbor_int64_decode(dst, &out));
        try testing.expectEqual(v, out);
    }

    // 8-bit decode must reject out-of-range values.
    var buf: [16]u8 = undefined;
    var states: [2]State = undefined;
    const st = encState(&states, &buf);
    try testing.expect(c.zcbor_uint32_put(st, 300));
    var dstates: [2]State = undefined;
    const dst = decState(&dstates, encoded(st, &buf), 1);
    var out8: u8 = undefined;
    try testing.expect(!c.zcbor_uint8_decode(dst, &out8));
    try testing.expectEqual(@as(c_int, c.ZCBOR_ERR_INT_SIZE), c.zcbor_peek_error(dst));
}

// --- Simple values and floats ----------------------------------------------

test "bool, nil, undefined encodings" {
    var buf: [8]u8 = undefined;
    var states: [2]State = undefined;
    const st = encState(&states, &buf);
    try testing.expect(c.zcbor_bool_put(st, false));
    try testing.expect(c.zcbor_bool_put(st, true));
    try testing.expect(c.zcbor_nil_put(st, null));
    try testing.expect(c.zcbor_undefined_put(st, null));
    try expectHex("f4f5f6f7", encoded(st, &buf));

    var dstates: [2]State = undefined;
    const dst = decState(&dstates, encoded(st, &buf), 4);
    var b: bool = undefined;
    try testing.expect(c.zcbor_bool_decode(dst, &b));
    try testing.expect(!b);
    try testing.expect(c.zcbor_bool_expect(dst, true));
    try testing.expect(c.zcbor_nil_expect(dst, null));
    try testing.expect(c.zcbor_undefined_expect(dst, null));
    try testing.expect(c.zcbor_payload_at_end(dst));
}

test "float encodings match RFC 8949 Appendix A" {
    var buf: [32]u8 = undefined;
    var states: [2]State = undefined;
    const st = encState(&states, &buf);
    try testing.expect(c.zcbor_float16_put(st, 1.5)); // f93e00
    try testing.expect(c.zcbor_float32_put(st, 100000.0)); // fa47c35000
    try testing.expect(c.zcbor_float64_put(st, 1.1)); // fb3ff199999999999a
    try expectHex("f93e00" ++ "fa47c35000" ++ "fb3ff199999999999a", encoded(st, &buf));

    var dstates: [2]State = undefined;
    const dst = decState(&dstates, encoded(st, &buf), 3);
    var f: float_check = undefined;
    try testing.expect(c.zcbor_float16_decode(dst, &f.f32));
    try testing.expectEqual(@as(f32, 1.5), f.f32);
    try testing.expect(c.zcbor_float32_decode(dst, &f.f32));
    try testing.expectEqual(@as(f32, 100000.0), f.f32);
    try testing.expect(c.zcbor_float64_decode(dst, &f.f64));
    try testing.expectEqual(@as(f64, 1.1), f.f64);
}

const float_check = struct { f32: f32, f64: f64 };

test "float16 conversion helpers" {
    try testing.expectEqual(@as(f32, 1.5), c.zcbor_float16_to_32(0x3e00));
    try testing.expectEqual(@as(f32, 65504.0), c.zcbor_float16_to_32(0x7bff));
    try testing.expectEqual(@as(u16, 0x3e00), c.zcbor_float32_to_16(1.5));
}

// --- Strings ----------------------------------------------------------------

test "tstr and bstr encodings match RFC 8949 Appendix A" {
    var buf: [32]u8 = undefined;
    var states: [2]State = undefined;
    const st = encState(&states, &buf);
    try testing.expect(c.zcbor_tstr_encode_ptr(st, "", 0));
    try testing.expect(c.zcbor_tstr_encode_ptr(st, "IETF", 4));
    const bytes = [_]u8{ 1, 2, 3, 4 };
    try testing.expect(c.zcbor_bstr_encode_ptr(st, &bytes, bytes.len));
    try expectHex("60" ++ "6449455446" ++ "4401020304", encoded(st, &buf));
}

test "decoded strings point into the payload (zero copy)" {
    var buf: [32]u8 = undefined;
    var states: [2]State = undefined;
    const st = encState(&states, &buf);
    try testing.expect(c.zcbor_tstr_encode_ptr(st, "hello", 5));
    const payload = encoded(st, &buf);

    var dstates: [2]State = undefined;
    const dst = decState(&dstates, payload, 1);
    var out: c.struct_zcbor_string = undefined;
    try testing.expect(c.zcbor_tstr_decode(dst, &out));
    try testing.expectEqual(@as(usize, 5), out.len);
    try testing.expectEqualSlices(u8, "hello", out.value[0..out.len]);
    // Zero copy: the decoded pointer must be inside the payload buffer.
    try testing.expect(@intFromPtr(out.value) >= @intFromPtr(payload.ptr));
    try testing.expect(@intFromPtr(out.value) + out.len <= @intFromPtr(payload.ptr) + payload.len);
}

// --- Containers --------------------------------------------------------------

test "list encodings match RFC 8949 Appendix A" {
    {
        var buf: [8]u8 = undefined;
        var states: [3]State = undefined;
        const st = encState(&states, &buf);
        try testing.expect(c.zcbor_list_start_encode(st, 0));
        try testing.expect(c.zcbor_list_end_encode(st, 0));
        try expectHex("80", encoded(st, &buf));
    }
    {
        var buf: [16]u8 = undefined;
        var states: [3]State = undefined;
        const st = encState(&states, &buf);
        try testing.expect(c.zcbor_list_start_encode(st, 3));
        try testing.expect(c.zcbor_uint32_put(st, 1));
        try testing.expect(c.zcbor_uint32_put(st, 2));
        try testing.expect(c.zcbor_uint32_put(st, 3));
        try testing.expect(c.zcbor_list_end_encode(st, 3));
        try expectHex("83010203", encoded(st, &buf));
    }
    {
        // [1, [2, 3], [4, 5]]
        var buf: [16]u8 = undefined;
        var states: [4]State = undefined;
        const st = encState(&states, &buf);
        try testing.expect(c.zcbor_list_start_encode(st, 3));
        try testing.expect(c.zcbor_uint32_put(st, 1));
        try testing.expect(c.zcbor_list_start_encode(st, 2));
        try testing.expect(c.zcbor_uint32_put(st, 2));
        try testing.expect(c.zcbor_uint32_put(st, 3));
        try testing.expect(c.zcbor_list_end_encode(st, 2));
        try testing.expect(c.zcbor_list_start_encode(st, 2));
        try testing.expect(c.zcbor_uint32_put(st, 4));
        try testing.expect(c.zcbor_uint32_put(st, 5));
        try testing.expect(c.zcbor_list_end_encode(st, 2));
        try testing.expect(c.zcbor_list_end_encode(st, 3));
        try expectHex("8301820203820405", encoded(st, &buf));
    }
}

test "map encode and ordered decode" {
    // {"a": 1, "b": [2, 3]}
    var buf: [32]u8 = undefined;
    var states: [4]State = undefined;
    const st = encState(&states, &buf);
    try testing.expect(c.zcbor_map_start_encode(st, 2));
    try testing.expect(c.zcbor_tstr_encode_ptr(st, "a", 1));
    try testing.expect(c.zcbor_uint32_put(st, 1));
    try testing.expect(c.zcbor_tstr_encode_ptr(st, "b", 1));
    try testing.expect(c.zcbor_list_start_encode(st, 2));
    try testing.expect(c.zcbor_uint32_put(st, 2));
    try testing.expect(c.zcbor_uint32_put(st, 3));
    try testing.expect(c.zcbor_list_end_encode(st, 2));
    try testing.expect(c.zcbor_map_end_encode(st, 2));
    try expectHex("a26161016162820203", encoded(st, &buf));

    var dstates: [4]State = undefined;
    const dst = decState(&dstates, encoded(st, &buf), 1);
    var key_a = c.struct_zcbor_string{ .value = "a", .len = 1 };
    var key_b = c.struct_zcbor_string{ .value = "b", .len = 1 };
    var v: u32 = undefined;
    try testing.expect(c.zcbor_map_start_decode(dst));
    try testing.expect(c.zcbor_tstr_expect(dst, &key_a));
    try testing.expect(c.zcbor_uint32_decode(dst, &v));
    try testing.expectEqual(@as(u32, 1), v);
    try testing.expect(c.zcbor_tstr_expect(dst, &key_b));
    try testing.expect(c.zcbor_list_start_decode(dst));
    try testing.expect(c.zcbor_uint32_expect(dst, 2));
    try testing.expect(c.zcbor_uint32_expect(dst, 3));
    try testing.expect(c.zcbor_list_end_decode(dst));
    try testing.expect(c.zcbor_map_end_decode(dst));
    try testing.expect(c.zcbor_payload_at_end(dst));
}

test "indefinite-length list decodes in lenient mode" {
    const payload = [_]u8{ 0x9f, 0x01, 0x02, 0xff };
    var dstates: [3]State = undefined;
    const dst = decState(&dstates, &payload, 1);
    dst.*.constant_state.*.enforce_canonical = false;
    try testing.expect(c.zcbor_list_start_decode(dst));
    try testing.expect(c.zcbor_uint32_expect(dst, 1));
    try testing.expect(c.zcbor_uint32_expect(dst, 2));
    try testing.expect(c.zcbor_list_end_decode(dst));
    try testing.expect(c.zcbor_payload_at_end(dst));
}

// --- Tags --------------------------------------------------------------------

test "tag encode and decode" {
    var buf: [16]u8 = undefined;
    var states: [2]State = undefined;
    const st = encState(&states, &buf);
    try testing.expect(c.zcbor_tag_put(st, 32)); // tag 32: URI
    try testing.expect(c.zcbor_tstr_encode_ptr(st, "x", 1));
    try expectHex("d820" ++ "6178", encoded(st, &buf));

    var dstates: [2]State = undefined;
    const dst = decState(&dstates, encoded(st, &buf), 2);
    var tag: u32 = undefined;
    try testing.expect(c.zcbor_tag_decode(dst, &tag));
    try testing.expectEqual(@as(u32, 32), tag);
    var out: c.struct_zcbor_string = undefined;
    try testing.expect(c.zcbor_tstr_decode(dst, &out));
}

// --- CBOR-in-bstr ------------------------------------------------------------

test "bstr-wrapped CBOR via bstr_start/end_encode" {
    var buf: [16]u8 = undefined;
    var states: [4]State = undefined; // 2 backups: one for the bstr, one for the list
    const st = encState(&states, &buf);
    try testing.expect(c.zcbor_bstr_start_encode(st));
    try testing.expect(c.zcbor_list_start_encode(st, 2));
    try testing.expect(c.zcbor_uint32_put(st, 1));
    try testing.expect(c.zcbor_uint32_put(st, 2));
    try testing.expect(c.zcbor_list_end_encode(st, 2));
    var result: c.struct_zcbor_string = undefined;
    try testing.expect(c.zcbor_bstr_end_encode(st, &result));
    try expectHex("43820102", encoded(st, &buf));
}

// --- Error handling -----------------------------------------------------------

test "decode errors are reported via zcbor_peek_error" {
    { // wrong type
        const payload = [_]u8{0x61} ++ "a".*; // tstr "a"
        var dstates: [2]State = undefined;
        const dst = decState(&dstates, &payload, 1);
        var out: u32 = undefined;
        try testing.expect(!c.zcbor_uint32_decode(dst, &out));
        try testing.expectEqual(@as(c_int, c.ZCBOR_ERR_WRONG_TYPE), c.zcbor_peek_error(dst));
    }
    { // empty payload
        const payload = [_]u8{};
        var dstates: [2]State = undefined;
        const dst = decState(&dstates, &payload, 1);
        var out: u32 = undefined;
        try testing.expect(!c.zcbor_uint32_decode(dst, &out));
        try testing.expectEqual(@as(c_int, c.ZCBOR_ERR_NO_PAYLOAD), c.zcbor_peek_error(dst));
    }
    { // truncated multi-byte integer
        const payload = [_]u8{0x19, 0x03}; // says 2-byte value, only 1 byte present
        var dstates: [2]State = undefined;
        const dst = decState(&dstates, &payload, 1);
        var out: u32 = undefined;
        try testing.expect(!c.zcbor_uint32_decode(dst, &out));
    }
}

test "encode fails cleanly when the buffer is too small" {
    var buf: [3]u8 = undefined;
    var states: [2]State = undefined;
    const st = encState(&states, &buf);
    try testing.expect(!c.zcbor_tstr_encode_ptr(st, "too long for buffer", 19));
    try testing.expect(c.zcbor_peek_error(st) != c.ZCBOR_SUCCESS);
}

test "canonical enforcement rejects non-minimal encodings" {
    // 23 encoded needlessly as 0x18 0x17 (1-byte extension).
    const payload = [_]u8{ 0x18, 0x17 };
    {
        // Strict is the default (library built with ZCBOR_CANONICAL).
        var dstates: [2]State = undefined;
        const dst = decState(&dstates, &payload, 1);
        var out: u32 = undefined;
        try testing.expect(!c.zcbor_uint32_decode(dst, &out));
        try testing.expectEqual(
            @as(c_int, c.ZCBOR_ERR_INVALID_VALUE_ENCODING),
            c.zcbor_peek_error(dst),
        );
    }
    {
        // Lenient decoding can be selected per state at runtime.
        var dstates: [2]State = undefined;
        const dst = decState(&dstates, &payload, 1);
        dst.*.constant_state.*.enforce_canonical = false;
        var out: u32 = undefined;
        try testing.expect(c.zcbor_uint32_decode(dst, &out));
        try testing.expectEqual(@as(u32, 23), out);
    }
}

// --- Skipping and unions -------------------------------------------------------

test "any_skip skips a whole nested structure" {
    // {"a": 1, "b": [2, 3]} followed by 42
    var buf: [32]u8 = undefined;
    var states: [4]State = undefined;
    const st = encState(&states, &buf);
    try testing.expect(c.zcbor_map_start_encode(st, 2));
    try testing.expect(c.zcbor_tstr_encode_ptr(st, "a", 1));
    try testing.expect(c.zcbor_uint32_put(st, 1));
    try testing.expect(c.zcbor_tstr_encode_ptr(st, "b", 1));
    try testing.expect(c.zcbor_list_start_encode(st, 2));
    try testing.expect(c.zcbor_uint32_put(st, 2));
    try testing.expect(c.zcbor_uint32_put(st, 3));
    try testing.expect(c.zcbor_list_end_encode(st, 2));
    try testing.expect(c.zcbor_map_end_encode(st, 2));
    try testing.expect(c.zcbor_uint32_put(st, 42));

    var dstates: [4]State = undefined;
    const dst = decState(&dstates, encoded(st, &buf), 2);
    try testing.expect(c.zcbor_any_skip(dst, null));
    try testing.expect(c.zcbor_uint32_expect(dst, 42));
    try testing.expect(c.zcbor_payload_at_end(dst));
}

test "union decoding with backup/restore" {
    // Payload is a tstr; try uint first, fall back to tstr.
    var buf: [16]u8 = undefined;
    var states: [3]State = undefined;
    const st = encState(&states, &buf);
    try testing.expect(c.zcbor_tstr_encode_ptr(st, "hi", 2));

    var dstates: [3]State = undefined;
    const dst = decState(&dstates, encoded(st, &buf), 1);
    try testing.expect(c.zcbor_union_start_code(dst));

    var out_int: u32 = undefined;
    try testing.expect(c.zcbor_union_elem_code(dst));
    try testing.expect(!c.zcbor_uint32_decode(dst, &out_int));

    var out_str: c.struct_zcbor_string = undefined;
    try testing.expect(c.zcbor_union_elem_code(dst));
    try testing.expect(c.zcbor_tstr_decode(dst, &out_str));
    try testing.expectEqualSlices(u8, "hi", out_str.value[0..out_str.len]);

    try testing.expect(c.zcbor_union_end_code(dst));
    try testing.expect(c.zcbor_payload_at_end(dst));
}
