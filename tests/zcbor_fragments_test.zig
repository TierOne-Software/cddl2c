//! Tests for zcbor's fragmented-payload support (ZCBOR_FRAGMENTS).
//!
//! This is the machinery for transferring payloads larger than any single
//! buffer — log files, firmware update images, SREC dumps — between systems:
//! `zcbor_update_state` switches to the next payload section, and the
//! string-fragment APIs stream a large bstr/tstr through in pieces.

const std = @import("std");
const c = @import("zcbor");

const testing = std.testing;

const State = c.zcbor_state_t;

/// Effectively-unbounded elem_count (mirrors zcbor's ZCBOR_LARGE_ELEM_COUNT).
const large_elem_count: usize = std.math.maxInt(usize) - 15;

fn encoded(states: []const State, buf: []const u8) []const u8 {
    return buf[0 .. @intFromPtr(states[0].payload) - @intFromPtr(buf.ptr)];
}

/// Fill a "file" with a deterministic pattern.
fn fillFile(buf: []u8) void {
    for (buf, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);
}

test "update_state continues decoding across payload sections" {
    // Payload: 1, 100, 1000 (1 + 2 + 3 bytes).
    var buf: [16]u8 = undefined;
    var enc: [2]State = undefined;
    c.zcbor_new_encode_state(&enc, enc.len, &buf, buf.len, 1);
    try testing.expect(c.zcbor_uint32_put(&enc, 1));
    try testing.expect(c.zcbor_uint32_put(&enc, 100));
    try testing.expect(c.zcbor_uint32_put(&enc, 1000));
    const payload = encoded(&enc, &buf);
    try testing.expectEqual(@as(usize, 6), payload.len);

    // Deliver in two sections, split between elements.
    var dec: [2]State = undefined;
    c.zcbor_new_decode_state(&dec, dec.len, payload.ptr, 3, large_elem_count, null, 0);
    try testing.expect(c.zcbor_uint32_expect(&dec, 1));
    try testing.expect(c.zcbor_uint32_expect(&dec, 100));
    try testing.expect(c.zcbor_payload_at_end(&dec));

    c.zcbor_update_state(&dec, payload.ptr + 3, payload.len - 3);
    try testing.expect(c.zcbor_uint32_expect(&dec, 1000));
    try testing.expect(c.zcbor_payload_at_end(&dec));
}

test "fragmented bstr decode reassembles a chunked file transfer" {
    // The "file" is wrapped in a map: { "name": "log.txt", "data": <1500 B> }.
    var file: [1500]u8 = undefined;
    fillFile(&file);

    var wire: [1600]u8 = undefined;
    var enc: [3]State = undefined;
    c.zcbor_new_encode_state(&enc, enc.len, &wire, wire.len, 1);
    try testing.expect(c.zcbor_map_start_encode(&enc, 2));
    try testing.expect(c.zcbor_tstr_encode_ptr(&enc, "name", 4));
    try testing.expect(c.zcbor_tstr_encode_ptr(&enc, "log.txt", 7));
    try testing.expect(c.zcbor_tstr_encode_ptr(&enc, "data", 4));
    try testing.expect(c.zcbor_bstr_encode_ptr(&enc, &file, file.len));
    try testing.expect(c.zcbor_map_end_encode(&enc, 2));
    const full = encoded(&enc, &wire);

    // Receive in 128-byte link-layer chunks.
    const chunk_size = 128;
    var dec: [3]State = undefined;
    c.zcbor_new_decode_state(&dec, dec.len, full.ptr, chunk_size, large_elem_count, null, 0);

    try testing.expect(c.zcbor_map_start_decode(&dec));
    try testing.expect(c.zcbor_tstr_expect_ptr(&dec, "name", 4));
    var name: c.struct_zcbor_string = undefined;
    try testing.expect(c.zcbor_tstr_decode(&dec, &name));
    try testing.expectEqualSlices(u8, "log.txt", name.value[0..name.len]);
    try testing.expect(c.zcbor_tstr_expect_ptr(&dec, "data", 4));

    try testing.expect(c.zcbor_bstr_fragments_start_decode(&dec));

    var out: [1500]u8 = undefined;
    var got: usize = 0;
    var fed: usize = chunk_size; // bytes of `full` handed to the decoder so far
    while (true) {
        var frag: c.struct_zcbor_string_fragment = undefined;
        try testing.expect(c.zcbor_str_fragment_decode(&dec, &frag));
        try testing.expectEqual(@as(usize, file.len), frag.total_len);
        @memcpy(out[frag.offset..][0..frag.fragment.len], frag.fragment.value[0..frag.fragment.len]);
        got += frag.fragment.len;
        if (c.zcbor_is_last_fragment(&frag)) break;
        const next = @min(chunk_size, full.len - fed);
        c.zcbor_update_state(&dec, full.ptr + fed, next);
        fed += next;
    }
    try testing.expectEqual(file.len, got);
    try testing.expectEqualSlices(u8, &file, &out);

    try testing.expect(c.zcbor_str_fragments_end_decode(&dec));
    // The map's trailing bytes may live in a not-yet-fed chunk.
    if (fed < full.len) {
        c.zcbor_update_state(&dec, full.ptr + fed, full.len - fed);
        fed = full.len;
    }
    try testing.expect(c.zcbor_map_end_decode(&dec));
}

test "fragmented bstr encode streams a file into MTU-sized buffers" {
    var file: [1000]u8 = undefined;
    fillFile(&file);

    // Encode { "data": <1000 B> } through three 512-byte output sections.
    const sec_size = 512;
    var sections: [3][sec_size]u8 = undefined;
    var sec_used: [3]usize = .{ 0, 0, 0 };
    var enc: [3]State = undefined;
    c.zcbor_new_encode_state(&enc, enc.len, &sections[0], sec_size, 1);

    try testing.expect(c.zcbor_map_start_encode(&enc, 1));
    try testing.expect(c.zcbor_tstr_encode_ptr(&enc, "data", 4));
    try testing.expect(c.zcbor_bstr_fragments_start_encode(&enc, file.len));

    var sec_idx: usize = 0;
    var sent: usize = 0;
    while (sent < file.len) {
        var frag = c.struct_zcbor_string{ .value = &file[sent], .len = file.len - sent };
        var enc_len: usize = 0;
        try testing.expect(c.zcbor_str_fragment_encode(&enc, &frag, &enc_len));
        sent += enc_len;
        if (sent < file.len) {
            // Section full: switch to the next output buffer.
            try testing.expect(c.zcbor_payload_at_end(&enc));
            sec_used[sec_idx] = sec_size;
            sec_idx += 1;
            c.zcbor_update_state(&enc, &sections[sec_idx], sec_size);
        }
    }
    try testing.expect(c.zcbor_str_fragments_end_encode(&enc));
    try testing.expect(c.zcbor_map_end_encode(&enc, 1));
    sec_used[sec_idx] =
        @intFromPtr(enc[0].payload) - @intFromPtr(&sections[sec_idx]);

    // Reassemble the wire image and decode it in one piece.
    var whole: [3 * sec_size]u8 = undefined;
    var whole_len: usize = 0;
    for (0..sec_idx + 1) |i| {
        @memcpy(whole[whole_len..][0..sec_used[i]], sections[i][0..sec_used[i]]);
        whole_len += sec_used[i];
    }

    var dec: [3]State = undefined;
    c.zcbor_new_decode_state(&dec, dec.len, &whole, whole_len, 1, null, 0);
    try testing.expect(c.zcbor_map_start_decode(&dec));
    try testing.expect(c.zcbor_tstr_expect_ptr(&dec, "data", 4));
    var data: c.struct_zcbor_string = undefined;
    try testing.expect(c.zcbor_bstr_decode(&dec, &data));
    try testing.expectEqualSlices(u8, &file, data.value[0..data.len]);
    try testing.expect(c.zcbor_map_end_decode(&dec));
    try testing.expect(c.zcbor_payload_at_end(&dec));
}

test "CBOR-in-CBOR fragmented decode across sections" {
    // A bstr wrapping the CBOR sequence: 100, 200, 300 (2 + 2 + 3 bytes).
    var inner_buf: [16]u8 = undefined;
    var ienc: [2]State = undefined;
    c.zcbor_new_encode_state(&ienc, ienc.len, &inner_buf, inner_buf.len, 3);
    try testing.expect(c.zcbor_uint32_put(&ienc, 100));
    try testing.expect(c.zcbor_uint32_put(&ienc, 200));
    try testing.expect(c.zcbor_uint32_put(&ienc, 300));
    const inner = encoded(&ienc, &inner_buf);
    try testing.expectEqual(@as(usize, 7), inner.len);

    var wire_buf: [16]u8 = undefined;
    var wenc: [2]State = undefined;
    c.zcbor_new_encode_state(&wenc, wenc.len, &wire_buf, wire_buf.len, 1);
    try testing.expect(c.zcbor_bstr_encode_ptr(&wenc, inner.ptr, inner.len));
    const wire = encoded(&wenc, &wire_buf);

    // Sections split after the first wrapped item (1 B header + 2 B item).
    var dec: [4]State = undefined;
    c.zcbor_new_decode_state(&dec, dec.len, wire.ptr, 3, large_elem_count, null, 0);
    try testing.expect(c.zcbor_cbor_bstr_fragments_start_decode(&dec));
    try testing.expect(c.zcbor_uint32_expect(&dec, 100));
    try testing.expect(c.zcbor_payload_at_end(&dec));

    var remainder: usize = 0;
    try testing.expect(c.zcbor_current_string_remainder(&dec, &remainder));
    try testing.expectEqual(@as(usize, 5), remainder);

    c.zcbor_update_state(&dec, wire.ptr + 3, wire.len - 3);
    try testing.expect(c.zcbor_uint32_expect(&dec, 200));
    try testing.expect(c.zcbor_uint32_expect(&dec, 300));
    try testing.expect(c.zcbor_current_string_remainder(&dec, &remainder));
    try testing.expectEqual(@as(usize, 0), remainder);
    try testing.expect(c.zcbor_str_fragments_end_decode(&dec));
    try testing.expect(c.zcbor_payload_at_end(&dec));
}

test "CBOR-in-CBOR fragmented encode across sections" {
    // Encode a bstr wrapping the sequence 100, 200, 300 (7 content bytes)
    // through two 5-byte output sections.
    var sections: [2][5]u8 = undefined;
    var enc: [4]State = undefined;
    c.zcbor_new_encode_state(&enc, enc.len, &sections[0], sections[0].len, 1);
    try testing.expect(c.zcbor_cbor_bstr_fragments_start_encode(&enc, 7));
    try testing.expect(c.zcbor_uint32_put(&enc, 100)); // 3 of 5 used
    try testing.expect(c.zcbor_uint32_put(&enc, 200)); // 5 of 5 used
    try testing.expect(c.zcbor_payload_at_end(&enc));

    c.zcbor_update_state(&enc, &sections[1], sections[1].len);
    try testing.expect(c.zcbor_uint32_put(&enc, 300));
    try testing.expect(c.zcbor_str_fragments_end_encode(&enc));
    const sec1_used = @intFromPtr(enc[0].payload) - @intFromPtr(&sections[1]);
    try testing.expectEqual(@as(usize, 3), sec1_used);

    // Reassemble and decode in one piece.
    var whole: [8]u8 = undefined;
    @memcpy(whole[0..5], &sections[0]);
    @memcpy(whole[5..8], sections[1][0..3]);

    var dec: [2]State = undefined;
    c.zcbor_new_decode_state(&dec, dec.len, &whole, whole.len, 1, null, 0);
    var data: c.struct_zcbor_string = undefined;
    try testing.expect(c.zcbor_bstr_decode(&dec, &data));
    try testing.expectEqual(@as(usize, 7), data.len);

    var idec: [2]State = undefined;
    c.zcbor_new_decode_state(&idec, idec.len, data.value, data.len, 3, null, 0);
    try testing.expect(c.zcbor_uint32_expect(&idec, 100));
    try testing.expect(c.zcbor_uint32_expect(&idec, 200));
    try testing.expect(c.zcbor_uint32_expect(&idec, 300));
}

test "validate and splice collected fragments" {
    // "HelloWorld" bstr split across two payload sections.
    var buf: [16]u8 = undefined;
    var enc: [2]State = undefined;
    c.zcbor_new_encode_state(&enc, enc.len, &buf, buf.len, 1);
    try testing.expect(c.zcbor_bstr_encode_ptr(&enc, "HelloWorld", 10));
    const full = encoded(&enc, &buf);

    var frags: [2]c.struct_zcbor_string_fragment = undefined;
    var dec: [2]State = undefined;
    c.zcbor_new_decode_state(&dec, dec.len, full.ptr, 6, large_elem_count, null, 0);
    try testing.expect(c.zcbor_bstr_fragments_start_decode(&dec));
    try testing.expect(c.zcbor_str_fragment_decode(&dec, &frags[0]));
    try testing.expect(!c.zcbor_is_last_fragment(&frags[0]));

    c.zcbor_update_state(&dec, full.ptr + 6, full.len - 6);
    try testing.expect(c.zcbor_str_fragment_decode(&dec, &frags[1]));
    try testing.expect(c.zcbor_is_last_fragment(&frags[1]));
    try testing.expect(c.zcbor_str_fragments_end_decode(&dec));

    try testing.expect(c.zcbor_validate_string_fragments(&frags, 2));
    var spliced: [10]u8 = undefined;
    var spliced_len: usize = spliced.len;
    try testing.expect(c.zcbor_splice_string_fragments(&frags, 2, &spliced, &spliced_len));
    try testing.expectEqual(@as(usize, 10), spliced_len);
    try testing.expectEqualSlices(u8, "HelloWorld", &spliced);

    // Out-of-order fragments must fail validation.
    var swapped = [2]c.struct_zcbor_string_fragment{ frags[1], frags[0] };
    try testing.expect(!c.zcbor_validate_string_fragments(&swapped, 2));
}
