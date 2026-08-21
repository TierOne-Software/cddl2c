//! Fuzz harnesses for the C code cddl2c generates from examples/sample.cddl.
//!
//! These test the *output* of the generator: the generated decoders must
//! survive arbitrary bytes, and the generated encoder/decoder pairs must
//! roundtrip losslessly — including through the fragmented APIs with
//! fuzz-chosen section and chunk boundaries.

const std = @import("std");
const g = @import("gen");

const testing = std.testing;

fn sectionUsed(states: []const g.zcbor_state_t, buf: [*]const u8) usize {
    return @intFromPtr(states[0].payload) - @intFromPtr(buf);
}

/// Arbitrary bytes into every generated one-shot decoder: must reject or
/// accept cleanly, never crash, hang, or read out of bounds.
fn fuzzGeneratedDecoders(_: void, smith: *testing.Smith) !void {
    var buf: [512]u8 = undefined;
    const len = smith.slice(&buf);
    var out_len: usize = 0;
    {
        var v: g.struct_config = undefined;
        _ = g.cbor_decode_config(&buf, len, &v, &out_len);
    }
    {
        var v: g.struct_reading = undefined;
        _ = g.cbor_decode_reading(&buf, len, &v, &out_len);
    }
    {
        var v: g.struct_event = undefined;
        _ = g.cbor_decode_event(&buf, len, &v, &out_len);
    }
    {
        var v: g.struct_file_msg = undefined;
        _ = g.cbor_decode_file_msg(&buf, len, &v, &out_len);
    }
    {
        var v: g.struct_log_file = undefined;
        _ = g.cbor_decode_log_file(&buf, len, &v, &out_len);
    }
    {
        var v: g.percentage_t = undefined;
        _ = g.cbor_decode_percentage(&buf, len, &v, &out_len);
    }
    {
        var v: g.struct_envelope = undefined;
        _ = g.cbor_decode_envelope(&buf, len, &v, &out_len);
    }
}

/// Random-but-valid config structs must roundtrip bit-exactly through the
/// generated encoder and decoder.
fn fuzzConfigRoundtrip(_: void, smith: *testing.Smith) !void {
    var name_buf: [16]u8 = undefined;
    var desc_buf: [16]u8 = undefined;

    var cfg = std.mem.zeroes(g.struct_config);
    const name_len = smith.slice(&name_buf);
    cfg.name = .{ .value = &name_buf, .len = name_len };
    cfg.color = @intCast(smith.valueRangeAtMost(u8, 0, 2));
    cfg.port = smith.value(u16);
    cfg.description_present = smith.value(bool);
    if (cfg.description_present) {
        const desc_len = smith.slice(&desc_buf);
        cfg.description = .{ .value = &desc_buf, .len = desc_len };
    }
    cfg.extra_count = smith.valueRangeAtMost(u8, 0, 4);
    for (0..cfg.extra_count) |i| cfg.extra[i] = smith.value(u32);

    var wire: [256]u8 = undefined;
    var wire_len: usize = 0;
    try testing.expectEqual(g.ZCBOR_SUCCESS, g.cbor_encode_config(&wire, wire.len, &cfg, &wire_len));

    var out = std.mem.zeroes(g.struct_config);
    var out_len: usize = 0;
    try testing.expectEqual(g.ZCBOR_SUCCESS, g.cbor_decode_config(&wire, wire_len, &out, &out_len));
    try testing.expectEqual(wire_len, out_len);

    try testing.expectEqualSlices(u8, name_buf[0..name_len], out.name.value[0..out.name.len]);
    try testing.expectEqual(cfg.color, out.color);
    try testing.expectEqual(cfg.port, out.port);
    try testing.expectEqual(cfg.description_present, out.description_present);
    if (cfg.description_present) {
        try testing.expectEqualSlices(u8, cfg.description.value[0..cfg.description.len], out.description.value[0..out.description.len]);
    }
    try testing.expectEqual(cfg.extra_count, out.extra_count);
    for (0..cfg.extra_count) |i| try testing.expectEqual(cfg.extra[i], out.extra[i]);
}

/// The fragmented file_msg encoder, driven across fuzz-chosen section sizes,
/// must produce byte-identical output to the one-shot encoder; the
/// fragmented decoder, fed fuzz-chosen chunks, must rebuild the content.
fn fuzzFileMsgFragDifferential(_: void, smith: *testing.Smith) !void {
    var content: [1024]u8 = undefined;
    const clen = smith.slice(&content);

    var msg = std.mem.zeroes(g.struct_file_msg);
    msg.filename = .{ .value = "f", .len = 1 };
    msg.file_size = @intCast(clen);
    msg.data = .{ .value = &content, .len = clen };

    var wire: [1200]u8 = undefined;
    var wire_len: usize = 0;
    try testing.expectEqual(g.ZCBOR_SUCCESS, g.cbor_encode_file_msg(&wire, wire.len, &msg, &wire_len));

    var states: [g.FILE_MSG_FRAG_N_STATES]g.zcbor_state_t = undefined;

    // --- Fragmented encode with random section sizes ------------------------
    var frag_wire: [1600]u8 = undefined;
    var frag_len: usize = 0;
    var sec: [512]u8 = undefined;
    var sec_size: usize = smith.valueRangeAtMost(u32, 64, 512);
    try testing.expectEqual(g.ZCBOR_SUCCESS, g.cbor_encode_file_msg_frag_begin(&states, states.len, &sec, sec_size, &msg, clen));

    var sent: usize = 0;
    var iterations: usize = 0;
    while (sent < clen) : (iterations += 1) {
        if (iterations > 4096) return error.TooManyIterations;
        var enc_len: usize = 0;
        try testing.expectEqual(g.ZCBOR_SUCCESS, g.cbor_encode_file_msg_frag_feed(&states, &content[sent], clen - sent, &enc_len));
        sent += enc_len;
        if (sent < clen and g.zcbor_payload_at_end(&states)) {
            @memcpy(frag_wire[frag_len..][0..sec_size], sec[0..sec_size]);
            frag_len += sec_size;
            sec_size = smith.valueRangeAtMost(u32, 1, 512);
            g.zcbor_update_state(&states, &sec, sec_size);
        }
    }
    var tail_len: usize = 0;
    try testing.expectEqual(g.ZCBOR_SUCCESS, g.cbor_encode_file_msg_frag_end(&states, &tail_len));
    @memcpy(frag_wire[frag_len..][0..tail_len], sec[0..tail_len]);
    frag_len += tail_len;

    try testing.expectEqualSlices(u8, wire[0..wire_len], frag_wire[0..frag_len]);

    // --- Fragmented decode with random chunk sizes --------------------------
    const first: usize = @min(wire_len, 40 + smith.valueRangeAtMost(u32, 0, 160));
    var hdr = std.mem.zeroes(g.struct_file_msg);
    try testing.expectEqual(g.ZCBOR_SUCCESS, g.cbor_decode_file_msg_frag_begin(&states, states.len, &wire, first, &hdr));
    try testing.expectEqual(@as(u32, @intCast(clen)), hdr.file_size);

    var rebuilt: [1024]u8 = undefined;
    var got: usize = 0;
    var fed: usize = first;
    iterations = 0;
    while (got < clen) : (iterations += 1) {
        if (iterations > 4096) return error.TooManyIterations;
        if (g.zcbor_payload_at_end(&states)) {
            if (fed >= wire_len) return error.RanOutOfPayload;
            const next = smith.valueRangeAtMost(u32, 1, @intCast(wire_len - fed));
            g.zcbor_update_state(&states, &wire[fed], next);
            fed += next;
        }
        var frag: g.struct_zcbor_string_fragment = undefined;
        try testing.expectEqual(g.ZCBOR_SUCCESS, g.cbor_decode_file_msg_frag_next(&states, &frag));
        try testing.expect(frag.fragment.len > 0);
        try testing.expect(frag.offset + frag.fragment.len <= clen);
        @memcpy(rebuilt[frag.offset..][0..frag.fragment.len], frag.fragment.value[0..frag.fragment.len]);
        got += frag.fragment.len;
    }
    try testing.expectEqual(g.ZCBOR_SUCCESS, g.cbor_decode_file_msg_frag_end(&states, null));
    try testing.expectEqualSlices(u8, content[0..clen], rebuilt[0..clen]);
}

/// CBOR-in-CBOR streaming: log entries pushed through the fragmented item
/// API with fuzz-chosen section sizes (exercising the retry/rollback path),
/// then decoded back one item at a time from fuzz-chosen chunks with a
/// staging buffer (exercising mid-item rollback on the decode side).
fn fuzzLogFileStreaming(_: void, smith: *testing.Smith) !void {
    const max_entries = 10;
    var msg_bufs: [max_entries][12]u8 = undefined;
    var msg_lens: [max_entries]usize = undefined;
    var entries: [max_entries]g.struct_log_entry = undefined;
    const n = smith.valueRangeAtMost(u8, 1, max_entries);

    var scratch: [512]u8 = undefined;
    var total_len: usize = 0;
    for (0..n) |i| {
        msg_lens[i] = smith.slice(&msg_bufs[i]);
        entries[i] = std.mem.zeroes(g.struct_log_entry);
        entries[i].seq = @intCast(i);
        entries[i].msg = .{ .value = &msg_bufs[i], .len = msg_lens[i] };
        var one_len: usize = 0;
        try testing.expectEqual(g.ZCBOR_SUCCESS, g.cbor_encode_log_entry(scratch[total_len..].ptr, scratch.len - total_len, &entries[i], &one_len));
        total_len += one_len;
    }

    var msg = std.mem.zeroes(g.struct_log_file);
    msg.name = .{ .value = "l", .len = 1 };

    // --- Fragmented encode with retry on section-full -----------------------
    var states: [g.LOG_FILE_FRAG_N_STATES]g.zcbor_state_t = undefined;
    var wire: [1024]u8 = undefined;
    var wire_len: usize = 0;
    var sec: [256]u8 = undefined;
    var sec_size: usize = smith.valueRangeAtMost(u32, 48, 256);
    try testing.expectEqual(g.ZCBOR_SUCCESS, g.cbor_encode_log_file_frag_begin(&states, states.len, &sec, sec_size, &msg, total_len));

    for (0..n) |i| {
        if (g.cbor_encode_log_file_frag_item(&states, &entries[i]) != g.ZCBOR_SUCCESS) {
            // Section full; the item was rolled back. Flush and retry.
            const used = sectionUsed(&states, &sec);
            @memcpy(wire[wire_len..][0..used], sec[0..used]);
            wire_len += used;
            sec_size = smith.valueRangeAtMost(u32, 48, 256);
            g.zcbor_update_state(&states, &sec, sec_size);
            try testing.expectEqual(g.ZCBOR_SUCCESS, g.cbor_encode_log_file_frag_item(&states, &entries[i]));
        }
    }
    var tail_len: usize = 0;
    try testing.expectEqual(g.ZCBOR_SUCCESS, g.cbor_encode_log_file_frag_end(&states, &tail_len));
    @memcpy(wire[wire_len..][0..tail_len], sec[0..tail_len]);
    wire_len += tail_len;

    // --- One-shot cross-check ------------------------------------------------
    var whole = std.mem.zeroes(g.struct_log_file);
    var dec_len: usize = 0;
    try testing.expectEqual(g.ZCBOR_SUCCESS, g.cbor_decode_log_file(&wire, wire_len, &whole, &dec_len));
    try testing.expectEqual(total_len, whole.entries.len);
    try testing.expectEqualSlices(u8, scratch[0..total_len], whole.entries.value[0..whole.entries.len]);

    // --- Fragmented decode with staging across chunk boundaries -------------
    var stage: [2][512]u8 = undefined;
    var stage_sel: usize = 0;
    const first: usize = @min(wire_len, 24 + smith.valueRangeAtMost(u32, 0, 72));
    var hdr = std.mem.zeroes(g.struct_log_file);
    try testing.expectEqual(g.ZCBOR_SUCCESS, g.cbor_decode_log_file_frag_begin(&states, states.len, &wire, first, &hdr));

    var fed: usize = first;
    var idx: usize = 0;
    var iterations: usize = 0;
    while (!g.cbor_decode_log_file_frag_at_end(&states)) : (iterations += 1) {
        if (iterations > 4096) return error.TooManyIterations;
        var ent = std.mem.zeroes(g.struct_log_entry);
        if (g.cbor_decode_log_file_frag_item(&states, &ent) != g.ZCBOR_SUCCESS) {
            // Item straddles the boundary: tail + next chunk -> staging.
            const tail = @intFromPtr(states[0].payload_end) - @intFromPtr(states[0].payload);
            if (fed >= wire_len) return error.RanOutOfPayload;
            const next = @min(@as(usize, smith.valueRangeAtMost(u32, 1, 128)), wire_len - fed);
            const buf = &stage[stage_sel];
            stage_sel ^= 1;
            @memcpy(buf[0..tail], states[0].payload[0..tail]);
            @memcpy(buf[tail..][0..next], wire[fed..][0..next]);
            fed += next;
            g.zcbor_update_state(&states, buf, tail + next);
            continue;
        }
        try testing.expect(idx < n);
        try testing.expectEqual(@as(u32, @intCast(idx)), ent.seq);
        try testing.expectEqualSlices(u8, msg_bufs[idx][0..msg_lens[idx]], ent.msg.value[0..ent.msg.len]);
        idx += 1;
    }
    try testing.expectEqual(@as(usize, n), idx);
    try testing.expectEqual(g.ZCBOR_SUCCESS, g.cbor_decode_log_file_frag_end(&states, null));
}

test "fuzz: generated decoders survive arbitrary bytes" {
    try testing.fuzz({}, fuzzGeneratedDecoders, .{ .corpus = &.{
        // {"name": "x", "color": 1, "port": 1}  (config-shaped prefix)
        "\xa3\x64name\x61x\x65color\x01\x64port\x01",
        "\x83\x07\xfa\x3f\xc0\x00\x00\x18\x63", // [7, 1.5, 99] (reading)
        "\x02", // error-code
    } });
}

test "fuzz: generated config codecs roundtrip" {
    try testing.fuzz({}, fuzzConfigRoundtrip, .{});
}

test "fuzz: generated fragmented file_msg API is a faithful differential" {
    try testing.fuzz({}, fuzzFileMsgFragDifferential, .{});
}

test "fuzz: generated CBOR-in-CBOR log streaming with retry and staging" {
    try testing.fuzz({}, fuzzLogFileStreaming, .{});
}
