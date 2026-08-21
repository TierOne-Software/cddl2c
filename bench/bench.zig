//! Throughput benchmarks for the code cddl2c generates from
//! examples/sample.cddl, built at ReleaseFast (`zig build bench`).
//!
//! Each benchmark is validated once for correctness before timing. Iteration
//! counts auto-calibrate to ~250 ms per benchmark.

const std = @import("std");
const g = @import("gen");

// --- Fixtures (globals so benchmark fns need no context) ---------------------

var cfg: g.struct_config = undefined;
var cfg_wire: [128]u8 = undefined;
var cfg_wire_len: usize = 0;

var reading_wire: [32]u8 = undefined;
var reading_wire_len: usize = 0;

var event_reading_wire: [32]u8 = undefined;
var event_reading_wire_len: usize = 0;
const event_error_wire = [_]u8{0x02};

const blob_len = 64 * 1024;
var blob: [blob_len]u8 = undefined;
var blob_msg: g.struct_file_msg = undefined;
var blob_wire: [blob_len + 64]u8 = undefined;
var blob_wire_len: usize = 0;
var blob_rebuilt: [blob_len]u8 = undefined;

const n_log_items = 100;
var log_msgs: [n_log_items][12]u8 = undefined;
var log_entries: [n_log_items]g.struct_log_entry = undefined;
var log_seq: [2048]u8 = undefined; // the wrapped CBOR sequence by itself
var log_seq_len: usize = 0;
var log_wire: [2200]u8 = undefined;
var log_wire_len: usize = 0;

// --- Benchmark functions ------------------------------------------------------

fn encodeConfig() void {
    var out: [128]u8 = undefined;
    var out_len: usize = 0;
    const rc = g.cbor_encode_config(&out, out.len, &cfg, &out_len);
    std.mem.doNotOptimizeAway(rc);
}

fn decodeConfig() void {
    var out: g.struct_config = undefined;
    var out_len: usize = 0;
    const rc = g.cbor_decode_config(&cfg_wire, cfg_wire_len, &out, &out_len);
    std.mem.doNotOptimizeAway(rc);
}

/// Hand-fused equivalent of decode_config: same zcbor calls, but one flat
/// function with no per-rule functions, helpers, or entry wrapper.
/// The delta against `decodeConfig` is the generator's structural overhead.
fn decodeConfigHandwritten() void {
    var out: g.struct_config = undefined;
    var states: [4]g.zcbor_state_t = undefined;
    g.zcbor_new_decode_state(&states, states.len, &cfg_wire, cfg_wire_len, 1, null, 0);
    const ok = blk: {
        if (!g.zcbor_map_start_decode(&states)) break :blk false;
        if (!g.zcbor_tstr_expect_ptr(&states, "name", 4)) break :blk false;
        if (!g.zcbor_tstr_decode(&states, &out.name)) break :blk false;
        if (!g.zcbor_tstr_expect_ptr(&states, "color", 5)) break :blk false;
        var color: i64 = undefined;
        if (!g.zcbor_int64_decode(&states, &color)) break :blk false;
        if (color < 0 or color > 2) break :blk false;
        out.color = @intCast(color);
        if (!g.zcbor_tstr_expect_ptr(&states, "port", 4)) break :blk false;
        if (!g.zcbor_uint16_decode(&states, &out.port)) break :blk false;
        out.description_present = g.zcbor_tstr_expect_ptr(&states, "description", 11);
        if (out.description_present) {
            if (!g.zcbor_tstr_decode(&states, &out.description)) break :blk false;
        }
        if (!g.zcbor_multi_decode(0, 4, &out.extra_count, @ptrCast(&g.zcbor_uint32_decode), &states, &out.extra, @sizeOf(u32))) break :blk false;
        if (!g.zcbor_map_end_decode(&states)) break :blk false;
        break :blk true;
    };
    std.mem.doNotOptimizeAway(ok);
}

fn decodeReading() void {
    var out: g.struct_reading = undefined;
    var out_len: usize = 0;
    const rc = g.cbor_decode_reading(&reading_wire, reading_wire_len, &out, &out_len);
    std.mem.doNotOptimizeAway(rc);
}

fn decodeEventFirstChoice() void {
    var out: g.struct_event = undefined;
    var out_len: usize = 0;
    const rc = g.cbor_decode_event(&event_reading_wire, event_reading_wire_len, &out, &out_len);
    std.mem.doNotOptimizeAway(rc);
}

fn decodeEventLastChoice() void {
    var out: g.struct_event = undefined;
    var out_len: usize = 0;
    const rc = g.cbor_decode_event(&event_error_wire, event_error_wire.len, &out, &out_len);
    std.mem.doNotOptimizeAway(rc);
}

fn encodeFileMsg() void {
    var out_len: usize = 0;
    const rc = g.cbor_encode_file_msg(&blob_wire, blob_wire.len, &blob_msg, &out_len);
    std.mem.doNotOptimizeAway(rc);
}

fn decodeFileMsg() void {
    var out: g.struct_file_msg = undefined;
    var out_len: usize = 0;
    const rc = g.cbor_decode_file_msg(&blob_wire, blob_wire_len, &out, &out_len);
    std.mem.doNotOptimizeAway(rc);
}

const chunk = 1024;

fn decodeFileMsgFragmented() void {
    var states: [g.FILE_MSG_FRAG_N_STATES]g.zcbor_state_t = undefined;
    var hdr: g.struct_file_msg = undefined;
    if (g.cbor_decode_file_msg_frag_begin(&states, states.len, &blob_wire, chunk, &hdr) != g.ZCBOR_SUCCESS) return;
    var got: usize = 0;
    var fed: usize = chunk;
    while (got < blob_len) {
        if (g.zcbor_payload_at_end(&states)) {
            const next = @min(chunk, blob_wire_len - fed);
            g.zcbor_update_state(&states, blob_wire[fed..].ptr, next);
            fed += next;
        }
        var frag: g.struct_zcbor_string_fragment = undefined;
        if (g.cbor_decode_file_msg_frag_next(&states, &frag) != g.ZCBOR_SUCCESS) return;
        if (frag.fragment.len == 0) return;
        @memcpy(blob_rebuilt[frag.offset..][0..frag.fragment.len], frag.fragment.value[0..frag.fragment.len]);
        got += frag.fragment.len;
    }
    const rc = g.cbor_decode_file_msg_frag_end(&states, null);
    std.mem.doNotOptimizeAway(rc);
}

fn encodeFileMsgFragmented() void {
    var states: [g.FILE_MSG_FRAG_N_STATES]g.zcbor_state_t = undefined;
    var out: [blob_len + 64]u8 = undefined;
    // Sections are contiguous slices of `out`, switched every `chunk` bytes:
    // measures section-switching overhead without reassembly memcpys.
    if (g.cbor_encode_file_msg_frag_begin(&states, states.len, &out, chunk, &blob_msg, blob_len) != g.ZCBOR_SUCCESS) return;
    var sent: usize = 0;
    var used: usize = chunk;
    while (sent < blob_len) {
        var enc_len: usize = 0;
        if (g.cbor_encode_file_msg_frag_feed(&states, &blob[sent], blob_len - sent, &enc_len) != g.ZCBOR_SUCCESS) return;
        sent += enc_len;
        if (sent < blob_len and g.zcbor_payload_at_end(&states)) {
            g.zcbor_update_state(&states, out[used..].ptr, chunk);
            used += chunk;
        }
    }
    const rc = g.cbor_encode_file_msg_frag_end(&states, null);
    std.mem.doNotOptimizeAway(rc);
}

fn decodeLogItemsFragApi() void {
    var states: [g.LOG_FILE_FRAG_N_STATES]g.zcbor_state_t = undefined;
    var hdr: g.struct_log_file = undefined;
    if (g.cbor_decode_log_file_frag_begin(&states, states.len, &log_wire, log_wire_len, &hdr) != g.ZCBOR_SUCCESS) return;
    while (!g.cbor_decode_log_file_frag_at_end(&states)) {
        var ent: g.struct_log_entry = undefined;
        if (g.cbor_decode_log_file_frag_item(&states, &ent) != g.ZCBOR_SUCCESS) return;
        std.mem.doNotOptimizeAway(ent.seq);
    }
    const rc = g.cbor_decode_log_file_frag_end(&states, null);
    std.mem.doNotOptimizeAway(rc);
}

/// Baseline for decodeLogItemsFragApi: the same 100 items decoded straight
/// from a contiguous buffer with the plain entry function (no wrapped-string
/// bookkeeping, no per-item backup).
fn decodeLogItemsBaseline() void {
    var pos: usize = 0;
    while (pos < log_seq_len) {
        var ent: g.struct_log_entry = undefined;
        var one_len: usize = 0;
        if (g.cbor_decode_log_entry(log_seq[pos..].ptr, log_seq_len - pos, &ent, &one_len) != g.ZCBOR_SUCCESS) return;
        pos += one_len;
        std.mem.doNotOptimizeAway(ent.seq);
    }
}

// --- Runner -------------------------------------------------------------------

const Bench = struct {
    name: []const u8,
    bytes_per_op: usize,
    func: *const fn () void,
};

fn nowNs(io: std.Io) i96 {
    // `.awake` is CLOCK_MONOTONIC on Linux.
    return std.Io.Timestamp.now(io, .awake).nanoseconds;
}

fn runBench(io: std.Io, b: Bench) void {
    // Warm up and calibrate the iteration count to ~60 ms per sample.
    var iters: u64 = 1;
    var elapsed: i96 = 0;
    while (true) {
        const t0 = nowNs(io);
        for (0..iters) |_| b.func();
        elapsed = nowNs(io) - t0;
        if (elapsed >= 60_000_000) break;
        if (elapsed < 1_000_000) {
            iters *|= 100;
        } else {
            const target: u128 = 80_000_000;
            iters = @intCast(@min(target * iters / @as(u128, @intCast(elapsed)) + 1, iters *| 100));
        }
    }

    // Best of 5 samples: the minimum is the least-noise estimator on a
    // machine with frequency scaling and background load.
    var best: i96 = elapsed;
    for (0..4) |_| {
        const t0 = nowNs(io);
        for (0..iters) |_| b.func();
        const dt = nowNs(io) - t0;
        if (dt < best) best = dt;
    }

    const ns_per_op = @as(f64, @floatFromInt(best)) / @as(f64, @floatFromInt(iters));
    const ops_per_s = 1e9 / ns_per_op;
    const mb_per_s = @as(f64, @floatFromInt(b.bytes_per_op)) * 1000.0 / ns_per_op;
    std.debug.print("{s:<44} {d:>10.0} {d:>12.0} {d:>10.1}\n", .{
        b.name, ns_per_op, ops_per_s, mb_per_s,
    });
}

fn fail(comptime what: []const u8) noreturn {
    std.debug.print("fixture setup failed: " ++ what ++ "\n", .{});
    std.process.exit(1);
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    // --- Fixture setup, validated. ---
    cfg = std.mem.zeroes(g.struct_config);
    cfg.name = .{ .value = "node", .len = 4 };
    cfg.color = 2;
    cfg.port = 8080;
    cfg.description_present = true;
    cfg.description = .{ .value = "a sensor", .len = 8 };
    cfg.extra[0] = 11;
    cfg.extra[1] = 22;
    cfg.extra_count = 2;
    if (g.cbor_encode_config(&cfg_wire, cfg_wire.len, &cfg, &cfg_wire_len) != g.ZCBOR_SUCCESS)
        fail("config");

    {
        var r = std.mem.zeroes(g.struct_reading);
        r.id = 7;
        r.value = 1.5;
        r.level = 99;
        if (g.cbor_encode_reading(&reading_wire, reading_wire.len, &r, &reading_wire_len) != g.ZCBOR_SUCCESS)
            fail("reading");
        var ev = std.mem.zeroes(g.struct_event);
        ev.choice = g.event_reading_c;
        ev.unnamed_0.reading = r;
        if (g.cbor_encode_event(&event_reading_wire, event_reading_wire.len, &ev, &event_reading_wire_len) != g.ZCBOR_SUCCESS)
            fail("event");
    }

    for (&blob, 0..) |*bb, i| bb.* = @truncate(i *% 31 +% 7);
    blob_msg = std.mem.zeroes(g.struct_file_msg);
    blob_msg.filename = .{ .value = "fw.srec", .len = 7 };
    blob_msg.file_size = blob_len;
    blob_msg.data = .{ .value = &blob, .len = blob_len };
    if (g.cbor_encode_file_msg(&blob_wire, blob_wire.len, &blob_msg, &blob_wire_len) != g.ZCBOR_SUCCESS)
        fail("file_msg");

    {
        for (0..n_log_items) |i| {
            const text = std.fmt.bufPrint(&log_msgs[i], "entry-{d:0>3}", .{i}) catch fail("log fmt");
            log_entries[i] = std.mem.zeroes(g.struct_log_entry);
            log_entries[i].seq = @intCast(i);
            log_entries[i].msg = .{ .value = &log_msgs[i], .len = text.len };
            var one_len: usize = 0;
            if (g.cbor_encode_log_entry(log_seq[log_seq_len..].ptr, log_seq.len - log_seq_len, &log_entries[i], &one_len) != g.ZCBOR_SUCCESS)
                fail("log_entry");
            log_seq_len += one_len;
        }
        var states: [g.LOG_FILE_FRAG_N_STATES]g.zcbor_state_t = undefined;
        var msg = std.mem.zeroes(g.struct_log_file);
        msg.name = .{ .value = "boot.log", .len = 8 };
        if (g.cbor_encode_log_file_frag_begin(&states, states.len, &log_wire, log_wire.len, &msg, log_seq_len) != g.ZCBOR_SUCCESS)
            fail("log_file begin");
        for (0..n_log_items) |i| {
            if (g.cbor_encode_log_file_frag_item(&states, &log_entries[i]) != g.ZCBOR_SUCCESS)
                fail("log_file item");
        }
        if (g.cbor_encode_log_file_frag_end(&states, &log_wire_len) != g.ZCBOR_SUCCESS)
            fail("log_file end");
    }

    // Validate the fragmented paths once before timing them.
    decodeFileMsgFragmented();
    if (!std.mem.eql(u8, &blob, &blob_rebuilt)) fail("fragmented reassembly mismatch");

    std.debug.print("\n{s:<44} {s:>10} {s:>12} {s:>10}\n", .{ "benchmark", "ns/op", "ops/s", "MB/s" });
    std.debug.print("{s:-<80}\n", .{""});

    const benches = [_]Bench{
        .{ .name = "encode config (~56 B map)", .bytes_per_op = cfg_wire_len, .func = encodeConfig },
        .{ .name = "decode config", .bytes_per_op = cfg_wire_len, .func = decodeConfig },
        .{ .name = "decode config (handwritten baseline)", .bytes_per_op = cfg_wire_len, .func = decodeConfigHandwritten },
        .{ .name = "decode reading (9 B array)", .bytes_per_op = reading_wire_len, .func = decodeReading },
        .{ .name = "decode event (union, 1st choice hits)", .bytes_per_op = event_reading_wire_len, .func = decodeEventFirstChoice },
        .{ .name = "decode event (union, 3rd choice hits)", .bytes_per_op = event_error_wire.len, .func = decodeEventLastChoice },
        .{ .name = "encode file_msg (64 KiB blob)", .bytes_per_op = blob_wire_len, .func = encodeFileMsg },
        .{ .name = "decode file_msg (64 KiB blob, zero copy)", .bytes_per_op = blob_wire_len, .func = decodeFileMsg },
        .{ .name = "decode file_msg fragmented (1 KiB chunks)", .bytes_per_op = blob_wire_len, .func = decodeFileMsgFragmented },
        .{ .name = "encode file_msg fragmented (1 KiB sections)", .bytes_per_op = blob_wire_len, .func = encodeFileMsgFragmented },
        .{ .name = "decode 100 log items (frag_item API)", .bytes_per_op = log_wire_len, .func = decodeLogItemsFragApi },
        .{ .name = "decode 100 log items (contiguous baseline)", .bytes_per_op = log_seq_len, .func = decodeLogItemsBaseline },
    };
    for (benches) |b| runBench(io, b);
    std.debug.print("\n", .{});
}
