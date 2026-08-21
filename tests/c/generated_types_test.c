/* Compile- and run-time checks for the code cddl2c generates from
 * examples/sample.cddl (types header + decode/encode C files). Compiled as
 * C11 with -Werror: any mismatch between the generator's output and these
 * expectations fails the build. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "zcbor_encode.h"

#include "sample_types.h"
#include "sample_decode.h"
#include "sample_encode.h"

/* CDDL enumeration -> C enum with the right values. */
_Static_assert(colors_red_c == 0, "colors_red_c");
_Static_assert(colors_green_c == 1, "colors_green_c");
_Static_assert(colors_blue_c == 2, "colors_blue_c");

/* Choice of named int literals -> C enum with the literal values. */
_Static_assert(error_code_err_ok_c == 0, "err_ok");
_Static_assert(error_code_err_crc_c == 1, "err_crc");
_Static_assert(error_code_err_timeout_c == 2, "err_timeout");

/* Scalar aliases keep static, narrowed representations. */
_Static_assert(sizeof(port_t) == 2, "port is uint16_t");
_Static_assert(sizeof(percentage_t) == 1, "percentage fits uint8_t");
_Static_assert(sizeof(sensor_id_t) == 4, "sensor-id is uint32_t");

/* Repeated member arrays are statically sized. */
_Static_assert(sizeof(((struct config *)0)->extra) == 4 * sizeof(uint32_t),
	       "extra[4]");

static int check_types(void)
{
	/* The generated structs must be plain aggregates usable without any
	 * dynamic allocation. */
	struct config cfg;
	memset(&cfg, 0, sizeof(cfg));
	cfg.color = colors_green_c;
	cfg.port = 8080;
	cfg.name.value = (const uint8_t *)"demo";
	cfg.name.len = 4;
	cfg.description_present = false;
	cfg.extra[0] = 1;
	cfg.extra_count = 1;

	struct reading r;
	memset(&r, 0, sizeof(r));
	r.id = 7;
	r.value = 1.5f;
	r.level = 99;

	struct event ev;
	memset(&ev, 0, sizeof(ev));
	ev.choice = event_reading_c;
	ev.reading = r;

	if (cfg.color != colors_green_c)
		return 1;
	if (ev.choice != event_reading_c)
		return 1;
	if (ev.reading.id != 7)
		return 1;
	return 0;
}

static int check_config_roundtrip(void)
{
	uint8_t payload[256];
	size_t enc_len = 0;
	size_t dec_len = 0;

	struct config cfg;
	memset(&cfg, 0, sizeof(cfg));
	cfg.name.value = (const uint8_t *)"demo";
	cfg.name.len = 4;
	cfg.color = colors_blue_c;
	cfg.port = 8080;
	cfg.description_present = true;
	cfg.description.value = (const uint8_t *)"a sensor";
	cfg.description.len = 8;
	cfg.extra[0] = 11;
	cfg.extra[1] = 22;
	cfg.extra_count = 2;

	if (cbor_encode_config(payload, sizeof(payload), &cfg, &enc_len) != ZCBOR_SUCCESS)
		return 10;
	if (enc_len == 0)
		return 11;

	struct config out;
	memset(&out, 0, sizeof(out));
	if (cbor_decode_config(payload, enc_len, &out, &dec_len) != ZCBOR_SUCCESS)
		return 12;
	if (dec_len != enc_len)
		return 13;
	if (out.name.len != 4 || memcmp(out.name.value, "demo", 4) != 0)
		return 14;
	if (out.color != colors_blue_c)
		return 15;
	if (out.port != 8080)
		return 16;
	if (!out.description_present)
		return 17;
	if (out.description.len != 8 || memcmp(out.description.value, "a sensor", 8) != 0)
		return 18;
	if (out.extra_count != 2 || out.extra[0] != 11 || out.extra[1] != 22)
		return 19;

	/* Optional member absent. */
	cfg.description_present = false;
	cfg.extra_count = 0;
	if (cbor_encode_config(payload, sizeof(payload), &cfg, &enc_len) != ZCBOR_SUCCESS)
		return 20;
	memset(&out, 0, sizeof(out));
	if (cbor_decode_config(payload, enc_len, &out, &dec_len) != ZCBOR_SUCCESS)
		return 21;
	if (out.description_present)
		return 22;
	if (out.extra_count != 0)
		return 23;
	return 0;
}

static int check_event_roundtrip(void)
{
	uint8_t payload[128];
	size_t enc_len = 0;
	size_t dec_len = 0;

	struct event ev;
	memset(&ev, 0, sizeof(ev));
	ev.choice = event_reading_c;
	ev.reading.id = 7;
	ev.reading.value = 1.5f;
	ev.reading.level = 99;

	if (cbor_encode_event(payload, sizeof(payload), &ev, &enc_len) != ZCBOR_SUCCESS)
		return 30;

	struct event out;
	memset(&out, 0, sizeof(out));
	if (cbor_decode_event(payload, enc_len, &out, &dec_len) != ZCBOR_SUCCESS)
		return 31;
	if (out.choice != event_reading_c)
		return 32;
	if (out.reading.id != 7 || out.reading.level != 99)
		return 33;
	if (out.reading.value < 1.4f || out.reading.value > 1.6f)
		return 34;
	return 0;
}

static int check_enum_roundtrip(void)
{
	uint8_t payload[16];
	size_t enc_len = 0;
	size_t dec_len = 0;

	enum error_code ec = error_code_err_timeout_c;
	if (cbor_encode_error_code(payload, sizeof(payload), &ec, &enc_len) != ZCBOR_SUCCESS)
		return 40;
	if (enc_len != 1 || payload[0] != 0x02)
		return 41;

	enum error_code out;
	if (cbor_decode_error_code(payload, enc_len, &out, &dec_len) != ZCBOR_SUCCESS)
		return 42;
	if (out != error_code_err_timeout_c)
		return 43;

	/* Values outside the enumeration must be rejected. */
	payload[0] = 0x05;
	if (cbor_decode_error_code(payload, 1, &out, &dec_len) == ZCBOR_SUCCESS)
		return 44;
	return 0;
}

static int check_range_validation(void)
{
	uint8_t payload[16];
	size_t enc_len = 0;
	size_t dec_len = 0;

	percentage_t pct = 42;
	if (cbor_encode_percentage(payload, sizeof(payload), &pct, &enc_len) != ZCBOR_SUCCESS)
		return 50;

	percentage_t out;
	if (cbor_decode_percentage(payload, enc_len, &out, &dec_len) != ZCBOR_SUCCESS)
		return 51;
	if (out != 42)
		return 52;

	/* 0..100: 101 must be rejected on encode... */
	pct = 101;
	if (cbor_encode_percentage(payload, sizeof(payload), &pct, &enc_len) == ZCBOR_SUCCESS)
		return 53;

	/* ...and on decode (0x18 0x65 = 101). */
	payload[0] = 0x18;
	payload[1] = 0x65;
	if (cbor_decode_percentage(payload, 2, &out, &dec_len) == ZCBOR_SUCCESS)
		return 54;
	return 0;
}

/* Fragmented file transfer: encode a 1000-byte "file" through 512-byte
 * output sections, reassemble the wire image, cross-check it with the
 * one-shot decoder, then decode it again from 128-byte input chunks using
 * the generated fragment API. */
static int check_fragmented_transfer(void)
{
	static uint8_t file[1000];
	static uint8_t sections[3][512];
	static uint8_t wire[3 * 512];
	size_t sec_used[3] = { 0, 0, 0 };
	zcbor_state_t states[FILE_MSG_FRAG_N_STATES];

	for (size_t i = 0; i < sizeof(file); i++)
		file[i] = (uint8_t)(i * 31 + 7);

	struct file_msg msg;
	memset(&msg, 0, sizeof(msg));
	msg.filename.value = (const uint8_t *)"fw.srec";
	msg.filename.len = 7;
	msg.file_size = sizeof(file);

	/* --- Sender: stream the file out in 300-byte reads. --- */
	if (cbor_encode_file_msg_frag_begin(states, FILE_MSG_FRAG_N_STATES,
					    sections[0], sizeof(sections[0]),
					    &msg, sizeof(file)) != ZCBOR_SUCCESS)
		return 60;

	size_t sent = 0;
	size_t sec_idx = 0;
	while (sent < sizeof(file)) {
		size_t want = sizeof(file) - sent;
		if (want > 300)
			want = 300;
		size_t enc_len = 0;
		if (cbor_encode_file_msg_frag_feed(states, &file[sent], want,
						   &enc_len) != ZCBOR_SUCCESS)
			return 61;
		sent += enc_len;
		if (sent < sizeof(file) && zcbor_payload_at_end(states)) {
			sec_used[sec_idx] = sizeof(sections[0]);
			sec_idx++;
			if (sec_idx >= 3)
				return 62;
			zcbor_update_state(states, sections[sec_idx],
					   sizeof(sections[0]));
		}
	}
	if (cbor_encode_file_msg_frag_end(states, &sec_used[sec_idx]) != ZCBOR_SUCCESS)
		return 63;

	size_t wire_len = 0;
	for (size_t i = 0; i <= sec_idx; i++) {
		memcpy(&wire[wire_len], sections[i], sec_used[i]);
		wire_len += sec_used[i];
	}

	/* --- Cross-check: the one-shot decoder accepts the wire image. --- */
	struct file_msg out;
	size_t dec_len = 0;
	memset(&out, 0, sizeof(out));
	if (cbor_decode_file_msg(wire, wire_len, &out, &dec_len) != ZCBOR_SUCCESS)
		return 64;
	if (dec_len != wire_len)
		return 65;
	if (out.filename.len != 7 || memcmp(out.filename.value, "fw.srec", 7) != 0)
		return 66;
	if (out.file_size != sizeof(file))
		return 67;
	if (out.data.len != sizeof(file) ||
	    memcmp(out.data.value, file, sizeof(file)) != 0)
		return 68;

	/* --- Receiver: decode from 128-byte link-layer chunks. --- */
	static uint8_t rebuilt[1000];
	struct file_msg hdr;
	memset(&hdr, 0, sizeof(hdr));
	if (cbor_decode_file_msg_frag_begin(states, FILE_MSG_FRAG_N_STATES,
					    wire, 128, &hdr) != ZCBOR_SUCCESS)
		return 70;
	if (hdr.filename.len != 7 || memcmp(hdr.filename.value, "fw.srec", 7) != 0)
		return 71;
	if (hdr.file_size != sizeof(file))
		return 72;

	size_t fed = 128;
	size_t got = 0;
	while (got < sizeof(file)) {
		if (zcbor_payload_at_end(states)) {
			if (fed >= wire_len)
				return 73;
			size_t next = wire_len - fed;
			if (next > 128)
				next = 128;
			zcbor_update_state(states, &wire[fed], next);
			fed += next;
		}
		struct zcbor_string_fragment frag;
		if (cbor_decode_file_msg_frag_next(states, &frag) != ZCBOR_SUCCESS)
			return 74;
		if (frag.total_len != sizeof(file) ||
		    frag.offset + frag.fragment.len > sizeof(file))
			return 75;
		memcpy(&rebuilt[frag.offset], frag.fragment.value,
		       frag.fragment.len);
		got += frag.fragment.len;
		if (got == sizeof(file) && !zcbor_is_last_fragment(&frag))
			return 76;
	}
	/* The map's closing bytes may sit in a chunk we have not fed yet. */
	if (zcbor_payload_at_end(states) && fed < wire_len) {
		zcbor_update_state(states, &wire[fed], wire_len - fed);
		fed = wire_len;
	}
	if (cbor_decode_file_msg_frag_end(states, NULL) != ZCBOR_SUCCESS)
		return 77;
	if (memcmp(rebuilt, file, sizeof(file)) != 0)
		return 78;
	return 0;
}

/* CBOR-in-CBOR streaming: send 24 log entries as a wrapped CBOR sequence
 * through 160-byte output sections (retrying items that hit a section
 * boundary), then receive them one entry at a time from 96-byte chunks,
 * staging partial items across chunk boundaries. */
static int check_cbor_in_cbor_streaming(void)
{
	enum { n_entries = 24, sec_size = 160, chunk_size = 96 };
	static char msgs[n_entries][12];
	static uint8_t scratch[512];    /* pre-encoded sequence, for sizing */
	static uint8_t sections[4][sec_size];
	static uint8_t wire[4 * sec_size];
	size_t sec_used[4] = { 0, 0, 0, 0 };
	zcbor_state_t states[LOG_FILE_FRAG_N_STATES];

	/* Pre-encode every entry once to learn the wrapped total length (a
	 * sender streaming from storage would know its sizes up front). */
	struct log_entry entries[n_entries];
	size_t total_len = 0;
	for (size_t i = 0; i < n_entries; i++) {
		int wrote = snprintf(msgs[i], sizeof(msgs[i]), "entry-%02u", (unsigned)i);
		if (wrote != 8)
			return 80;
		entries[i].seq = (uint32_t)i;
		entries[i].msg.value = (const uint8_t *)msgs[i];
		entries[i].msg.len = 8;

		size_t one_len = 0;
		if (cbor_encode_log_entry(&scratch[total_len],
					  sizeof(scratch) - total_len,
					  &entries[i], &one_len) != ZCBOR_SUCCESS)
			return 81;
		total_len += one_len;
	}

	/* --- Sender: stream entries, switching sections when one fills. --- */
	struct log_file msg;
	memset(&msg, 0, sizeof(msg));
	msg.name.value = (const uint8_t *)"boot.log";
	msg.name.len = 8;

	if (cbor_encode_log_file_frag_begin(states, LOG_FILE_FRAG_N_STATES,
					    sections[0], sec_size, &msg,
					    total_len) != ZCBOR_SUCCESS)
		return 82;

	size_t sec_idx = 0;
	for (size_t i = 0; i < n_entries; i++) {
		int rc = cbor_encode_log_file_frag_item(states, &entries[i]);
		if (rc != ZCBOR_SUCCESS) {
			/* Item did not fit: the state was rolled back to the
			 * item's start. Close this section and retry in a
			 * fresh one. */
			sec_used[sec_idx] =
				(size_t)(states->payload - sections[sec_idx]);
			sec_idx++;
			if (sec_idx >= 4)
				return 83;
			zcbor_update_state(states, sections[sec_idx], sec_size);
			if (cbor_encode_log_file_frag_item(states, &entries[i]) != ZCBOR_SUCCESS)
				return 84;
		}
	}
	if (cbor_encode_log_file_frag_end(states, &sec_used[sec_idx]) != ZCBOR_SUCCESS)
		return 85;

	size_t wire_len = 0;
	for (size_t i = 0; i <= sec_idx; i++) {
		memcpy(&wire[wire_len], sections[i], sec_used[i]);
		wire_len += sec_used[i];
	}

	/* --- Cross-check: one-shot decode sees the same wrapped bytes. --- */
	struct log_file whole;
	size_t dec_len = 0;
	memset(&whole, 0, sizeof(whole));
	if (cbor_decode_log_file(wire, wire_len, &whole, &dec_len) != ZCBOR_SUCCESS)
		return 86;
	if (whole.entries.len != total_len ||
	    memcmp(whole.entries.value, scratch, total_len) != 0)
		return 87;

	/* --- Receiver: 96-byte chunks; stage items that straddle. --- */
	static uint8_t stage[2][2 * chunk_size];
	int stage_sel = 0;
	struct log_file hdr;
	memset(&hdr, 0, sizeof(hdr));
	if (cbor_decode_log_file_frag_begin(states, LOG_FILE_FRAG_N_STATES,
					    wire, chunk_size, &hdr) != ZCBOR_SUCCESS)
		return 90;
	if (hdr.name.len != 8 || memcmp(hdr.name.value, "boot.log", 8) != 0)
		return 91;

	size_t fed = chunk_size;
	size_t idx = 0;
	while (!cbor_decode_log_file_frag_at_end(states)) {
		struct log_entry ent;
		memset(&ent, 0, sizeof(ent));
		if (cbor_decode_log_file_frag_item(states, &ent) != ZCBOR_SUCCESS) {
			/* The item straddles a section boundary: combine the
			 * unconsumed tail with the next chunk in a staging
			 * buffer and retry. */
			size_t avail = (size_t)(states->payload_end - states->payload);
			size_t next = wire_len - fed;

			if (next == 0)
				return 92;
			if (next > chunk_size)
				next = chunk_size;
			uint8_t *buf = stage[stage_sel];
			stage_sel ^= 1;
			memcpy(buf, states->payload, avail);
			memcpy(&buf[avail], &wire[fed], next);
			fed += next;
			zcbor_update_state(states, buf, avail + next);
			continue;
		}
		/* Fragments are zero copy: use the entry before recycling the
		 * buffer it points into. */
		if (ent.seq != idx)
			return 93;
		if (ent.msg.len != 8 || memcmp(ent.msg.value, msgs[idx], 8) != 0)
			return 94;
		idx++;
		if (idx > n_entries)
			return 95;
	}
	if (idx != n_entries)
		return 96;
	if (cbor_decode_log_file_frag_end(states, NULL) != ZCBOR_SUCCESS)
		return 97;
	return 0;
}

/* Unordered map decoding: a sender that emits config keys in a different
 * order than the CDDL (e.g. canonical key sorting) must still decode. */
static int check_unordered_map_decode(void)
{
	uint8_t payload[128];
	zcbor_state_t states[4];

	/* Encode {"port": 8080, "color": 1, "name": "demo"} by hand --
	 * reverse of the CDDL member order. */
	zcbor_new_encode_state(states, 4, payload, sizeof(payload), 1);
	if (!zcbor_map_start_encode(states, 3) ||
	    !zcbor_tstr_put_lit(states, "port") ||
	    !zcbor_uint32_put(states, 8080) ||
	    !zcbor_tstr_put_lit(states, "color") ||
	    !zcbor_uint32_put(states, 1) ||
	    !zcbor_tstr_put_lit(states, "name") ||
	    !zcbor_tstr_put_lit(states, "demo") ||
	    !zcbor_map_end_encode(states, 3))
		return 100;
	size_t wire_len = (size_t)(states->payload - payload);

	struct config out;
	size_t out_len = 0;
	memset(&out, 0, sizeof(out));
	if (cbor_decode_config(payload, wire_len, &out, &out_len) != ZCBOR_SUCCESS)
		return 101;
	if (out.name.len != 4 || memcmp(out.name.value, "demo", 4) != 0)
		return 102;
	if (out.color != colors_green_c || out.port != 8080)
		return 103;
	if (out.description_present || out.extra_count != 0)
		return 104;

	/* Unknown keys are still rejected (strict schema). */
	zcbor_new_encode_state(states, 4, payload, sizeof(payload), 1);
	if (!zcbor_map_start_encode(states, 4) ||
	    !zcbor_tstr_put_lit(states, "name") ||
	    !zcbor_tstr_put_lit(states, "demo") ||
	    !zcbor_tstr_put_lit(states, "color") ||
	    !zcbor_uint32_put(states, 1) ||
	    !zcbor_tstr_put_lit(states, "port") ||
	    !zcbor_uint32_put(states, 1) ||
	    !zcbor_tstr_put_lit(states, "bogus") ||
	    !zcbor_uint32_put(states, 9) ||
	    !zcbor_map_end_encode(states, 4))
		return 105;
	wire_len = (size_t)(states->payload - payload);
	if (cbor_decode_config(payload, wire_len, &out, &out_len) == ZCBOR_SUCCESS)
		return 106;
	return 0;
}

/* bstr .cbor X one-shot: the wrapped reading decodes straight into a typed
 * struct field. */
static int check_typed_cbor_bstr(void)
{
	uint8_t payload[64];
	size_t enc_len = 0;
	size_t dec_len = 0;

	struct envelope env;
	memset(&env, 0, sizeof(env));
	env.kind = 3;
	env.inner.id = 7;
	env.inner.value = 1.5f;
	env.inner.level = 42;

	if (cbor_encode_envelope(payload, sizeof(payload), &env, &enc_len) != ZCBOR_SUCCESS)
		return 110;

	struct envelope out;
	memset(&out, 0, sizeof(out));
	if (cbor_decode_envelope(payload, enc_len, &out, &dec_len) != ZCBOR_SUCCESS)
		return 111;
	if (dec_len != enc_len)
		return 112;
	if (out.kind != 3 || out.inner.id != 7 || out.inner.level != 42)
		return 113;
	if (out.inner.value < 1.4f || out.inner.value > 1.6f)
		return 114;

	/* A truncated wrapped string must be rejected cleanly. */
	if (cbor_decode_envelope(payload, enc_len - 2, &out, &dec_len) == ZCBOR_SUCCESS)
		return 115;
	return 0;
}

/* Union of two map types: the first alternative (config) enters its map and
 * fails partway through on a file_msg payload; the union must roll back
 * cleanly and succeed with the second alternative. Also: trailing garbage
 * after a valid document must be rejected. */
static int check_union_rollback_and_trailing(void)
{
	uint8_t payload[128];
	size_t enc_len = 0;
	size_t dec_len = 0;
	static uint8_t small[4] = { 1, 2, 3, 4 };

	struct file_msg fm;
	memset(&fm, 0, sizeof(fm));
	fm.filename.value = (const uint8_t *)"a.bin";
	fm.filename.len = 5;
	fm.file_size = sizeof(small);
	fm.data.value = small;
	fm.data.len = sizeof(small);
	if (cbor_encode_file_msg(payload, sizeof(payload), &fm, &enc_len) != ZCBOR_SUCCESS)
		return 120;

	struct report rep;
	memset(&rep, 0, sizeof(rep));
	if (cbor_decode_report(payload, enc_len, &rep, &dec_len) != ZCBOR_SUCCESS)
		return 121;
	if (rep.choice != report_file_msg_c)
		return 122;
	if (rep.file_msg.file_size != sizeof(small) ||
	    rep.file_msg.data.len != sizeof(small) ||
	    memcmp(rep.file_msg.data.value, small, sizeof(small)) != 0)
		return 123;

	/* First alternative also still works. */
	struct config cfg;
	memset(&cfg, 0, sizeof(cfg));
	cfg.name.value = (const uint8_t *)"n";
	cfg.name.len = 1;
	cfg.color = colors_red_c;
	cfg.port = 7;
	if (cbor_encode_config(payload, sizeof(payload), &cfg, &enc_len) != ZCBOR_SUCCESS)
		return 124;
	memset(&rep, 0, sizeof(rep));
	if (cbor_decode_report(payload, enc_len, &rep, &dec_len) != ZCBOR_SUCCESS)
		return 125;
	if (rep.choice != report_config_c || rep.config.port != 7)
		return 126;

	/* Trailing garbage after a valid document must be rejected. */
	payload[enc_len] = 0x00;
	if (cbor_decode_config(payload, enc_len + 1, &cfg, &dec_len) != ZCBOR_ERR_PAYLOAD_NOT_CONSUMED)
		return 127;
	return 0;
}

/* Forward compatibility: a map with a "* any => any" extension point must
 * skip unknown keys (simulating fields added by a future schema version),
 * while maps without it keep rejecting unknowns. */
static int check_open_map_forward_compat(void)
{
	uint8_t payload[128];
	zcbor_state_t states[4];

	/* A "future" open-msg: {0: 7, 99: "future", 100: [1, 2]} -- keys 99
	 * and 100 do not exist in the current schema. */
	zcbor_new_encode_state(states, 4, payload, sizeof(payload), 1);
	if (!zcbor_map_start_encode(states, 3) ||
	    !zcbor_uint32_put(states, 0) ||
	    !zcbor_uint32_put(states, 7) ||
	    !zcbor_uint32_put(states, 99) ||
	    !zcbor_tstr_put_lit(states, "future") ||
	    !zcbor_uint32_put(states, 100) ||
	    !zcbor_list_start_encode(states, 2) ||
	    !zcbor_uint32_put(states, 1) ||
	    !zcbor_uint32_put(states, 2) ||
	    !zcbor_list_end_encode(states, 2) ||
	    !zcbor_map_end_encode(states, 3))
		return 130;
	size_t wire_len = (size_t)(states->payload - payload);

	struct open_msg out;
	size_t out_len = 0;
	memset(&out, 0, sizeof(out));
	if (cbor_decode_open_msg(payload, wire_len, &out, &out_len) != ZCBOR_SUCCESS)
		return 131;
	if (out.k0 != 7 || out.k1_present)
		return 132;
	if (out_len != wire_len)
		return 133;

	/* Unknown keys arriving before known ones must also be skipped. */
	zcbor_new_encode_state(states, 4, payload, sizeof(payload), 1);
	if (!zcbor_map_start_encode(states, 3) ||
	    !zcbor_uint32_put(states, 50) ||
	    !zcbor_nil_put(states, NULL) ||
	    !zcbor_uint32_put(states, 1) ||
	    !zcbor_tstr_put_lit(states, "note") ||
	    !zcbor_uint32_put(states, 0) ||
	    !zcbor_uint32_put(states, 9) ||
	    !zcbor_map_end_encode(states, 3))
		return 134;
	wire_len = (size_t)(states->payload - payload);
	memset(&out, 0, sizeof(out));
	if (cbor_decode_open_msg(payload, wire_len, &out, &out_len) != ZCBOR_SUCCESS)
		return 135;
	if (out.k0 != 9 || !out.k1_present || out.k1.len != 4 ||
	    memcmp(out.k1.value, "note", 4) != 0)
		return 136;
	return 0;
}

int main(void)
{
	int rc;

	if ((rc = check_types()) != 0)
		return rc;
	if ((rc = check_config_roundtrip()) != 0)
		return rc;
	if ((rc = check_event_roundtrip()) != 0)
		return rc;
	if ((rc = check_enum_roundtrip()) != 0)
		return rc;
	if ((rc = check_range_validation()) != 0)
		return rc;
	if ((rc = check_fragmented_transfer()) != 0)
		return rc;
	if ((rc = check_cbor_in_cbor_streaming()) != 0)
		return rc;
	if ((rc = check_unordered_map_decode()) != 0)
		return rc;
	if ((rc = check_typed_cbor_bstr()) != 0)
		return rc;
	if ((rc = check_union_rollback_and_trailing()) != 0)
		return rc;
	if ((rc = check_open_map_forward_compat()) != 0)
		return rc;
	return 0;
}
