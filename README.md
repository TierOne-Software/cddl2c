# cbor-cddl-c

Reuse of the [zcbor](zcbor/) C CBOR implementation with a Zig build, Zig unit
tests, fuzz harnesses, and a new CDDL → C11 code generator (`cddl2c`) written
in Zig.

Target profile: **C11, embedded/RTOS, static and deterministic allocation.**
Nothing here calls `malloc`; every buffer, state, and generated type is
caller- or statically allocated.

Requires a recent Zig master (developed against `0.17.0-dev.1606`).

## Layout

```
zcbor/               FORKED zcbor C library, flattened to src/ + include/
                     (+ LICENSE). Forked from github.com/nordicsemi/zcbor at
                     upstream commit c46c01766512 ("zcbor.py: Fix issue where
                     semicolons in string literals were seen as comments"),
                     then modified and extended through static analysis and
                     fuzz testing. No upstream compatibility is maintained.
                     See "zcbor fork changes" below.
build.zig            builds zcbor as a static C11 lib + all tests + cddl2c
src/                 the cddl2c generator (pure Zig)
  Tokenizer.zig      CDDL lexer
  Parser.zig         recursive-descent parser -> ast.zig
  codegen.zig        C11 type generator
  validate.zig       union-disjointness check (runs before codegen)
  main.zig           CLI
tests/
  zcbor_test.zig     Zig unit tests for the C library (RFC 8949 vectors)
  zcbor_fuzz.zig     fuzz harnesses for the decoder
  c/generated_types_test.c   C11 checks of cddl2c output (_Static_assert)
examples/sample.cddl input for the end-to-end test
```

## Commands

```sh
zig build test          # everything: C-lib tests, parser/codegen tests,
                        # fuzz smoke pass, end-to-end C compile+run check
zig build test --fuzz   # continuous coverage-guided fuzzing (see note below)
zig build               # install libzcbor.a and the cddl2c CLI
zig build -Dtarget=aarch64-linux-musl        # cross-compiles cleanly
./zig-out/bin/cddl2c examples/sample.cddl -o sample_types.h -d -e
```

cddl2c usage:

```
cddl2c INPUT.cddl [-o TYPES.h] [-d [DECODE.c]] [-e [ENCODE.c]]
```

`-o` writes the types header (stdout if omitted). `-d` additionally generates
decode functions and `-e` encode functions, each as a `.c` file plus a public
`.h`. Their paths default to siblings of `-o` (`X_types.h` -> `X_decode.c`,
`X_decode.h`, ...), or can be given explicitly after the flag.

`--entry RULE[,RULE...]` generates only the listed rules plus everything
they reference (tree-shaking), and gives only them public wrappers and
fragmented APIs — internal rules stay `static`. Measured on the sample
schema: −32 % generated flash. `--frag RULE[,RULE...]` further restricts
the fragmented-payload API (default: every qualifying entry rule;
`--frag ''` disables it). `--ordered-maps` switches map decoding from
key-search (accepts any wire order) to strict CDDL order (leaner, ~2×
faster on small maps, but rejects reordered senders).

Pure `-Dtarget=thumb-freestanding-eabi` does not build because zcbor uses
libc headers (`string.h`); on real RTOS targets zcbor is compiled with the
toolchain's libc (newlib/picolibc, Zephyr minimal libc), which is how
upstream uses it too.

## zcbor fork changes

The C library diverges from upstream zcbor where upstream patterns are
undefined behavior or hazards; upstream API compatibility is explicitly not
a goal:

- **No function-pointer casts anywhere.** Upstream's `ZCBOR_CAST_FP` macro
  and `zcbor_cast_error` are removed, and the internal
  `zcbor_search_key_(t|b)str_*` helpers now call through static wrappers
  with the exact `zcbor_decoder_t` signature instead of casting
  `zcbor_tstr_expect`. Calling a function through a mismatched pointer type
  is undefined behavior (C11 6.3.2.3); the whole library and all generated
  code run clean under `-fsanitize=function`.
- **`zcbor_search_key_uint` / `zcbor_search_key_int`** added: typed
  unordered-map key searches for integer keys (upstream only has string
  variants).
- **The `payload`/`payload_mut` union in `zcbor_state_t` is gone** — the
  field is a single `const uint8_t *payload`, and the few encode-side write
  sites cast constness away (well-defined; the underlying buffer is
  writable). This also gives bindings a clean field name instead of the
  anonymous-union placeholder translate-c generated.
- **Exhausted-map searches fail in O(1).** `zcbor_unordered_map_search`
  keeps a processed-element count (in both search modes) and returns
  `ZCBOR_ERR_ELEM_NOT_FOUND` immediately once every element has been
  consumed, instead of re-scanning the whole map. This is the dominant cost
  of search-based decoding (the terminating search of repeated members and
  absent-optional lookups): measured 569 -> 254 ns on the 5-member `config`
  decode, for ~60 B of flash.
- **`zcbor_multi_decode_w_backup` rollback fixed**: a failed element
  attempt that left inner state backups behind (e.g. aborting inside a
  nested container) used to make the restore act on the wrong backup; the
  fork drops orphaned backups before restoring, and generated repeated
  array members use the `_w_backup` variant.
- **`strnlen` is renamed `zcbor_strnlen`.** Upstream declares and defines
  the reserved libc identifier globally (a collision hazard with static
  libcs, and formally UB per C11 7.31.13); the fork owns its symbol.

## zcbor build configuration

The C library is built with `-std=c11 -Wall -Wextra -Werror -Wvla` and:

- **`ZCBOR_CANONICAL`**: encoding always produces definite-length,
  minimal-size headers (deterministic bytes, the usual choice for
  embedded/COSE), and decoding defaults to strict canonical checking. Tests
  show how to opt out per decode state at runtime
  (`state->constant_state->enforce_canonical = false`).
- **`ZCBOR_FRAGMENTS`**: multi-part payload support (`zcbor_update_state`
  plus the string-fragment APIs), for payloads larger than any single buffer
  — log files, firmware images, SREC dumps. This changes
  `sizeof(zcbor_state_t)`, so the define is applied uniformly to the
  library, the translate-c module, and all generated/test C.

## Tests

- `tests/zcbor_test.zig` drives the C API through translate-c: RFC 8949
  Appendix A wire-format vectors (ints, strings, floats, containers),
  roundtrips, zero-copy string decoding, error codes, canonical enforcement,
  indefinite-length handling, `any_skip`, and union backup/restore.
- `tests/zcbor_fragments_test.zig` covers the multi-part payload machinery:
  decoding across sections with `zcbor_update_state`, reassembling a
  1500-byte "file" delivered in 128-byte chunks via the fragment APIs,
  streaming a fragmented encode into MTU-sized output buffers,
  CBOR-in-CBOR (`zcbor_cbor_bstr_fragments_start_*`) decode/encode across
  sections, and `zcbor_validate_string_fragments`/
  `zcbor_splice_string_fragments`.
- `tests/zcbor_fuzz.zig` has four harnesses:
  1. arbitrary bytes → `zcbor_any_skip` loop (lenient mode),
  2. the same with canonical enforcement,
  3. differential roundtrip: a random valid encode sequence must decode back
     to identical values,
  4. fragmented reassembly: a bstr encoded whole, then fragment-decoded
     across fuzz-chosen chunk boundaries, must rebuild the exact content.

The full suite passes in **Debug, ReleaseSafe, ReleaseFast, and
ReleaseSmall**. The ReleaseSafe run matters: it keeps UBSan trap
instrumentation on the C code under full optimization, and it caught the
function-pointer-cast undefined behavior that zcbor's architecture
traditionally relies on — fixed structurally in the generated code and in
the forked library (see "zcbor fork changes").

The tool itself is hardened and fuzzed too:

- The parser bounds its recursion (hostile `((((...` input is rejected, not
  a stack overflow) and is fuzzed with arbitrary text; the code generator
  bounds rule-reference chains, validates `.size` ranges, saturates
  occurrence arithmetic, and is fuzzed with "any document that parses must
  generate or error cleanly, never crash".
- `tests/generated_fuzz.zig` fuzzes the **generated C** (compiled into a
  Zig test module via translate-c):
  1. arbitrary bytes into every generated one-shot decoder — must reject or
     accept cleanly, never crash;
  2. random valid `config` structs must roundtrip bit-exactly through the
     generated encoder/decoder pair;
  3. the fragmented `file_msg` encoder driven across fuzz-chosen section
     sizes must produce byte-identical output to the one-shot encoder, and
     the fragmented decoder must rebuild the content from fuzz-chosen
     chunks;
  4. CBOR-in-CBOR log streaming with fuzz-chosen section/chunk boundaries,
     exercising the item retry (encode) and staging-buffer (decode)
     rollback paths.

  Under plain `zig build test` they run once over the seed corpus. With
  `zig build test --fuzz` they fuzz continuously. **Note:** on
  `0.17.0-dev.1606` the new `std.testing.Smith` fuzzer runtime itself panics
  ("start index 1 is larger than end index 0") shortly after starting — this
  reproduces with a trivial std-only fuzz test, i.e. an upstream Zig bug, not
  a harness problem. The harnesses are written against the current API and
  will work as-is once master fixes the runtime.

## cddl2c: CDDL → C11 types and codecs

`cddl2c` parses a useful subset of RFC 8610 and generates C type definitions
plus, with `-d`/`-e`, matching decode/encode functions built on the zcbor C
library. Naming follows zcbor's conventions (`_c` enum members, `_choice`,
`_present`, `_count`, `decode_repeated_*` helpers, `cbor_decode_X`/
`cbor_encode_X` entry functions).

| CDDL | C |
|---|---|
| `colors = &( red: 0, green: 1 )` | `enum colors { colors_red_c = 0, colors_green_c = 1 }` |
| `colors = &colors-group` | same, from the referenced group rule |
| `err = e-ok / e-crc` (named int literals) | `enum err { err_e_ok_c = 0, ... }` with the literal values |
| `mode = "slow" / "fast"` | positional `enum mode` |
| `cfg = { name: tstr, ? d: tstr }` | `struct cfg` with `d` + `bool d_present` |
| `r = [ x: int, y: int ]` | `struct r` with fields in order |
| `0*4 extra: uint` | `uint32_t extra[4]; size_t extra_count;` |
| `* items: uint` (unbounded) | capped at `default_max_qty` (3), commented |
| `ev = reading / cfg` | `struct ev` = anonymous `union` + `enum ev_choice choice` |
| `port = uint .size 2`, `pct = 0..100` | `typedef uint16_t port_t;`, `typedef uint8_t pct_t;` (width narrowing) |
| `tstr` / `bstr` | `struct zcbor_string` (zero copy into payload) |
| `bstr .cbor X` | typed member (`struct X` etc.) decoded/encoded through the wrapping byte string one-shot; also gets the CBOR-in-CBOR fragmented API |
| `bstr .cborseq [* T]` | `struct zcbor_string` (zero copy); streamed item-by-item via the CBOR-in-CBOR fragmented API |
| `v = 1` (literal rule) | constant; members referencing it need no storage |
| `* any => any` in a map | extension point: decode skips unknown keys (forward compatibility); no storage, nothing encoded |
| `#6.n(T)` | represented as `T` (tag validated at xcode time) |

Recursive types are rejected (cannot be statically allocated). Generics,
`.bits`, sockets/plugs (`$`/`$$` extension points) are parsed structurally at
best but not given semantics. Type choices inside `&()` beyond literals are
unsupported.

### Generated decode/encode functions

The generated codecs mirror zcbor.py's architecture:

- Every rule with a C artifact gets a static `decode_X`/`encode_X` function
  (`bool f(zcbor_state_t *state, T *result)`), plus a public entry wrapper
  `cbor_decode_X`/`cbor_encode_X` built on `zcbor_entry_function` with an
  exactly-sized, stack-allocated `zcbor_state_t` array (backup count is
  computed from the type's nesting depth).
- **Maps decode in any wire order** (the CBOR/CDDL semantics): each member
  is found via `zcbor_search_key_*` and marked processed, so
  key-reordering and canonically key-sorted senders both work.
  `--ordered-maps` opts into the leaner strict-order decode
  (`zcbor_tstr_expect_ptr` per key). Encoding always emits CDDL order.
- **Maps are closed by default** (unknown keys rejected). Declare a map
  extensible with a trailing `* any => any` entry and its decoder skips
  unknown keys instead (`zcbor_map_end_decode_skip_unknown` in the fork) —
  future schema versions can add fields without breaking deployed
  decoders. The extension point generates no storage and encodes nothing.
  In `--ordered-maps` mode only trailing unknowns can be skipped
  (positional decode).
- **No function-pointer casts**: every generated function that travels
  through a `zcbor_decoder_t`/`zcbor_encoder_t` has that exact signature
  (`void *` parameter, typed local view inside). Calling through a
  mismatched function-pointer type is undefined behavior (C11 6.3.2.3) —
  found by `-fsanitize=function` in a ReleaseSafe run and fixed
  structurally, in both the generated code and the forked library.
- `?` members in maps search for their key and set `_present`; in arrays
  they use an inline attempt-with-rollback block. Encode is a plain
  `if (input->x_present)`.
- Bounded/unbounded repetitions use `zcbor_multi_decode` /
  `zcbor_multi_encode_minmax` over the fixed-size array.
- Unions try each alternative under `zcbor_union_start_code`/backup-restore
  and set `choice`; encode switches on `choice`. Between alternatives the
  generated code drops any state backups a failed alternative left behind
  (e.g. from a container it entered before failing) so the rollback always
  acts on the union's own snapshot — without this, a union of two map
  types misdecodes when the first alternative fails mid-map.
- **Decode entry wrappers reject trailing data**: a valid document followed
  by extra bytes fails with `ZCBOR_ERR_PAYLOAD_NOT_CONSUMED` (upstream's
  `zcbor_entry_function` silently ignores trailing bytes). `payload_len_out`
  still reports the consumed length.
- **Generation-time validation** rejects constructs that would produce
  broken C or wire data: enum values outside C `int` range, CBOR tags above
  `UINT32_MAX` (the zcbor tag API limit), empty integer ranges (`5..2`),
  keyless map members (odd element counts), and duplicate rule definitions.
- **Ambiguous unions are rejected before codegen** (`src/validate.zig`).
  Union decode tries arms in declaration order and the first match wins, so
  two arms that can match the same bytes make the later one silently
  unreachable. Every type-level `/` union (rule-level and member-level) is
  checked: arms must be provably disjoint by outer major type, concrete
  literal value sets (enums, `'F'`-style byte literals, text literals),
  integer/size ranges, tag numbers, fixed array lengths, or — for maps — a
  shared required key with disjoint value types, or a required key the other
  (closed) arm does not declare. A final `any` arm is allowed as a catch-all;
  `any` anywhere else swallows the later arms and is rejected. Group-level
  `//` choices are not analyzed (limitation).
- Enums validate membership on both directions (unknown values fail with
  `ZCBOR_ERR_WRONG_VALUE`/`ZCBOR_ERR_BAD_ARG`); tstr enums compare/emit the
  strings.
- Constants (`version = 1`, literal members) are `expect`ed on decode and
  `put` on encode; ranges and `.size` bounds are validated in both
  directions.

### Fragmented payloads (large file transfer)

A payload larger than any single buffer — a log file, a firmware image, an
SREC dump — cannot be decoded from one contiguous `payload[]`. zcbor's
answer (enabled here via `ZCBOR_FRAGMENTS`) is *payload sections*: the state
walks one buffer at a time, and `zcbor_update_state(states, buf, len)`
switches it to the next section when the current one is exhausted
(`zcbor_payload_at_end(states)`).

cddl2c generates two flavors of fragmented API, chosen by the CDDL type of
the final member:

| CDDL shape of last member | Generated API | Use when |
|---|---|---|
| `data: bstr` (or `tstr`) | `*_frag_begin` / `_frag_next` (dec) / `_frag_feed` (enc) / `_frag_end` | the blob is opaque bytes: firmware image, raw file |
| `entries: bstr .cborseq [* rec]` (or `.cbor T`) | `*_frag_begin` / `_frag_item` / `_frag_at_end` (dec) / `_frag_end` | the blob is structured CBOR records: logs, SREC lines, telemetry batches |

Both are generated only for map/array rules whose **members all occur
exactly once** and whose **last member** has the shape above. The
all-occur-once requirement keeps the container's element count exact, which
is what makes fragmented *encoding* safe under `ZCBOR_CANONICAL`: zcbor
skips the end-of-container header rewrite entirely when the size hint
matches, so an already-transmitted first section is never touched again.

#### What FRAG_N_STATES means

Every zcbor operation runs on an *array* of `zcbor_state_t`, not a single
struct:

```
states[0]        the working state (payload position, element count)
states[1..N-2]   backup slots: a snapshot is pushed when zcbor may need to
                 roll back -- one per open container (canonical encode),
                 union attempt, optional/repeated element, ...
states[N-1]      the "constant state": error code, settings, backup list
```

Too few backup slots fails at runtime with `ZCBOR_ERR_NO_BACKUP_MEM`. The
one-shot `cbor_decode_X`/`cbor_encode_X` wrappers size this array internally
from the type's nesting depth. The fragmented API cannot: the state must
survive *between* your calls, so **you** allocate the array — and the
generated `<TYPE>_FRAG_N_STATES` macro is the exact size it needs:

- plain fragmented: nesting depth of the type + 2 (working + constant);
- CBOR-in-CBOR: additionally +1 for the backup held while the wrapped
  string is open, +1 for the transient backup around each `_frag_item`
  call (that is what makes items atomically retryable), + the item type's
  own nesting depth.

```c
zcbor_state_t states[FILE_MSG_FRAG_N_STATES]; /* keep alive across calls */
```

#### Opaque blob: `file-msg = { filename: tstr, file-size: uint, data: bstr }`

Receiver — header fields arrive in the first chunk, the blob streams out as
`zcbor_string_fragment`s (zero copy: each fragment points into the chunk you
fed, so consume it before reusing that buffer):

```c
zcbor_state_t states[FILE_MSG_FRAG_N_STATES];
struct file_msg hdr;

/* The first section must contain everything up to and including the
 * 'data' string header (here: filename, file-size, ~a dozen bytes). */
int err = cbor_decode_file_msg_frag_begin(states, FILE_MSG_FRAG_N_STATES,
                                          chunk, chunk_len, &hdr);
if (err != ZCBOR_SUCCESS)
    return err;
open_flash_slot(hdr.filename, hdr.file_size);

size_t got = 0;
while (got < hdr.file_size) {
    if (zcbor_payload_at_end(states)) {           /* section used up? */
        chunk_len = receive_next(chunk);          /* your transport */
        zcbor_update_state(states, chunk, chunk_len);
    }
    struct zcbor_string_fragment frag;
    err = cbor_decode_file_msg_frag_next(states, &frag);
    if (err != ZCBOR_SUCCESS)
        return err;
    write_flash(frag.offset, frag.fragment.value, frag.fragment.len);
    got += frag.fragment.len;                     /* frag.total_len = whole size */
}
return cbor_decode_file_msg_frag_end(states, NULL);
```

Sender — the total blob length must be known up front (the CBOR string
header contains it). `_frag_feed` writes as much as fits and reports it in
`enc_len`; when the section is full, transmit it and switch buffers:

```c
zcbor_state_t states[FILE_MSG_FRAG_N_STATES];

err = cbor_encode_file_msg_frag_begin(states, FILE_MSG_FRAG_N_STATES,
                                      txbuf, sizeof(txbuf), &msg,
                                      file_size /* = data_total_len */);
size_t sent = 0;
while (sent < file_size) {
    size_t n = read_file(filebuf, sizeof(filebuf));  /* e.g. SREC reads */
    size_t off = 0;
    while (off < n) {
        size_t enc_len = 0;
        err = cbor_encode_file_msg_frag_feed(states, &filebuf[off], n - off, &enc_len);
        if (err != ZCBOR_SUCCESS)
            return err;
        off += enc_len;
        sent += enc_len;
        if (off < n) {                       /* txbuf full: ship it */
            transmit(txbuf, sizeof(txbuf));
            zcbor_update_state(states, txbuf, sizeof(txbuf));
        }
    }
}
size_t last_len = 0;
err = cbor_encode_file_msg_frag_end(states, &last_len);
transmit(txbuf, last_len);                   /* final, partial section */
```

#### Structured records: `log-file = { name: tstr, entries: bstr .cborseq [* log-entry] }`

`bstr .cbor X` wraps one CBOR item, `bstr .cborseq [* T]` wraps a sequence
of `T` items — the natural encoding for record streams. The generated API
decodes/encodes **one typed item at a time** (here `struct log_entry`)
instead of handing you raw bytes.

The key property: `_frag_item` is *atomic*. It snapshots the state, and if
the item runs out of payload mid-way it rolls everything back and returns
`ZCBOR_ERR_NO_PAYLOAD` — the state is left exactly at the item's start, so
the same item can be retried after more payload arrives.

Sender — retry an item that did not fit in the current section:

```c
err = cbor_encode_log_file_frag_begin(states, LOG_FILE_FRAG_N_STATES,
                                      txbuf, sizeof(txbuf), &msg,
                                      entries_total_len);
for (size_t i = 0; i < n_entries; i++) {
    err = cbor_encode_log_file_frag_item(states, &entries[i]);
    if (err != ZCBOR_SUCCESS) {                       /* section full */
        size_t used = (size_t)(states->payload - txbuf);
        transmit(txbuf, used);
        zcbor_update_state(states, txbuf, sizeof(txbuf));
        err = cbor_encode_log_file_frag_item(states, &entries[i]); /* retry */
        if (err != ZCBOR_SUCCESS)
            return err;                               /* item > section */
    }
}
err = cbor_encode_log_file_frag_end(states, &last_len);
transmit(txbuf, last_len);
```

(`entries_total_len` is the encoded size of all wrapped items. A sender
that stores records pre-encoded knows it; otherwise encode once to a
scratch buffer to measure, as the end-to-end test does.)

Receiver — one subtlety: `zcbor_update_state` *abandons* the unconsumed
tail of the current section, so an item that straddles a chunk boundary
must be re-fed. Copy the tail plus the next chunk into a staging buffer and
retry (two alternating staging buffers, since the decoded strings point
into the buffer being read):

```c
uint8_t stage[2][2 * CHUNK];
int sb = 0;

err = cbor_decode_log_file_frag_begin(states, LOG_FILE_FRAG_N_STATES,
                                      chunk, chunk_len, &hdr);
while (!cbor_decode_log_file_frag_at_end(states)) {
    struct log_entry ent;
    err = cbor_decode_log_file_frag_item(states, &ent);
    if (err != ZCBOR_SUCCESS) {
        /* Item straddles the boundary: tail + next chunk -> staging. */
        size_t tail = (size_t)(states->payload_end - states->payload);
        uint8_t *buf = stage[sb];
        sb ^= 1;
        memcpy(buf, states->payload, tail);
        size_t next = receive_next(&buf[tail]);      /* your transport */
        zcbor_update_state(states, buf, tail + next);
        continue;                                    /* retry the item */
    }
    handle_entry(&ent);   /* zero copy: use before recycling the buffer */
}
return cbor_decode_log_file_frag_end(states, NULL);
```

The end-to-end C test (`tests/c/generated_types_test.c`) runs both flavors
for real: a 1000-byte file through 512-byte sections and back through
128-byte chunks, and 24 log entries streamed out with item retry and back
in with the staging pattern. `tests/zcbor_fragments_test.zig` shows the
same flows against the raw zcbor API.

Codec-specific limitations: `~` (unwrap), `#6` without a tag number, and
non-literal member keys (`tstr => x`) are rejected when `-d`/`-e` is given;
group rules referenced from map context need inlining. Group-choice maps
(`{ a // b }`) and the fragmented begin functions decode in strict CDDL
order even in unordered mode (union backtracking and partial payloads
don't compose with key searching).

The end-to-end test generates `sample_types.h`, `sample_decode.c/.h`, and
`sample_encode.c/.h` from `examples/sample.cddl` at build time, compiles them
with `-std=c11 -Wall -Wextra -Werror`, and runs
`tests/c/generated_types_test.c`: `_Static_assert`s on the type shapes plus
runtime encode→decode roundtrips (map with optional/repeated members, union
dispatch, enum validation, range rejection). `zig build test` covers all of
it.

## Benchmarks & footprint

`zig build bench` runs throughput benchmarks of the generated codecs at
ReleaseFast (fixtures validated before timing, iteration counts
auto-calibrated, best-of-5 sampling to suppress scheduler/frequency noise —
repeat runs agree within ~1 %). `zig build bench-lto` is the same suite
with full LTO across the Zig driver, generated C, and zcbor.
`bench/size.sh [target]` reports flash footprint at `-Os` (default target:
ARM Thumb-2 as a Cortex-M stand-in).

Representative results (x86-64 desktop, ReleaseFast; relative numbers are
what matter):

| benchmark | ns/op | throughput |
|---|---|---|
| encode `config` (~56 B map) | 278 | 3.6 M ops/s |
| decode `config` (unordered, default) | 254 | 3.9 M ops/s |
| decode `config` (`--ordered-maps`) | 237 | 4.2 M ops/s |
| decode `config`, hand-fused ordered baseline | 175 | 5.7 M ops/s |
| decode `reading` (9 B array) | 69 | 14.5 M ops/s |
| decode `event` union (1st / 3rd choice) | 92 / 76 | 11 / 13 M ops/s |
| decode `file_msg` 64 KiB blob (zero copy) | 169 | O(header) — payload untouched |
| encode `file_msg` 64 KiB blob | 1 560 | ~42 GB/s (memcpy-bound) |
| fragmented decode, 64 KiB in 1 KiB chunks | 2 479 | ~26 GB/s incl. reassembly memcpy |
| fragmented encode, 64 KiB in 1 KiB sections | 2 348 | ~28 GB/s |
| 100 log items via `_frag_item` | 95 ns/item | 10.5 M items/s |
| 100 log items, contiguous baseline | 70 ns/item | 14.2 M items/s |

Flash footprint (`thumb-linux-musleabihf`, `-Os`, whole 9-rule sample schema
including three fragmented APIs): generated decode **2.27 KiB**, generated
encode **2.15 KiB**; zcbor library ~10.5 KiB (+1.4 KiB optional
`zcbor_print`). Public entry wrappers are 44 B each; simple struct decoders
run 46–184 B. Build with `-ffunction-sections -Wl,--gc-sections` so unused
functions cost nothing.

What the numbers say:

- **Unordered map decoding now costs only ~7 % over strict order** (254 vs
  237 ns) after the fork's O(1) exhausted-map search exit — it used to be
  2.4× (569 ns) because the terminating search of repeated members
  re-scanned the whole map. In-order wire hits the searches' first-try
  fast path; heavily out-of-order wire still pays O(n²) element skipping.
  **`ZCBOR_MAP_SMART_SEARCH` was evaluated and deliberately not enabled**:
  its per-element flags only skip redundant key-decoder *attempts* — the
  scan's `zcbor_any_skip` cost and the terminal-search problem remain — so
  for this generator's search pattern it adds state size, flag buffers,
  and backup-copy machinery for no measurable gain. The build
  intentionally leaves it undefined (defining it would also require flag
  storage the generated entry wrappers don't allocate).
- **Blob paths are memory-bound already.** One-shot blob decode is zero
  copy (O(header)); fragmentation adds ~14 ns per 1 KiB section switch —
  noise compared to any real transport.
- **Optional members decode inline** (a try-with-rollback block instead of
  a `zcbor_present_decode` function-pointer call into a helper): ~5 % on
  `config` decode plus a small flash saving per optional member.
- **Pure scalar aliases inline at call sites** (`port = uint .size 2`
  members call `zcbor_uint16_decode` directly); validated aliases keep one
  shared function for their range checks. With `--entry`, trivial alias
  functions disappear entirely.
- **LTO recovers most of the remaining layering cost** (measured with
  `zig build bench-lto`): fragmented 64 KiB decode 2 406 → 1 879 ns
  (~35 GB/s), `_frag_item` streaming 102 → 71 ns/item (near parity with
  the contiguous baseline), `config` encode −21 %. For embedded targets,
  compile the generated C and zcbor with `-flto` when the toolchain
  allows.
- **What's left vs hand-fused zcbor** (~50 ns on a small map decode) is
  `zcbor_entry_function` bookkeeping and per-rule call layers — visible
  only on sub-100-byte messages at >4 M ops/s, irrelevant at embedded link
  rates.
- **`--entry` tree-shaking**: generating the sample schema with
  `--entry config,event,file-msg,log-file` cuts the generated flash by
  32 % (4 518 → 3 078 B) and the public decode API from 19 functions to
  10 — internal rules become `static` and unreachable rules vanish.
- **Union try-chains are cheap** — a wrong alternative fails on the first
  type check, so even hitting the 3rd choice beats the 1st-choice case on
  ns/op (smaller payload).
- The size report caught the fragmented API being generated for an
  11-byte record type it can't help (`log-entry`) — hence `--frag`/
  `--entry` to control the public surface where `--gc-sections` isn't in
  play.

## Next steps

- CI runs of the test suite under all four optimize modes, with benchmark
  regression tracking.
- If a schema with many keys and heavily out-of-order senders ever needs
  it: search-position memoization (remember where unprocessed elements
  start) would beat `ZCBOR_MAP_SMART_SEARCH`'s flags, which don't avoid
  the element-skipping cost.
