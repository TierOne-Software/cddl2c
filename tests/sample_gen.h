/* Aggregate header handed to translate-c so Zig fuzz harnesses and
 * benchmarks can call the code cddl2c generates from examples/sample.cddl,
 * plus the underlying zcbor API. */
#include "zcbor_decode.h"
#include "zcbor_encode.h"
#include "sample_types.h"
#include "sample_decode.h"
#include "sample_encode.h"
