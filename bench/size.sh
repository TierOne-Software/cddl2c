#!/bin/sh
# Flash-footprint report for the zcbor library + the code cddl2c generates
# from examples/sample.cddl, compiled at -Os.
#
# Usage: bench/size.sh [target-triple]
# Default target is thumb-linux-musleabihf (ARM Thumb-2, a stand-in for
# Cortex-M flash sizes); try aarch64-linux-musl or x86_64-linux-musl too.
set -e
cd "$(dirname "$0")/.."

TARGET="${1:-thumb-linux-musleabihf}"
OUT=zig-out/size
mkdir -p "$OUT"

zig build >/dev/null
./zig-out/bin/cddl2c examples/sample.cddl -o "$OUT/sample_types.h" -d -e

FLAGS="-Os -target $TARGET -std=c11 -Izcbor/include -I$OUT \
    -DZCBOR_CANONICAL -DZCBOR_FRAGMENTS -ffunction-sections"

for f in zcbor/src/*.c "$OUT"/sample_decode.c "$OUT"/sample_encode.c; do
    zig cc $FLAGS -c "$f" -o "$OUT/$(basename "$f" .c).o"
done

echo "== section sizes ($TARGET, -Os) =="
size "$OUT"/*.o

echo ""
echo "== largest functions (generated code) =="
nm --size-sort --radix=d "$OUT"/sample_decode.o "$OUT"/sample_encode.o 2>/dev/null |
    grep -i " t " | grep -v '\$[td]' | tail -20
