#!/usr/bin/env bash
set -eo pipefail

CC_CMD="clang"
if ! command -v $CC_CMD &>/dev/null; then
    CC_CMD="gcc"
fi

echo "=========================================================="
echo "RUNNING HIGH-ASSURANCE PRE-FLIGHT VERIFICATION GATES"
echo "=========================================================="

echo "[BUILD] Building release library targets..."
cargo build --release --lib --no-default-features

LIB_EXT="so"
if [[ "$OSTYPE" == "darwin"* ]]; then
    LIB_EXT="dylib"
    $CC_CMD -shared -Wl,-force_load,target/release/libnona_core.a -o target/release/libnona_core.dylib
else
    $CC_CMD -shared -Wl,--whole-archive target/release/libnona_core.a -Wl,--no-whole-archive -o target/release/libnona_core.so
fi
LIB_PATH="target/release/libnona_core.${LIB_EXT}"

echo "--> Executing Gate 3: Header Enum Bijectivity..."
$CC_CMD -Wall -Werror -Iinclude -c tests/c_abi/test_enum_bijectivity.c -o /dev/null
echo "  ✓ Gate 3 passed: Status codes are bijective and collision-free."

echo "--> Executing Gate 1: Dynamic Linkage & FFI Calling Conventions..."
$CC_CMD -Wall -Werror -Iinclude tests/c_abi/test_dynamic_linkage.c -ldl -o /tmp/gate1_runner
/tmp/gate1_runner "$LIB_PATH"

echo "--> Executing Gate 4: Memory Remanence Post-Purge Canary..."
$CC_CMD -Wall -Werror -Iinclude tests/c_abi/test_memory_remanence.c -o /tmp/gate4_runner
/tmp/gate4_runner

echo "--> Executing Gate 2: Sub-4 KiB Stack Frame Ceiling..."
./tools/check_stack_sizes.sh

echo "--> Executing Gate 5: Boundary & Degenerate Timing Invariance..."
cargo test --test test_timing_boundaries --features std --release -- --nocapture

echo "=========================================================="
echo "ALL MECHANICAL GATES PASSED: SYSTEM CERTIFIED COMPLIANT"
echo "=========================================================="
