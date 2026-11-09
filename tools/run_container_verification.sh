#!/usr/bin/env bash
# Copyright (c) 2026 Nona Contributors.
# Licensed under the Apache License, Version 2.0 or the MIT License.

# ============================================================================
# PROJECT: Nona Core Engine
# SCRIPT: run_container_verification.sh - HACVS-V2 Container Verification Suite
# GATE: 3.1 Linux Container Dynamic ASan/UBSan Verification
# ============================================================================

set -euo pipefail

NONA_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$NONA_ROOT"

# 1. Detect Host Architecture and Select Pinned Image
HOST_RAW="$(uname -m)"
case "$HOST_RAW" in
    arm64|aarch64)
        PLATFORM="linux/arm64"
        MUSL_IMAGE="docker.io/clux/muslrust@sha256:0e24d3040bc42ade7eebb53832e4d88d74dc4a0f015ba744c3a41c26a8e1e8d9"
        ;;
    x86_64|amd64)
        PLATFORM="linux/amd64"
        MUSL_IMAGE="docker.io/clux/muslrust@sha256:500d50571f9f83d467481cbaf58cab6d711700047d0e69b73a1caadc23358abd"
        ;;
    *)
        echo "[ERROR] Unsupported host architecture: $HOST_RAW" >&2
        exit 1
        ;;
esac

# 2. Resolve Podman Binary
PODMAN_BIN="${PODMAN_BIN:-podman}"
if ! command -v "$PODMAN_BIN" &>/dev/null; then
    echo "[ERROR] Podman binary not found in PATH" >&2
    exit 1
fi

if ! "$PODMAN_BIN" info >/dev/null 2>&1; then
    echo "[ERROR] Container engine ($PODMAN_BIN) is unreachable or not running." >&2
    exit 1
fi

# 3. Resolve Cargo Cache Volume
CARGO_MOUNT=()
NONA_RUNTIME_DIR="${NONA_RUNTIME_DIR:-${NONA_ROOT}/.runtime}"
if [ ! -d "$NONA_RUNTIME_DIR" ] && [ -d "${NONA_ROOT}/../.runtime" ]; then
    NONA_RUNTIME_DIR="$(cd "${NONA_ROOT}/../.runtime" 2>/dev/null && pwd)"
fi
if [ -d "${NONA_RUNTIME_DIR}/.cargo" ]; then
    CARGO_MOUNT=(-v "${NONA_RUNTIME_DIR}/.cargo":/cargo:ro -e CARGO_HOME=/cargo)
fi

echo "===================================================================="
echo "NONA CORE ENGINE: HACVS-V2 14-LAYER CONTAINER VERIFICATION (ASan+UBSan)"
echo "Host Architecture: $HOST_RAW | Target Platform: $PLATFORM"
echo "Container Digest:  $MUSL_IMAGE"
echo "===================================================================="

# 4. Execute 14-Layer HACVS-V2 Pipeline
"$PODMAN_BIN" run --rm --net=none --platform "$PLATFORM" \
  -v "${NONA_ROOT}":/volume \
  ${CARGO_MOUNT:+"${CARGO_MOUNT[@]}"} \
  -e CARGO_NET_OFFLINE=true \
  -e RUSTUP_TOOLCHAIN=nightly \
  -w /volume \
  "$MUSL_IMAGE" \
  bash -c '
    set -e
    echo "--- 1. HERMETIC MUSL RELEASE BUILD (WITH HOST-DEFENSE) ---"
    cargo build --release --frozen --offline --no-default-features --features host-defense

    TARGET_DIR=$(find target/ -type d -name "release" | grep -i "musl" | head -n 1)
    if [ -z "$TARGET_DIR" ]; then TARGET_DIR="target/release"; fi
    TARGET_LIB="$TARGET_DIR/libnona_core.a"

    # Dynamically extract and alias toolchain-mangled unwinding personality symbol
    EH_SYM=$(nm "$TARGET_LIB" | grep " U " | grep "personality" | awk "{print \$2}" | head -n 1 || true)
    DEFSYM_FLAG=""
    if [ -n "$EH_SYM" ]; then
        DEFSYM_FLAG="-Wl,--defsym=${EH_SYM}=rust_eh_personality"
    fi

    LDFLAGS="-lpthread -ldl $DEFSYM_FLAG"
    INC_FLAGS="-Iinclude -Itests/integration"
    SAN_FLAGS="-fsanitize=address,undefined"

    echo "--- 2. ZERO-HEAP SYMBOL AUDIT ---"
    if nm "$TARGET_LIB" | grep -iE "(malloc|free|realloc|__rust_alloc)"; then
      echo "[!] HEAP SYMBOLS DETECTED" && exit 1
    else
      echo "[+] ZERO HEAP SYMBOLS CONFIRMED IN RELEASE ARTIFACTS"
    fi

    echo "--- 3. C-ABI CONTRACT PERMUTATIONS (ASan + UBSan) ---"
    gcc -std=c99 $SAN_FLAGS $INC_FLAGS tests/integration/c_runner.c -L"$TARGET_DIR" -lnona_core $LDFLAGS -o /tmp/c_runner
    /tmp/c_runner

    if [ -f "tests/integration/kat_runner.c" ]; then
      echo "--- 4. CRYPTOGRAPHIC KNOWN-ANSWER TESTS (ASan + UBSan) ---"
      gcc -std=c99 $SAN_FLAGS $INC_FLAGS tests/integration/kat_runner.c -L"$TARGET_DIR" -lnona_core $LDFLAGS -o /tmp/kat_runner
      /tmp/kat_runner
    fi

    echo "--- 5. ADVERSARIAL FUZZING (100k Cycles + ASan + UBSan) ---"
    gcc -std=c99 $SAN_FLAGS $INC_FLAGS tests/integration/fuzz_runner.c -L"$TARGET_DIR" -lnona_core $LDFLAGS -o /tmp/fuzz_runner
    /tmp/fuzz_runner

    echo "--- 6. ASYNC SIGNAL INTERCEPT & DECONTAMINATION (ASan + UBSan) ---"
    gcc -std=c99 $SAN_FLAGS $INC_FLAGS tests/integration/signal_runner.c -L"$TARGET_DIR" -lnona_core $LDFLAGS -o /tmp/signal_runner
    /tmp/signal_runner

    echo "--- 7. EMPIRICAL TIMING NEUTRALITY (dudect + ASan + UBSan) ---"
    gcc -std=c99 -O2 $SAN_FLAGS $INC_FLAGS tests/integration/timing_runner.c -L"$TARGET_DIR" -lnona_core $LDFLAGS -lm -o /tmp/timing_runner
    /tmp/timing_runner

    echo "--- 8. MEMORY REMANENCE (H(R)=0 + ASan + UBSan) ---"
    gcc -std=c99 $SAN_FLAGS $INC_FLAGS tests/integration/remanence_runner.c -L"$TARGET_DIR" -lnona_core $LDFLAGS -o /tmp/remanence_runner
    /tmp/remanence_runner

    echo "--- 9. MULTI-THREADED CONCURRENCY (8 THREADS + ASan + UBSan) ---"
    gcc -std=c99 $SAN_FLAGS $INC_FLAGS tests/integration/concurrency_runner.c -L"$TARGET_DIR" -lnona_core $LDFLAGS -o /tmp/concurrency_runner
    /tmp/concurrency_runner

    echo "--- 10. DATABASE C-UDF LINKAGE & STACK BOUNDS (<2560B + ASan + UBSan) ---"
    gcc -std=c99 $SAN_FLAGS $INC_FLAGS tests/integration/udf_runner.c -L"$TARGET_DIR" -lnona_core $LDFLAGS -o /tmp/udf_runner
    /tmp/udf_runner

    echo "--- 11. END-TO-END PIPELINE DETERMINISM (kA != kB + ASan + UBSan) ---"
    gcc -std=c99 $SAN_FLAGS $INC_FLAGS tests/integration/e2e_pipeline_runner.c -L"$TARGET_DIR" -lnona_core $LDFLAGS -o /tmp/e2e_pipeline_runner
    /tmp/e2e_pipeline_runner

    echo "--- 12. CARDINALITY BOUNDARY & SHANNON SUPPRESSION (ASan + UBSan) ---"
    gcc -std=c99 $SAN_FLAGS $INC_FLAGS tests/integration/cardinality_boundary_runner.c -L"$TARGET_DIR" -lnona_core $LDFLAGS -o /tmp/cardinality_boundary_runner
    /tmp/cardinality_boundary_runner

    echo "--- 13. PROJECT WYCHEPROOF & NIST CAVP SECP256K1 VALIDATION ---"
    cargo test --release --frozen --offline --features "std host-defense" --test test_wycheproof

    echo "--- 14. WIRE DISPATCH & INGESTION CONTINUOUS FUZZ SMOKE GATE ---"
    cargo test --release --frozen --offline --features "std host-defense" --test test_fuzz_smoke

    echo "[===] HACVS-V2 14-LAYER VERIFICATION COMPLETE [===]"
  '

echo "===================================================================="
echo "RUNNING EDGE-CASE BOUNDARY SCENARIOS (A, B, C)"
echo "===================================================================="

# Scenario A: Restricted RLIMIT_MEMLOCK Quota (ulimit -l 0)
# NOTE: Executed under UBSan without ASan because AddressSanitizer interposes
# mlockall(2) to protect virtual shadow allocations, returning 0 unconditionally.
echo "[SCENARIO A] Testing restricted memlock (ulimit -l 0 + UBSan)..."
"$PODMAN_BIN" run --rm --net=none --platform "$PLATFORM" --ulimit memlock=0:0 \
  -v "${NONA_ROOT}":/volume \
  ${CARGO_MOUNT:+"${CARGO_MOUNT[@]}"} \
  -e CARGO_NET_OFFLINE=true \
  -e RUSTUP_TOOLCHAIN=nightly \
  -w /volume \
  "$MUSL_IMAGE" \
  bash -c '
    set -e
    TARGET_DIR=$(find target/ -type d -name "release" | grep -i "musl" | head -n 1)
    if [ -z "$TARGET_DIR" ]; then TARGET_DIR="target/release"; fi
    TARGET_LIB="$TARGET_DIR/libnona_core.a"

    EH_SYM=$(nm "$TARGET_LIB" | grep " U " | grep "personality" | awk "{print \$2}" | head -n 1 || true)
    DEFSYM_FLAG=""
    if [ -n "$EH_SYM" ]; then DEFSYM_FLAG="-Wl,--defsym=${EH_SYM}=rust_eh_personality"; fi
    LDFLAGS="-lpthread -ldl $DEFSYM_FLAG"

    cat << "SEOF" > /tmp/test_memlock.c
#include <stdio.h>
#include <stdint.h>
#include "nona.h"
int main(void) {
    int32_t status = nona_core_init();
    if (status == -2) {
        printf("[+] SUCCESS: Correctly returned -2 (mlockall rejected gracefully)\n");
        return 0;
    }
    printf("[!] FAIL: Unexpected status returned: %d\n", status);
    return 1;
}
SEOF
    gcc -std=c99 -fsanitize=undefined -Iinclude /tmp/test_memlock.c -L"$TARGET_DIR" -lnona_core $LDFLAGS -o /tmp/memlock_runner
    /tmp/memlock_runner
  '

# Scenario B: Adversarial Wire Ingestion & MTU Boundary Stress (ASan + UBSan)
echo "[SCENARIO B] Testing wire ingestion boundary stress (ASan + UBSan)..."
"$PODMAN_BIN" run --rm --net=none --platform "$PLATFORM" \
  -v "${NONA_ROOT}":/volume \
  ${CARGO_MOUNT:+"${CARGO_MOUNT[@]}"} \
  -e CARGO_NET_OFFLINE=true \
  -e RUSTUP_TOOLCHAIN=nightly \
  -w /volume \
  "$MUSL_IMAGE" \
  bash -c '
    set -e
    TARGET_DIR=$(find target/ -type d -name "release" | grep -i "musl" | head -n 1)
    if [ -z "$TARGET_DIR" ]; then TARGET_DIR="target/release"; fi
    TARGET_LIB="$TARGET_DIR/libnona_core.a"

    EH_SYM=$(nm "$TARGET_LIB" | grep " U " | grep "personality" | awk "{print \$2}" | head -n 1 || true)
    DEFSYM_FLAG=""
    if [ -n "$EH_SYM" ]; then DEFSYM_FLAG="-Wl,--defsym=${EH_SYM}=rust_eh_personality"; fi
    LDFLAGS="-lpthread -ldl $DEFSYM_FLAG"

    cat << "SEOF" > /tmp/test_wire.c
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include "nona.h"
int main(void) {
    uint8_t aligned_buf[4224] __attribute__((aligned(64))) = {0};
    assert(nona_ingest_stream(aligned_buf, 127) == -3);
    assert(nona_ingest_stream(aligned_buf, 129) == -3);
    assert(nona_ingest_stream(aligned_buf, 4224) == -3);
    assert(nona_ingest_stream(aligned_buf + 1, 128) == -2);
    printf("[+] SUCCESS: Adversarial wire boundaries rejected deterministically.\n");
    return 0;
}
SEOF
    gcc -std=c99 -fsanitize=address,undefined -Iinclude /tmp/test_wire.c -L"$TARGET_DIR" -lnona_core $LDFLAGS -o /tmp/wire_runner
    /tmp/wire_runner
  '

# Scenario C: Cryptographic Singularity & Group Order Annihilation
echo "[SCENARIO C] Testing cryptographic singularities..."
"$PODMAN_BIN" run --rm --net=none --platform "$PLATFORM" \
  -v "${NONA_ROOT}":/volume \
  ${CARGO_MOUNT:+"${CARGO_MOUNT[@]}"} \
  -e CARGO_NET_OFFLINE=true \
  -e RUSTUP_TOOLCHAIN=nightly \
  -w /volume \
  "$MUSL_IMAGE" \
  bash -c '
    set -e
    cargo test --release --frozen --offline --features "std host-defense" \
      --test test_wycheproof -- test_wycheproof_group_order_boundaries_and_annihilation test_wycheproof_batch_to_affine_all_infinity
    echo "[+] SUCCESS: Cryptographic edge singularities safely annihilated."
  '

echo "===================================================================="
echo "[===] ALL HACVS-V2 VERIFICATION & SCENARIO GATES PASSED (ASan+UBSan) [===]"
echo "===================================================================="
