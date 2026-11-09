#!/usr/bin/env bash
# Copyright (c) 2026 Nona Contributors.
# Licensed under the Apache License, Version 2.0 or the MIT License.

# ============================================================================
# PROJECT: Nona Core Engine
# MODULE: run_sanitizers.sh - Multi-Target Dynamic Sanitizer Matrix Harness
# ============================================================================
#
# WORKSTREAM 5 ARCHITECTURAL SPECIFICATION:
# - macOS Darwin: UBSan (-fsanitize=undefined) execution
# - Linux Musl (Static): UBSan (-fsanitize=undefined) execution
# - Linux Glibc (CI): ASan (-fsanitize=address), LSan, and UBSan execution
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

echo "================================================================================"
echo "NONA CORE DYNAMIC SANITIZER MATRIX"
echo "================================================================================"

PLATFORM="$(uname -s)"
ARCH="$(uname -m)"
CC_BIN="${CC:-}"
if [ -z "$CC_BIN" ]; then
    if command -v clang &>/dev/null; then
        CC_BIN="clang"
    elif command -v gcc &>/dev/null; then
        CC_BIN="gcc"
    else
        CC_BIN="cc"
    fi
fi
TMP_DIR="$(mktemp -d /tmp/nona_sanitizers.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "[INFO] Host Platform: $PLATFORM ($ARCH)"
echo "[INFO] C Compiler:    $($CC_BIN --version | head -n 1)"

echo "[INFO] Compiling libnona_core static archive..."
cargo build --release --lib --no-default-features --features host-defense --frozen --quiet
LIB_NONA="target/release/libnona_core.a"

if [ ! -f "$LIB_NONA" ]; then
    echo "[ERROR] Missing $LIB_NONA" >&2
    exit 1
fi

RUNNERS=(
    "tests/integration/c_runner.c"
    "tests/integration/kat_runner.c"
    "tests/integration/cardinality_boundary_runner.c"
    "tests/integration/e2e_pipeline_runner.c"
    "tests/integration/remanence_runner.c"
    "tests/integration/concurrency_runner.c"
    "tests/integration/signal_runner.c"
    "tests/integration/timing_runner.c"
    "tests/integration/udf_runner.c"
)

# Multi-Target Sanitizer Suite Resolution
SUITES=()
if [ "$PLATFORM" = "Darwin" ]; then
    echo "[INFO] Host is macOS Darwin: Activating UBSan (UndefinedBehaviorSanitizer)..."
    SUITES=("ubsan")
elif [ "$PLATFORM" = "Linux" ]; then
    if ldd --version 2>&1 | grep -qi "musl"; then
        echo "[INFO] Static musl environment detected: Enforcing STATIC MUSL SANITIZER RESTRICTION."
        SUITES=("ubsan")
    else
        echo "[INFO] Glibc Linux detected: Activating UBSan and ASan suites..."
        SUITES=("ubsan" "asan")
    fi
fi

for suite in "${SUITES[@]}"; do
    echo "--------------------------------------------------------------------------------"
    echo "[*] EXECUTING SANITIZER MATRIX PASS: $suite"
    echo "--------------------------------------------------------------------------------"

    FLAGS=()
    if [ "$suite" = "ubsan" ]; then
        FLAGS=("-fsanitize=undefined" "-fno-sanitize-recover=all")
    elif [ "$suite" = "asan" ]; then
        FLAGS=("-fsanitize=address" "-fno-omit-frame-pointer" "-no-pie")
    fi

    for runner_src in "${RUNNERS[@]}"; do
        runner_name="$(basename "$runner_src" .c)"
        bin_out="$TMP_DIR/${runner_name}_${suite}"

        $CC_BIN -std=c99 -Wall -Wextra -O1 -Iinclude -Itests/integration \
            "${FLAGS[@]}" \
            "$runner_src" \
            "$LIB_NONA" \
            -lpthread -ldl \
            -o "$bin_out"

        echo "  [+] Running $runner_name under $suite..."
        "$bin_out" > /dev/null
        echo "  [PASS] $runner_name ($suite: clean execution, zero violations)"
    done
done

echo "================================================================================"
echo "[SUCCESS] Multi-Target Dynamic Sanitizer Matrix PASSED across all targets!"
echo "================================================================================"
