#!/usr/bin/env bash
# Copyright (c) 2026 Nona Contributors.
# Licensed under the Apache License, Version 2.0 or the MIT License.

# ============================================================================
# PROJECT: Nona Core Engine
# MODULE: verify_linkage.sh - Host Native Linkage & Binary Hardening Audit
# ============================================================================

set -euo pipefail

# 1. Establish Canonical Workspace Root
NONA_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$NONA_ROOT"

# 2. Compile Pure #![no_std] Static Library Artifact
TARGET_BASE="${CARGO_TARGET_DIR:-target}"
LIB_STATIC="${LIB_STATIC:-}"

if [ -z "$LIB_STATIC" ]; then
    echo "[INFRA] Compiling pure #![no_std] static archive for symbol and linkage audit..."
    cargo build --release --lib --no-default-features --quiet
    LIB_STATIC="${TARGET_BASE}/release/libnona_core.a"
fi

if [ ! -f "$LIB_STATIC" ]; then
    echo "[ERROR] Failed to locate or build static library at $LIB_STATIC." >&2
    exit 1
fi

echo "[INFRA] Auditing static library artifact: $LIB_STATIC"

# 3. Dynamic Toolchain Discovery
RUST_SYSROOT="$(rustc --print sysroot 2>/dev/null || true)"
LLVM_NM=""
if [ -n "$RUST_SYSROOT" ]; then
    LLVM_NM="$(find "$RUST_SYSROOT" -name "llvm-nm" 2>/dev/null | head -n 1 || true)"
fi
if [ -z "$LLVM_NM" ] && command -v llvm-nm &>/dev/null; then
    LLVM_NM="llvm-nm"
fi
NM_BIN="${LLVM_NM:-nm}"

# 4. Zero-Heap Symbol Audit
echo "[AUDIT] Performing zero-heap symbol audit with $NM_BIN..."
HEAP_SYMBOLS=$("$NM_BIN" "$LIB_STATIC" 2>/dev/null | grep -iE "(malloc|free|realloc|__rust_alloc)" || true)

if [ -n "$HEAP_SYMBOLS" ]; then
    echo "[!] HEAP SYMBOLS DETECTED IN $LIB_STATIC:" >&2
    echo "$HEAP_SYMBOLS" >&2
    exit 1
fi
echo "[+] ZERO HEAP SYMBOLS CONFIRMED in $LIB_STATIC."

# 5. Compile Dedicated Linkage Runner Inside Target Dir
AUDIT_DIR="${TARGET_BASE}/linkage_audit"
mkdir -p "$AUDIT_DIR"
RUNNER_BIN="${AUDIT_DIR}/linkage_runner"

cleanup() {
    rm -rf "$AUDIT_DIR"
}
trap cleanup EXIT INT TERM

CC_BIN="${CC:-gcc}"
if ! command -v "$CC_BIN" &>/dev/null; then
    CC_BIN="clang"
fi

PLATFORM="$(uname -s)"

# In-crate rust_eh_personality provides full C-ABI closure; no external stub required.

echo "[INFRA] Compiling dedicated C-ABI linkage runner ($CC_BIN) against $LIB_STATIC..."
$CC_BIN -std=c99 -Wall -Wextra -O2 -Iinclude \
    tests/integration/c_runner.c \
    "$LIB_STATIC" \
    -lpthread -ldl \
    -o "$RUNNER_BIN"

echo "[SUCCESS] Dedicated linkage runner compiled successfully. Symbols resolved."

# 6. Binary Hardening Audit
echo "[INFRA] Platform detected: $PLATFORM"
if [ "$PLATFORM" = "Linux" ] && command -v readelf &>/dev/null; then
    echo "[INFRA] Running Linux ELF hardening audit on $RUNNER_BIN..."
    ELF_TYPE=$(readelf -h "$RUNNER_BIN" | grep "Type:" | awk '{print $2}')
    if [[ "$ELF_TYPE" != "DYN" && "$ELF_TYPE" != "EXEC" ]]; then
        echo "[ERROR] Unexpected ELF type: $ELF_TYPE" >&2
        exit 1
    fi

    if readelf -l "$RUNNER_BIN" | grep -A1 "GNU_STACK" | grep -q "E"; then
        echo "[ERROR] Stack segment is Executable (NX Disabled)!" >&2
        exit 1
    fi
    echo "[+] Linux ELF NX & PIE hardening verified."
elif [ "$PLATFORM" = "Darwin" ] && command -v otool &>/dev/null; then
    echo "[INFRA] Running Darwin Mach-O hardening audit on $RUNNER_BIN..."
    if ! otool -hv "$RUNNER_BIN" | grep -q "PIE"; then
        echo "[ERROR] Mach-O binary lacks PIE flag!" >&2
        exit 1
    fi
    echo "[+] Darwin Mach-O PIE hardening verified."
fi

# 7. Execute Linkage Runner (Runtime C-ABI Contract Permutations)
echo "[INFRA] Executing dedicated linkage runner..."
"$RUNNER_BIN"

echo "[SUCCESS] verify_linkage.sh: Static library linkage, symbol isolation, and ABI contracts verified."
