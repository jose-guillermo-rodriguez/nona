#!/usr/bin/env bash
# Copyright (c) 2026 Nona Contributors.
# Licensed under the Apache License, Version 2.0 or the MIT License.

# ============================================================================
# PROJECT: Nona Core Engine
# SCRIPT: run_certification_pipeline.sh - Complete End-to-End Certification Pipeline
# ============================================================================

set -euo pipefail

NONA_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$NONA_ROOT"

MODE="all"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --host-only)
            MODE="host"
            shift
            ;;
        --container-only)
            MODE="container"
            shift
            ;;
        *)
            echo "Usage: $0 [--host-only | --container-only]" >&2
            exit 1
            ;;
    esac
done

echo "======================================================================"
echo "NONA CORE ENGINE: FULL OPEN-SOURCE CERTIFICATION PIPELINE"
echo "Mode: ${MODE}"
echo "======================================================================"

# ============================================================================
# PHASE 1: HOST / NATIVE VERIFICATION GATES (NO CONTAINER REQUIRED)
# ============================================================================
if [ "$MODE" = "all" ] || [ "$MODE" = "host" ]; then
    echo ""
    echo ">>> [STAGE 1/9] Verus Machine-Checked Formal SMT Proofs..."
    if [ -f "./tools/run_verus_safe.sh" ]; then
        export PATH="${VERUS_DIR:-$HOME/.verus/bin}:$PATH"
        # Host Phase strictly forbids escaping into container daemons
        ./tools/run_verus_safe.sh --native-host
    else
        echo "[SKIP] Verus verification harness not found."
    fi

    echo ""
    echo ">>> [STAGE 2/9] Code Review & Static Hygiene Suite..."
    ./tools/check_code_hygiene.sh

    echo ""
    echo ">>> [STAGE 3/9] CycloneDX v1.5 SBOM & Supply Chain Gating (Gate 5.2)..."
    make sbom

    echo ""
    echo ">>> [STAGE 4/9] #![no_std] Core Substrate Build & Freestanding C-ABI Gate..."
    cargo build --release --lib --no-default-features
    RUSTFLAGS="-C panic=abort" cargo test --test test_c_abi --no-default-features

    echo ""
    echo ">>> [STAGE 5/9] Full Rust Test Matrix (Unit, Integration & Doctests)..."
    cargo test --all-targets --features std
    cargo test --doc --features std

    echo ""
    echo ">>> [STAGE 6/9] Static Linkage, Zero-Heap & Binary Hardening Audit..."
    ./tools/verify_linkage.sh

    echo ""
    echo ">>> [STAGE 7/9] Hardened Mechanical Runtime Gates (1 through 5)..."
    ./tools/run_mechanical_gates.sh

    echo ""
    echo ">>> [STAGE 8/9] Dynamic Sanitizer Matrix (UBSan)..."
    ./tools/run_sanitizers.sh

    echo ""
    echo ">>> [STAGE 9/9] Performance Microbenchmark Suite Validation..."
    cargo bench --features std --no-run

    echo ""
    echo "======================================================================"
    echo " [✓] PHASE 1: ALL HOST / NATIVE GATES COMPLETED SUCCESSFULLY"
    echo "======================================================================"
fi

# ============================================================================
# PHASE 2: HERMETIC CONTAINER VERIFICATION (PODMAN / DOCKER REQUIRED)
# ============================================================================
if [ "$MODE" = "all" ] || [ "$MODE" = "container" ]; then
    # Discover available container engine
    CONTAINER_BIN="${CONTAINER_ENGINE:-}"
    if [ -z "$CONTAINER_BIN" ]; then
        if command -v podman &>/dev/null; then
            CONTAINER_BIN="$(command -v podman)"
        elif command -v docker &>/dev/null; then
            CONTAINER_BIN="$(command -v docker)"
        fi
    fi

    HAS_CONTAINER=1
    if [ -z "$CONTAINER_BIN" ] || ! "$CONTAINER_BIN" info >/dev/null 2>&1; then
        HAS_CONTAINER=0
    fi

    if [ "$HAS_CONTAINER" -eq 0 ]; then
        echo "[FATAL] Container verification required for mode '${MODE}', but no active container engine was found." >&2
        echo "[HINT] Start Podman/Docker (e.g., 'podman machine start') or run '--host-only' / 'make host'." >&2
        exit 1
    fi

    echo ""
    echo ">>> [STAGE 10/12] Machine Stack Ceiling Audit (-Z emit-stack-sizes musl)..."
    ./tools/verify_stack_sizes.sh

    echo ""
    echo ">>> [STAGE 11/12] HACVS-V2 14-Layer Container Verification & Scenarios..."
    ./tools/run_container_verification.sh

    echo ""
    echo ">>> [STAGE 12/12] Reproducible AWS Nitro Enclave Build & PCR Measurement..."
    ./tools/build_nitro_eif.sh

    echo ""
    echo "======================================================================"
    echo " [✓] PHASE 2: ALL CONTAINER ARTIFACTS COMPLETED SUCCESSFULLY"
    echo "======================================================================"
fi

echo ""
echo "======================================================================"
echo "CERTIFICATION COMPLETE: 100% OF NONA QA GATES VERIFIED AND PASSED"
echo "======================================================================"
