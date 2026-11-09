#!/usr/bin/env bash
# Copyright (c) 2026 Nona Contributors.
# Licensed under the Apache License, Version 2.0 or the MIT License.

# ============================================================================
# PROJECT: Nona Core Engine
# MODULE: run_verus_safe.sh - Substrate Formal Verification Safety Harness
# ============================================================================

set -euo pipefail

# 1. Dynamic Root Discovery (Zero Host Footprint)
if ! BASE_DIR="$(git rev-parse --show-toplevel 2>/dev/null)"; then
    BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi
cd "$BASE_DIR"

export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${BASE_DIR}/target/verus_cache}"
mkdir -p "$CARGO_TARGET_DIR"

# 2. Mode Resolution (Container Hermeticity vs Native Host)
NATIVE_HOST=0
CHECK_ENV_ONLY=0
PASSTHROUGH_ARGS=()

for arg in "$@"; do
    case "$arg" in
        --native-host)
            NATIVE_HOST=1
            ;;
        --check-env)
            CHECK_ENV_ONLY=1
            ;;
        --container)
            NATIVE_HOST=0
            ;;
        *)
            PASSTHROUGH_ARGS+=("$arg")
            ;;
    esac
done

# If already inside container, force native execution
if [ "${NONA_IN_CONTAINER:-0}" = "1" ]; then
    NATIVE_HOST=1
fi

CONTAINER_BIN="$(command -v podman 2>/dev/null || command -v docker 2>/dev/null || echo "")"

# Delegate to hermetic container if not explicitly running native host
if [ "$NATIVE_HOST" -eq 0 ]; then
    if [ -n "$CONTAINER_BIN" ] && "$CONTAINER_BIN" info >/dev/null 2>&1; then
        if [ "$CHECK_ENV_ONLY" -eq 1 ]; then
            echo "[OK] Hermetic container engine operational: $CONTAINER_BIN"
            exit 0
        fi
        exec "${BASE_DIR}/tools/run_verus_container.sh" ${PASSTHROUGH_ARGS[@]+"${PASSTHROUGH_ARGS[@]}"}
    fi
fi

# 3. Dynamic Toolchain & SMT Solver Discovery (Native Execution Path)
CANDIDATE_DIRS=(
    "${NONA_RUNTIME_DIR:-}"
    "${BASE_DIR}/.runtime"
    "${BASE_DIR}/../.runtime"
    "${BASE_DIR}/../../.runtime"
    "${VIRTUAL_ENV:-}/.runtime"
    "${VIRTUAL_ENV:-}/../.runtime"
    "${VIRTUAL_ENV:-}/../../.runtime"
    "${HOME}/.verus"
    "/opt/verus"
)

VERUS_BIN=""
if [ -n "${VERUS_OVERRIDE:-}" ] && [ -x "${VERUS_OVERRIDE}" ]; then
    VERUS_BIN="${VERUS_OVERRIDE}"
elif command -v verus &>/dev/null; then
    VERUS_BIN="$(command -v verus)"
else
    for dir in "${CANDIDATE_DIRS[@]}"; do
        [ -z "$dir" ] && continue
        if [ -x "${dir}/verus-x86-linux/verus" ]; then
            VERUS_BIN="${dir}/verus-x86-linux/verus"
            break
        elif [ -x "${dir}/verus-arm64-macos/verus" ]; then
            VERUS_BIN="${dir}/verus-arm64-macos/verus"
            break
        elif [ -x "${dir}/verus-x86-macos/verus" ]; then
            VERUS_BIN="${dir}/verus-x86-macos/verus"
            break
        elif [ -x "${dir}/verus-aarch64-linux/verus" ]; then
            VERUS_BIN="${dir}/verus-aarch64-linux/verus"
            break
        elif [ -x "${dir}/verus-engine/verus" ]; then
            VERUS_BIN="${dir}/verus-engine/verus"
            break
        elif [ -x "${dir}/verus" ]; then
            VERUS_BIN="${dir}/verus"
            break
        elif [ -x "${dir}/bin/verus" ]; then
            VERUS_BIN="${dir}/bin/verus"
            break
        else
            for cand in "${dir}"/verus-*/verus; do
                if [ -x "$cand" ]; then
                    VERUS_BIN="$cand"
                    break 2
                fi
            done
        fi
    done
fi

if [ -z "$VERUS_BIN" ] || [ ! -x "$VERUS_BIN" ]; then
    echo "[ERROR] Verus binary not found in PATH or candidate runtime directories." >&2
    echo "[HINT] Install Podman/Docker for hermetic verification, or install Verus to ~/.verus." >&2
    exit 1
fi

# 4. Host Linux ABI & Glibc Version Guard (Radical Efficacy Invariant)
if [ "$(uname -s)" = "Linux" ] && [ "${NONA_IN_CONTAINER:-0}" != "1" ]; then
    HOST_GLIBC=$(ldd --version 2>/dev/null | head -n 1 | grep -oE "[0-9]+\.[0-9]+" | head -n 1 || echo "0.0")
    if [ "$(printf "%s\n%s\n" "2.39" "$HOST_GLIBC" | sort -V | head -n 1)" != "2.39" ]; then
        echo "[ERROR] Incompatible Host Runtime detected!" >&2
        echo "        Host glibc version ($HOST_GLIBC) is lower than required glibc 2.39." >&2
        echo "        Ubuntu 22.04 LTS (glibc 2.35) cannot execute this binary without dynamic loader aborts." >&2
        echo "[REMEDY] Execute formal verification via hermetic container: ./tools/run_verus_container.sh" >&2
        echo "         Or upgrade the host to Ubuntu 24.04 LTS." >&2
        exit 1
    fi
fi

VERUS_DIR="$(cd "$(dirname "${VERUS_BIN}")" && pwd)"
export PATH="${VERUS_DIR}:$PATH"

Z3_BIN=""
if [ -n "${VERUS_Z3_PATH:-}" ] && [ -x "${VERUS_Z3_PATH}" ]; then
    Z3_BIN="${VERUS_Z3_PATH}"
elif [ -x "${VERUS_DIR}/z3" ]; then
    Z3_BIN="${VERUS_DIR}/z3"
elif [ -x "${VERUS_DIR}/../z3_solver/z3" ]; then
    Z3_BIN="$(cd "${VERUS_DIR}/../z3_solver" && pwd)/z3"
elif [ -x "${VERUS_DIR}/../bin/z3" ]; then
    Z3_BIN="$(cd "${VERUS_DIR}/../bin" && pwd)/z3"
elif command -v z3 &>/dev/null; then
    Z3_BIN="$(command -v z3)"
else
    for dir in "${CANDIDATE_DIRS[@]}"; do
        [ -z "$dir" ] && continue
        if [ -x "${dir}/z3_solver/z3" ]; then
            Z3_BIN="${dir}/z3_solver/z3"
            break
        elif [ -x "${dir}/z3" ]; then
            Z3_BIN="${dir}/z3"
            break
        elif [ -x "${dir}/bin/z3" ]; then
            Z3_BIN="${dir}/bin/z3"
            break
        fi
    done
fi

if [ -n "$Z3_BIN" ] && [ -x "$Z3_BIN" ]; then
    export VERUS_Z3_PATH="$Z3_BIN"
    Z3_DIR="$(cd "$(dirname "${Z3_BIN}")" && pwd)"
    export PATH="${Z3_DIR}:$PATH"
else
    echo "[ERROR] Z3 solver binary not found. Set VERUS_Z3_PATH or install Z3 in candidate runtimes." >&2
    exit 1
fi

if [ "$CHECK_ENV_ONLY" -eq 1 ]; then
    if "${VERUS_BIN}" --version >/dev/null 2>&1; then
        echo "[OK] Verus (${VERUS_BIN}) and Z3 (${Z3_BIN}) operational."
        exit 0
    fi
    exit 1
fi

ulimit -v 4194304 2>/dev/null || true

# 5. Execution Pipeline
if [ "${#PASSTHROUGH_ARGS[@]}" -gt 0 ]; then
    TARGET_FILE="${PASSTHROUGH_ARGS[0]}"
    FUNC_NAME="${PASSTHROUGH_ARGS[1]:-}"
    FLAGS=(--rlimit 1000000 --cfg verus --crate-type=lib)
    if [ -n "${FUNC_NAME}" ]; then
        FLAGS+=(--verify-root --verify-function "${FUNC_NAME}")
    fi
    "${VERUS_BIN}" "${FLAGS[@]}" "${TARGET_FILE}"
else
    TARGETS=(
        "src/psi.rs"
        "src/normalization.rs"
        "src/obfuscation.rs"
        "src/allocator.rs"
        "src/crypto.rs"
    )

    TOTAL_TARGETS=${#TARGETS[@]}
    TOTAL_VERIFIED=0
    TOTAL_ERRORS=0
    EMPTY_TARGETS=0
    IDX=1

    echo "=== NONA CORE ENGINE: FORMAL VERIFICATION SUITE ==="

    for REL_PATH in "${TARGETS[@]}"; do
        FULL_PATH="${BASE_DIR}/${REL_PATH}"
        echo "[${IDX}/${TOTAL_TARGETS}] Verifying ${REL_PATH}..."

        set +e
        OUT=$("${VERUS_BIN}" --rlimit 1000000 --cfg verus --crate-type=lib "${FULL_PATH}" 2>&1)
        STATUS=$?
        set -e

        echo "${OUT}"

        V=$(echo "${OUT}" | awk '/verification results::/ { for(i=1;i<=NF;i++) if($i ~ /^verified/) print $(i-1) }' | tail -n 1)
        E=$(echo "${OUT}" | awk '/verification results::/ { for(i=1;i<=NF;i++) if($i ~ /^error/) print $(i-1) }' | tail -n 1)

        V=${V:-0}
        E=${E:-0}

        if [ ${STATUS} -ne 0 ] && [ "${E}" -eq 0 ]; then
            E=1
        fi

        if [ "${V}" -eq 0 ]; then
            EMPTY_TARGETS=$((EMPTY_TARGETS + 1))
        fi

        TOTAL_VERIFIED=$((TOTAL_VERIFIED + V))
        TOTAL_ERRORS=$((TOTAL_ERRORS + E))
        IDX=$((IDX + 1))
    done

    TOTAL_THEOREMS=$((TOTAL_VERIFIED + TOTAL_ERRORS))

    if [ "${TOTAL_ERRORS}" -eq 0 ] && [ "${EMPTY_TARGETS}" -eq 0 ] && [ "${TOTAL_VERIFIED}" -gt 0 ] && [ "${TOTAL_THEOREMS}" -eq "${TOTAL_VERIFIED}" ]; then
        echo "[===] 100% CORE ALGEBRAIC & INVARIANT TARGETS VERIFIED: ${TOTAL_VERIFIED}/${TOTAL_THEOREMS} SMT TARGETS SEALED (0 ERRORS) [===]"
    else
        echo "[===] VERIFICATION FAILURE: ${TOTAL_ERRORS} ERRORS DETECTED (${TOTAL_VERIFIED}/${TOTAL_THEOREMS} THEOREMS VERIFIED, ${EMPTY_TARGETS} EMPTY TARGETS) [===]"
        exit 1
    fi
fi
