#!/usr/bin/env bash
# Copyright (c) 2026 Nona Contributors.
# Licensed under the Apache License, Version 2.0 or the MIT License.

# ============================================================================
# PROJECT: Nona Core Engine
# SCRIPT: verify_stack_sizes.sh - Container-Agnostic Machine Stack Audit
# ============================================================================

set -euo pipefail

NONA_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$NONA_ROOT"

# Ensure standard macOS / Linux binary paths are evaluated
export PATH="/opt/homebrew/bin:/usr/local/bin:$HOME/.local/bin:$PATH"

# 1. Dispatch Gate: Container vs Native Host
if [ "${1:-}" != "--inside-container" ]; then
    PLATFORM_NAME="$(uname -s)"

    # If running outside a Linux musl environment, dispatch via container engine
    if [ "$PLATFORM_NAME" != "Linux" ] || [ ! -d "/opt/rustup" ]; then
        
        # Discover available container engine: CONTAINER_ENGINE override -> podman -> docker
        ENGINE="${CONTAINER_ENGINE:-}"
        if [ -z "$ENGINE" ]; then
            if command -v podman &>/dev/null; then
                ENGINE="podman"
            elif command -v docker &>/dev/null; then
                ENGINE="docker"
            fi
        fi

        if [ -z "$ENGINE" ] || ! command -v "$ENGINE" &>/dev/null; then
            echo "[ERROR] No supported container engine (podman or docker) found in PATH." >&2
            echo "[HINT] Install podman or docker, or set CONTAINER_ENGINE=/path/to/engine." >&2
            exit 1
        fi

        HOST_RAW="$(uname -m)"
        case "$HOST_RAW" in
            arm64|aarch64) CONTAINER_PLATFORM="linux/arm64" ;;
            x86_64|amd64)  CONTAINER_PLATFORM="linux/amd64" ;;
            *) echo "[ERROR] Unsupported host architecture: $HOST_RAW" >&2; exit 1 ;;
        esac

        MUSL_IMAGE="docker.io/clux/muslrust:latest"

        # Resolve cargo cache directory if present
        CARGO_MOUNT=()
        NONA_RUNTIME_DIR="${NONA_RUNTIME_DIR:-${NONA_ROOT}/.runtime}"
        if [ ! -d "$NONA_RUNTIME_DIR" ] && [ -d "${NONA_ROOT}/../.runtime" ]; then
            NONA_RUNTIME_DIR="$(cd "${NONA_ROOT}/../.runtime" 2>/dev/null && pwd)"
        fi
        if [ -d "${NONA_RUNTIME_DIR}/.cargo" ]; then
            CARGO_MOUNT=(-v "${NONA_RUNTIME_DIR}/.cargo":/cargo:ro -e CARGO_HOME=/cargo)
        fi

        echo "[AUDIT] Host: $PLATFORM_NAME ($HOST_RAW) | Engine: $ENGINE | Image: $MUSL_IMAGE"
        exec "$ENGINE" run --rm -i \
            --platform "$CONTAINER_PLATFORM" \
            -v "${NONA_ROOT}":/volume:ro \
            "${CARGO_MOUNT[@]}" \
            -e RUSTUP_TOOLCHAIN=nightly \
            -w /volume \
            "$MUSL_IMAGE" \
            bash /volume/tools/verify_stack_sizes.sh --inside-container
    fi
fi

# 2. Inside Container / Native Linux: Toolchain & Inspector Initialization
echo "=== 1. Toolchain & Inspector Resolution ==="
rustup target add aarch64-unknown-linux-musl --toolchain nightly >/dev/null 2>&1 || true
rustup component add llvm-tools-preview --toolchain nightly >/dev/null 2>&1

SYSROOT="$(rustc --print sysroot 2>/dev/null || true)"
READELF=$(find "$SYSROOT" /opt/rustup "$RUSTUP_HOME" "$HOME/.rustup" -name "llvm-readelf" 2>/dev/null | head -n 1 || true)
if [ -z "$READELF" ] || [ ! -x "$READELF" ]; then
    READELF=$(find "$SYSROOT" /opt/rustup "$RUSTUP_HOME" "$HOME/.rustup" -name "llvm-readobj" 2>/dev/null | head -n 1 || true)
fi
if [ -z "$READELF" ] || [ ! -x "$READELF" ]; then
    READELF=$(command -v llvm-readelf || command -v readelf || true)
fi
if [ -z "$READELF" ] || [ ! -x "$READELF" ]; then
    READELF=$(find /opt/rustup -name "llvm-readobj" 2>/dev/null | grep "nightly" | head -n 1 || command -v llvm-readobj || true)
fi
if [ -z "$READELF" ] || [ ! -x "$READELF" ]; then
    echo "[ERROR] readelf / llvm-readelf binary could not be resolved." >&2
    exit 1
fi
echo "[+] Stack Inspector (readelf): $READELF"
echo "[+] Active compiler: $(rustc --version)"

export CARGO_TARGET_DIR=/tmp/target
TARGET_DIR="/tmp/target/aarch64-unknown-linux-musl/release"

# 3. Compile Static Library with Stack Sizes Emitted
echo ""
echo "=== 2. Compiling Static Library (libnona_core.a) with -Z emit-stack-sizes ==="
RUSTFLAGS="-C link-arg=-lc -C target-feature=+crt-static -Z emit-stack-sizes" \
    cargo rustc --release --no-default-features --target aarch64-unknown-linux-musl --lib --crate-type staticlib

# 4. Audit libnona_core.a Machine Stack Frames
echo ""
echo "===================================================================="
echo "AUDIT: STATIC ENGINE ARCHIVE (libnona_core.a)"
echo "===================================================================="
if [[ "$READELF" == *"readobj"* ]]; then
    "$READELF" --elf-output-style=GNU --stack-sizes --demangle "$TARGET_DIR/libnona_core.a" > /tmp/lib_raw.txt
else
    "$READELF" --stack-sizes --demangle "$TARGET_DIR/libnona_core.a" > /tmp/lib_raw.txt
fi

awk '
  /^[[:space:]]*[0-9]+/ {
    size = $1 + 0;
    func_name = substr($0, index($0, $1) + length($1));
    sub(/^[[:space:]]+/, "", func_name);
    printf "%6d\t%s\n", size, func_name;
  }
' /tmp/lib_raw.txt | sort -t$'\t' -k1,1nr > /tmp/lib_parsed.txt

TOTAL_LIB=$(wc -l < /tmp/lib_parsed.txt)
echo "[+] Audited $TOTAL_LIB functions across libnona_core.a"

echo ""
echo "--- Top 15 Largest Machine Stack Frames ---"
head -n 15 /tmp/lib_parsed.txt | awk -F'\t' '{ printf "%6d bytes   %s\n", $1, $2 }'

echo ""
echo "--- Invariant 2 Check: Hard Ceiling <= 4096 Bytes ---"
VIOLATIONS=$(awk -F'\t' '$1 > 4096 { printf "[VIOLATION] %6d bytes: %s\n", $1, $2 }' /tmp/lib_parsed.txt)

if [ -n "$VIOLATIONS" ]; then
    echo "[!] FATAL: Stack ceiling breached in libnona_core.a (> 4096 bytes):" >&2
    echo "$VIOLATIONS" >&2
    exit 1
fi

MAX_FRAME=$(head -n 1 /tmp/lib_parsed.txt | awk -F'\t' '{print $1}')
echo "[+] INVARIANT VERIFIED: All $TOTAL_LIB functions <= 4096 B (Peak frame: $MAX_FRAME B)"
