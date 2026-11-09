#!/usr/bin/env bash
# Copyright (c) 2026 Nona Contributors.
# Licensed under the Apache License, Version 2.0 or the MIT License.

# ============================================================================
# PROJECT: Nona Core Engine
# SCRIPT: run_verus_container.sh - Hermetic Containerized Formal Verification
# ============================================================================

set -euo pipefail

NONA_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$NONA_ROOT"

IMAGE_NAME="${VERUS_IMAGE:-nona-verus-verifier:latest}"

# 1. Resolve Container Engine (Podman > Docker)
CONTAINER_BIN="${CONTAINER_BIN:-}"
if [ -z "$CONTAINER_BIN" ]; then
    CONTAINER_BIN="$(command -v podman 2>/dev/null || command -v docker 2>/dev/null || echo "")"
fi

if [ -z "$CONTAINER_BIN" ]; then
    echo "[ERROR] No container engine found (podman or docker required for hermetic verification)." >&2
    echo "[HINT] Install podman or docker, or run on Ubuntu 24.04 with glibc >= 2.39 using --native-host." >&2
    exit 1
fi

if ! "$CONTAINER_BIN" info >/dev/null 2>&1; then
    echo "[ERROR] Container engine ($CONTAINER_BIN) is unreachable or daemon is not active." >&2
    echo "[HINT] Run podman machine start (macOS) or ensure container service is running." >&2
    exit 1
fi

# 2. Build or Verify Container Image
if ! "$CONTAINER_BIN" image exists "$IMAGE_NAME" 2>/dev/null && ! "$CONTAINER_BIN" inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    echo "[CONTAINER] Building hermetic Verus verification image (${IMAGE_NAME})..."
    "$CONTAINER_BIN" build \
        --platform linux/amd64 \
        -t "$IMAGE_NAME" \
        -f tools/docker/Dockerfile.verus .
fi

echo "===================================================================="
echo "NONA CORE ENGINE: HERMETIC FORMAL SMT VERIFICATION"
echo "Container Engine: $CONTAINER_BIN | Image: $IMAGE_NAME"
echo "Platform:         linux/amd64 (glibc 2.39 / libstdc++ 3.4.32)"
echo "===================================================================="

# 3. Cache Directory Mounting
CACHE_DIR="${NONA_ROOT}/target/verus_cache"
mkdir -p "$CACHE_DIR"

# 4. Execute Verification Pipeline Inside Sealed Container
"$CONTAINER_BIN" run --rm --platform linux/amd64 \
    -v "${NONA_ROOT}":/volume:Z \
    -e NONA_IN_CONTAINER=1 \
    -e RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}" \
    -e CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}" \
    -w /volume \
    "$IMAGE_NAME" \
    /volume/tools/run_verus_safe.sh --native-host "$@"
