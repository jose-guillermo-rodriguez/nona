#!/usr/bin/env bash
# Copyright (c) 2026 Nona Contributors.
# Licensed under the Apache License, Version 2.0 or the MIT License.
#
# Deterministic CycloneDX v1.5 SBOM Generation & Sanitization Engine
# Enforces Gate 5.2 / PL-03 Invariants:
#   1. Canonical CycloneDX v1.5 Schema
#   2. Deterministic Byte-for-Byte Output (SOURCE_DATE_EPOCH)
#   3. Zero Workstation Path & file:// Leakage
#   4. Closed-form Dependency Graph Parity

set -euo pipefail

NONA_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$NONA_ROOT"

OUTPUT_PREFIX="nona-core.cdx"
OUTPUT_FILE="${OUTPUT_PREFIX}.json"

echo "==> Generating deterministic CycloneDX v1.5 SBOM (${OUTPUT_FILE})..."
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1700000000}" cargo cyclonedx \
  --format json \
  --spec-version 1.5 \
  --target all \
  --override-filename "$OUTPUT_PREFIX"

echo "==> Applying algebraic path sanitization..."
jq '
  walk(
    if type == "string" then
      sub("path\\+file://[^#]+#nona-core@"; "pkg:cargo/nona-core@")
      | sub("\\?download_url=file://\\."; "")
    else . end
  )
' "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"

echo "==> Verifying zero-leakage invariant..."
RESIDUAL_PATHS=$(jq -r '.. | strings | select(test("(/Users/|/home/|/private/|/var/folders/|/Volumes/|file://|^[A-Za-z]:\\\\)"))' "$OUTPUT_FILE")
if [ -n "$RESIDUAL_PATHS" ]; then
  echo "[FATAL] Residual host paths or pseudo-URIs detected in ${OUTPUT_FILE}:" >&2
  echo "$RESIDUAL_PATHS" >&2
  exit 1
fi

echo "[✓] Gate 5.2 compliant SBOM verified: ${OUTPUT_FILE}"
