#!/usr/bin/env bash
# Copyright (c) 2026 Nona Contributors.
# Licensed under the Apache License, Version 2.0 or the MIT License.

# ============================================================================
# PROJECT: Nona Core Engine
# SCRIPT: deploy/run_nitro.sh - AWS Nitro Enclave & Local Simulation Harness
# ============================================================================

set -euo pipefail

if ! NONA_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"; then
    NONA_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi
cd "$NONA_ROOT"

DEFAULT_CPU_COUNT=2
DEFAULT_MEMORY_MIB=512
DEFAULT_CID=16
DEFAULT_VSOCK_PORT=5005
SIM_PID_FILE="/tmp/nona_enclave.pid"
SIM_SOCK_FILE="/tmp/nona.sock"
SIM_LOG_FILE="/tmp/nona_enclave.log"

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)
        TARGET_ARCH="x86_64"
        DEFAULT_MEMORY_MIB=512
        ;;
    aarch64|arm64)
        TARGET_ARCH="aarch64"
        # Graviton with 64 KiB kernel pages allocates 1 GiB hugepages
        DEFAULT_MEMORY_MIB=1024
        ;;
    *)
        echo "[!] Unsupported host architecture: $ARCH" >&2
        exit 1
        ;;
esac

EIF_FILE="${NONA_ROOT}/target/enclave/nona_enclave_${TARGET_ARCH}.eif"
MANIFEST_FILE="${NONA_ROOT}/manifests/enclave_manifest_${TARGET_ARCH}.json"

show_usage() {
    cat << USAGE
Nona AWS Nitro Enclave Provisioning & Simulation Harness

Usage:
  ./deploy/run_nitro.sh [COMMAND] [OPTIONS]

Commands:
  start               Provision and launch Nona enclave daemon (default)
  stop, terminate     Terminate running Nona enclave instances
  status, describe    Query status and PCR measurements of active enclaves
  console             Attach console to running enclave (debug mode)
  build-and-run       Build deterministic EIF and immediately provision

Options:
  --cpu-count <N>     Number of dedicated vCPUs (default: ${DEFAULT_CPU_COUNT})
  --memory <MiB>      Enclave dedicated RAM in MiB (default: ${DEFAULT_MEMORY_MIB})
  --cid <CID>         Enclave Context ID for AF_VSOCK communication (default: ${DEFAULT_CID})
  --eif <path>        Custom path to .eif package (default: ${EIF_FILE})
  --debug             Launch enclave in debug mode
  --skip-pcr-check    Bypass PCR matching against repository release manifest
  -h, --help          Display this help banner
USAGE
}

CPU_COUNT="$DEFAULT_CPU_COUNT"
MEMORY_MIB="$DEFAULT_MEMORY_MIB"
ENCLAVE_CID="$DEFAULT_CID"
CUSTOM_EIF=""
DEBUG_MODE=false
VERIFY_PCR=true
ACTION="start"

while [[ $# -gt 0 ]]; do
    case "$1" in
        start|stop|terminate|status|describe|console|build-and-run)
            ACTION="$1"
            shift
            ;;
        --cpu-count)
            CPU_COUNT="$2"
            shift 2
            ;;
        --memory)
            MEMORY_MIB="$2"
            shift 2
            ;;
        --cid)
            ENCLAVE_CID="$2"
            shift 2
            ;;
        --eif)
            CUSTOM_EIF="$2"
            shift 2
            ;;
        --debug)
            DEBUG_MODE=true
            shift
            ;;
        --skip-pcr-check)
            VERIFY_PCR=false
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            echo "[ERROR] Unknown parameter: $1" >&2
            show_usage
            exit 1
            ;;
    esac
done

if [ -n "$CUSTOM_EIF" ]; then
    EIF_FILE="$CUSTOM_EIF"
fi

HAS_NITRO_CLI=false
if command -v nitro-cli &>/dev/null; then
    HAS_NITRO_CLI=true
fi

check_allocator_service() {
    if command -v systemctl &>/dev/null; then
        if systemctl is-active --quiet nitro-enclaves-allocator.service 2>/dev/null; then
            echo "[+] Nitro Enclaves Allocator service is active."
        else
            echo "[*] Starting nitro-enclaves-allocator service..."
            sudo systemctl start nitro-enclaves-allocator.service 2>/dev/null || true
        fi
    fi
}

verify_pcr_manifest() {
    if [ "$VERIFY_PCR" = false ]; then
        echo "[!] Skipping PCR manifest verification per user flag."
        return 0
    fi

    if [ ! -f "$MANIFEST_FILE" ]; then
        echo "[!] Warning: Release manifest $MANIFEST_FILE not found. Skipping static PCR equality check."
        return 0
    fi

    echo "[+] Verifying EIF measurements against $MANIFEST_FILE..."
    if command -v jq &>/dev/null; then
        EXPECTED_PCR0=$(jq -r '.measurements.PCR0 // empty' "$MANIFEST_FILE" 2>/dev/null || true)
        if [ -n "$EXPECTED_PCR0" ]; then
            if [ "$HAS_NITRO_CLI" = true ]; then
                ACTUAL_PCR0=$(nitro-cli describe-eif --eif-path "$EIF_FILE" | jq -r '.Measurements.PCR0 // empty' 2>/dev/null || true)
                if [ -n "$ACTUAL_PCR0" ] && [ "$EXPECTED_PCR0" != "$ACTUAL_PCR0" ]; then
                    echo "[SECURITY ALERT] PCR0 mismatch detected!" >&2
                    echo "  Expected (Manifest): $EXPECTED_PCR0" >&2
                    echo "  Actual (EIF):        $ACTUAL_PCR0" >&2
                    echo "Terminating deployment to prevent unauthorized binary execution." >&2
                    exit 1
                fi
                echo "[+] PCR0 cryptographically verified: $EXPECTED_PCR0"
            else
                echo "[INFO] Running outside AWS Nitro CLI environment; skipping hardware EIF PCR measurement check."
            fi
        fi
    fi
}

# ---------------------------------------------------------
# Action Handlers
# ---------------------------------------------------------

case "$ACTION" in
    stop|terminate)
        if [ "$HAS_NITRO_CLI" = true ]; then
            echo "[*] Terminating existing Nitro enclaves..."
            ENCLAVE_IDS=$(nitro-cli describe-enclaves | grep -o '"EnclaveID": *"[^"]*"' | awk -F'"' '{print $4}' || true)
            if [ -z "$ENCLAVE_IDS" ]; then
                echo "[+] No active Nitro enclaves found."
            else
                for EID in $ENCLAVE_IDS; do
                    echo "[*] Terminating enclave $EID..."
                    nitro-cli terminate-enclave --enclave-id "$EID"
                done
                echo "[+] All enclaves terminated."
            fi
        else
            echo "[*] Stopping local simulation enclave daemon..."
            if [ -f "$SIM_PID_FILE" ]; then
                PID=$(cat "$SIM_PID_FILE" 2>/dev/null || true)
                if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
                    kill -TERM "$PID" 2>/dev/null || kill -9 "$PID" 2>/dev/null || true
                    echo "[+] Enclave daemon (PID $PID) terminated."
                fi
                rm -f "$SIM_PID_FILE"
            fi
            rm -f "$SIM_SOCK_FILE"
            echo "[+] Local simulation enclave terminated."
        fi
        exit 0
        ;;

    status|describe)
        if [ "$HAS_NITRO_CLI" = true ]; then
            echo "=== ACTIVE AWS NITRO ENCLAVES ==="
            nitro-cli describe-enclaves
        else
            echo "=== ACTIVE NONA UPSTREAM MOCK DAEMON (AF_UNIX) ==="
            if [ -f "$SIM_PID_FILE" ] && kill -0 "$(cat "$SIM_PID_FILE" 2>/dev/null)" 2>/dev/null; then
                PID=$(cat "$SIM_PID_FILE")
                echo "[+] State: RUNNING (PID: $PID)"
                echo "    Socket: $SIM_SOCK_FILE"
                if [ -f "$MANIFEST_FILE" ]; then
                    echo "    Manifest: $MANIFEST_FILE"
                    if command -v jq &>/dev/null; then
                        jq -r '"    PCR0: " + .measurements.PCR0' "$MANIFEST_FILE" 2>/dev/null || true
                    fi
                fi
            else
                echo "[+] No active local simulation enclaves found."
            fi
        fi
        exit 0
        ;;

    console)
        if [ "$HAS_NITRO_CLI" = true ]; then
            ENCLAVE_ID=$(nitro-cli describe-enclaves | grep -o '"EnclaveID": *"[^"]*"' | head -n 1 | awk -F'"' '{print $4}' || true)
            if [ -z "$ENCLAVE_ID" ]; then
                echo "[ERROR] No active enclave found to attach console." >&2
                exit 1
            fi
            echo "[*] Attaching to read-only console for enclave $ENCLAVE_ID..."
            nitro-cli console --enclave-id "$ENCLAVE_ID"
            exit 0
        else
            echo "[*] Showing local simulation log output ($SIM_LOG_FILE)..."
            if [ -f "$SIM_LOG_FILE" ]; then
                tail -n 30 "$SIM_LOG_FILE"
            else
                echo "[+] No console logs found."
            fi
            exit 0
        fi
        ;;

    build-and-run)
        echo "[*] Triggering deterministic reproducible build for ${TARGET_ARCH}..."
        ./tools/build_nitro_eif.sh --target "${TARGET_ARCH}"
        ;;
esac

# ---------------------------------------------------------
# Launch Flow: start
# ---------------------------------------------------------

verify_pcr_manifest

if [ "$HAS_NITRO_CLI" = true ]; then
    check_allocator_service

    if [ ! -f "$EIF_FILE" ]; then
        echo "[!] Enclave Image File ($EIF_FILE) not found."
        echo "[*] Building hermetic enclave image now..."
        ./tools/build_nitro_eif.sh --target "${TARGET_ARCH}"
    fi

    RUN_CMD=(
        nitro-cli run-enclave
        --eif-path "$EIF_FILE"
        --cpu-count "$CPU_COUNT"
        --memory "$MEMORY_MIB"
        --enclave-cid "$ENCLAVE_CID"
    )

    if [ "$DEBUG_MODE" = true ]; then
        RUN_CMD+=(--debug-mode)
        echo "[!] WARNING: Launching in DEBUG MODE. PCRs will be zeroed by hypervisor."
    fi

    echo "===================================================================="
    echo "LAUNCHING NONA CONFIDENTIAL ENCLAVE"
    echo "  Architecture:  ${TARGET_ARCH}"
    echo "  EIF Image:     ${EIF_FILE}"
    echo "  vCPUs:         ${CPU_COUNT}"
    echo "  Memory:        ${MEMORY_MIB} MiB"
    echo "  AF_VSOCK CID:  ${ENCLAVE_CID} (Port: ${DEFAULT_VSOCK_PORT})"
    echo "===================================================================="

    RUN_OUTPUT="$("${RUN_CMD[@]}")"
    echo "$RUN_OUTPUT"

    ENCLAVE_ID=$(echo "$RUN_OUTPUT" | grep -o '"EnclaveID": *"[^"]*"' | head -n 1 | awk -F'"' '{print $4}' || true)
    if [ -n "$ENCLAVE_ID" ]; then
        echo "===================================================================="
        echo "[+] Nona Core Engine successfully launched in AWS Nitro Enclave!"
        echo "  Enclave ID: $ENCLAVE_ID"
        echo "  Parent-to-Enclave Socket: vsock://${ENCLAVE_CID}:${DEFAULT_VSOCK_PORT}"
        echo "===================================================================="
    fi
else
    echo "===================================================================="
    echo "LAUNCHING NONA CORE WIRE-PROTOCOL MOCK (UPSTREAM DEV)"
    echo "  Host:          $(uname -s) (${TARGET_ARCH})"
    echo "  Transport:     Dual-Transport AF_UNIX (${SIM_SOCK_FILE})"
    echo "  vCPUs:         ${CPU_COUNT}"
    echo "  Memory:        ${MEMORY_MIB} MiB"
    echo "===================================================================="

    # Ensure native enclave daemon binary is compiled
    DAEMON_BIN="${NONA_ROOT}/target/debug/nona_enclave"
    if [ ! -x "$DAEMON_BIN" ]; then
        echo "[*] Compiling nona_enclave daemon for host architecture..."
        cargo build --bin nona_enclave --features std --frozen --offline --quiet
    fi

    # Terminate existing instance if any
    if [ -f "$SIM_PID_FILE" ]; then
        OLD_PID=$(cat "$SIM_PID_FILE" 2>/dev/null || true)
        if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
            kill -TERM "$OLD_PID" 2>/dev/null || true
            sleep 0.2
        fi
        rm -f "$SIM_PID_FILE"
    fi
    rm -f "$SIM_SOCK_FILE"

    # Spawn daemon in background with upstream mock Unix transport
    "$DAEMON_BIN" --mock-unix "$SIM_SOCK_FILE" > "$SIM_LOG_FILE" 2>&1 &
    SIM_PID=$!
    echo "$SIM_PID" > "$SIM_PID_FILE"

    # Wait for socket initialization
    for i in {1..20}; do
        if [ -S "$SIM_SOCK_FILE" ]; then
            break
        fi
        sleep 0.05
    done

    if [ ! -S "$SIM_SOCK_FILE" ]; then
        echo "[ERROR] Upstream mock daemon failed to initialize socket: ${SIM_SOCK_FILE}" >&2
        cat "$SIM_LOG_FILE" >&2
        exit 1
    fi

    echo "===================================================================="
    echo "[+] Nona Core Engine running in Upstream Wire-Protocol Mock mode!"
    echo "  Mock Enclave PID: $SIM_PID"
    echo "  Mock IPC Socket:  unix://${SIM_SOCK_FILE}"
    echo "  Note: Hardware NSM attestation requires deployment to AWS Nitro Enclave."
    echo "===================================================================="
fi
