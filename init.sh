#!/bin/sh
set -e
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
echo "[INIT] Nona Confidential Enclave Runtime Initialized"
echo "[INIT] Launching AF_VSOCK Listener on Port 5005..."
exec /bin/nona_enclave
