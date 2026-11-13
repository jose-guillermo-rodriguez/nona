#!/usr/bin/env bash
set -euo pipefail

echo "================================================================="
echo "NONA REPOSITORY: DOCUMENTATION & CODE ALIGNMENT AUDIT"
echo "================================================================="

echo ""
echo "[AUDIT 1] Dynamic Verus theorem count parity & regression scan..."

# 1. Parse dynamic ground truth from proofs/verus_verification.log
if [ -f "proofs/verus_verification.log" ]; then
    DYNAMIC_VERIFIED=$(grep -oE "verification results:: [0-9]+ verified" proofs/verus_verification.log | awk "{sum += \$3} END {print sum}")
    echo "  [*] Verified SMT targets aggregated from log: ${DYNAMIC_VERIFIED}"
    
    # 2. Assert positive synchronization across core documentation
    for doc in README.md SPECIFICATION.md SECURITY.md; do
        if ! grep -qE "${DYNAMIC_VERIFIED}.*(SMT|theorems|targets|verified|formal)" "$doc"; then
            echo "  [!] ERROR: $doc does not reflect active proof ground-truth (${DYNAMIC_VERIFIED})!" >&2
            exit 1
        fi
    done
    echo "  ✓ Positive sync: README.md, SPECIFICATION.md, and SECURITY.md match live proof log (${DYNAMIC_VERIFIED} targets)."
fi

# 3. Fail-closed negative check for legacy milestone regressions
STALE_HITS=$(grep -rnE "(111\s*theorems|111/111|111\s*targets|111\s*SMT|111\s*proofs|121\s*theorems|121/121|121\s*targets|121\s*SMT|121\s*proofs)" docs/ SPECIFICATION.md README.md SECURITY.md src/ || true)
if [ -n "$STALE_HITS" ]; then
    echo "  [!] ERROR: Stale legacy milestone references detected:" >&2
    echo "$STALE_HITS" >&2
    exit 1
fi
echo "  ✓ Clean: Zero stale milestone references (111 / 121) found."

echo ""
echo "[AUDIT 2] Scanning for coordinate terminology ('Jacobian')..."
grep -rnEi "jacobian" docs/ SPECIFICATION.md README.md include/ || echo "  ✓ Clean: No 'Jacobian' terminology in documentation."

echo ""
echo "[AUDIT 3] Auditing TCB external_body / axiom counts..."
CODE_EXTERNAL_COUNT=$(grep -rnE "^[[:space:]]*#\[verifier::external_body\]" src/ | wc -l | tr -d ' ')
echo "  [*] Live #[verifier::external_body] attributes in src/: $CODE_EXTERNAL_COUNT"
if [ "$CODE_EXTERNAL_COUNT" -ne 7 ]; then
  echo "  [!] FAIL: Live TCB external_body count ($CODE_EXTERNAL_COUNT) diverges from SPECIFICATION.md §4.5.1 (7)."
  exit 1
fi
grep -rnE "(external_body|axiom|unverified perimeter)" docs/TCB.md SPECIFICATION.md || true

echo ""
echo "[AUDIT 4] Checking feature flag consistency ('host-defense')..."
grep -rn "host-defense" docs/ SPECIFICATION.md || echo "  [!] Warning: 'host-defense' not explicitly documented in docs/ or SPECIFICATION.md."

echo ""
echo "[AUDIT 5] Checking C-ABI status code parity between include/nona.h and SPECIFICATION.md..."
python3 tools/check_status_parity.py

echo ""
echo "[AUDIT 6] Checking Dudect / timing neutrality statements across docs..."
grep -rnE "(dudect|Welch|timing neutrality|side-channel)" docs/ SPECIFICATION.md

echo ""
echo "================================================================="
echo "DOCUMENTATION AUDIT SWEEP COMPLETE"
echo "================================================================="
