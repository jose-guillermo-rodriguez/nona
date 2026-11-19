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
MAX_EXTERNAL_AXIOMS=$(python3 -c 'import json; print(json.load(open("assurance_policy.json"))["thresholds"]["max_external_body_axioms"])')
echo "  [*] Live #[verifier::external_body] attributes in src/: $CODE_EXTERNAL_COUNT (policy ceiling: $MAX_EXTERNAL_AXIOMS)"
if [ "$CODE_EXTERNAL_COUNT" -gt "$MAX_EXTERNAL_AXIOMS" ]; then
  echo "  [!] FAIL: Live TCB external_body count ($CODE_EXTERNAL_COUNT) exceeds assurance_policy.json ceiling ($MAX_EXTERNAL_AXIOMS)." >&2
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

echo ""
echo "[AUDIT 7] Enforcing cross-repository version parity & non-mutating EIF manifest hygiene..."
CRATE_VERSION=$(grep -m1 '^version = ' Cargo.toml | sed -E 's/version = "([^"]+)"/\1/')
echo "  [*] Canonical Cargo.toml crate version: v${CRATE_VERSION}"

if grep -qE 'v2\.0\.0' tools/build_nitro_eif.sh; then
    echo "  [!] FAIL: tools/build_nitro_eif.sh contains stale hardcoded version 'v2.0.0' (expected v${CRATE_VERSION})." >&2
    exit 1
fi

if grep -qE 'MANIFEST_OUTPUT="\$\{MANIFEST_DIR\}/enclave_manifest_' tools/build_nitro_eif.sh; then
    echo "  [!] FAIL: tools/build_nitro_eif.sh writes generated manifests directly into tracked manifests/ instead of target/." >&2
    exit 1
fi

if ! grep -q -- '--bless-manifest' tools/build_nitro_eif.sh; then
    echo "  [!] FAIL: tools/build_nitro_eif.sh lacks an explicit --bless-manifest flag and fail-closed PCR verification gate." >&2
    exit 1
fi
python3 - "$CRATE_VERSION" <<'PYEOF'
import json, re, sys
from pathlib import Path

expected_version = sys.argv[1]
hex96 = re.compile(r"^[0-9a-f]{96}$")

for rel in ("manifests/enclave_manifest_x86_64.json", "manifests/enclave_manifest.json"):
    p = Path(rel)
    if not p.is_file():
        print(f"  [!] FAIL: Missing required reference manifest: {rel}", file=sys.stderr)
        sys.exit(1)
    data = json.loads(p.read_text())
    manifest_ver = data.get("crate_version") or data.get("version")
    if manifest_ver != expected_version:
        print(
            f"  [!] FAIL: {rel} version ({manifest_ver!r}) does not match Cargo.toml ({expected_version!r}).",
            file=sys.stderr,
        )
        sys.exit(1)
    size = data.get("binary_size_bytes", 0)
    if not isinstance(size, int) or size <= 54928 or size > 16777216:
        print(
            f"  [!] FAIL: {rel} binary_size_bytes ({size}) is stale (<= 54928) or out of bounds.",
            file=sys.stderr,
        )
        sys.exit(1)
    meas = data.get("measurements", {})
    for pcr in ("PCR0", "PCR1", "PCR2"):
        val = meas.get(pcr, "")
        if not isinstance(val, str) or not hex96.match(val):
            print(f"  [!] FAIL: {rel} has invalid SHA-384 digest for {pcr}: {val!r}", file=sys.stderr)
            sys.exit(1)
PYEOF
if [ "$CRATE_VERSION" = "1.0.2" ]; then
    if ! grep -q '^## \[1.0.2\]' CHANGELOG.md; then
        echo "  [!] FAIL: CHANGELOG.md missing [1.0.2] release entry." >&2
        exit 1
    fi
    if ! grep -q '"version": "1.0.2"' nona-core.cdx.json; then
        echo "  [!] FAIL: nona-core.cdx.json SBOM root component must reflect 1.0.2." >&2
        exit 1
    fi
fi
echo "  ✓ Version parity, manifest artifact freshness, and non-mutating EIF hygiene verified."



echo ""
echo "[AUDIT 8] Enforcing Lemniscate Assurance Ratchet (declarative policy, git monotonicity & introspection)..."
if [ ! -f "assurance_policy.json" ]; then
    echo "  [!] FAIL: Missing root declarative stage-gate contract: assurance_policy.json" >&2
    exit 1
fi
if [ ! -f "tools/verify_assurance_ratchet.py" ]; then
    echo "  [!] FAIL: Missing ratchet enforcement & introspection engine: tools/verify_assurance_ratchet.py" >&2
    exit 1
fi
if grep -qE '\[ "\$CODE_EXTERNAL_COUNT" -ne 7 \]' tools/audit_doc_alignment.sh; then
    echo "  [!] FAIL: tools/audit_doc_alignment.sh still hardcodes external_body == 7 instead of delegating to assurance_policy.json." >&2
    exit 1
fi
if ! grep -q "Lemniscate Assurance Ratchet" docs/HAVH.md || ! grep -q "assurance_policy.json" docs/HAVH.md; then
    echo "  [!] FAIL: docs/HAVH.md must document the Lemniscate Assurance Ratchet and assurance_policy.json." >&2
    exit 1
fi
if ! grep -q "Monotonic Assurance Ratchet" README.md || ! grep -q "assurance_policy.json" README.md; then
    echo "  [!] FAIL: README.md must document the Monotonic Assurance Ratchet and assurance_policy.json." >&2
    exit 1
fi
python3 tools/verify_assurance_ratchet.py
echo "  ✓ Lemniscate Assurance Ratchet verified (policy, git monotonicity, and dynamic symbol introspection)."


echo ""
echo "[AUDIT 9] Enforcing formal boundary & hardware semantic models (TLA+, STPA/PASTA host model, silicon memory ordering)..."
if [ ! -f "specs/vsock_session.tla" ] || [ ! -f "specs/vsock_session.cfg" ]; then
    echo "  [!] FAIL: Missing formal vsock session TLA+ model or TLC config (specs/vsock_session.tla, specs/vsock_session.cfg)." >&2
    exit 1
fi
for sym in Init Next Spec TypeInvariant DeadlockFreedom; do
    if ! grep -qE "\b${sym}\b" specs/vsock_session.tla; then
        echo "  [!] FAIL: specs/vsock_session.tla missing required formal specification symbol: ${sym}" >&2
        exit 1
    fi
done
if ! grep -qE "^verify-models:" Makefile; then
    echo "  [!] FAIL: Makefile missing 'verify-models' target for TLA+ model checking." >&2
    exit 1
fi
if [ ! -f "docs/HARDWARE_SEMANTICS.md" ]; then
    echo "  [!] FAIL: Missing silicon semantic gap analysis: docs/HARDWARE_SEMANTICS.md" >&2
    exit 1
fi
for pattern in "TSO" "aarch64" "speculative" "errata"; do
    if ! grep -qiE "$pattern" docs/HARDWARE_SEMANTICS.md; then
        echo "  [!] FAIL: docs/HARDWARE_SEMANTICS.md missing required hardware analysis coverage: $pattern" >&2
        exit 1
    fi
done
for pattern in "STPA" "PASTA" "time-warp" "L3"; do
    if ! grep -qiE "$pattern" docs/THREAT_MODEL.md; then
        echo "  [!] FAIL: docs/THREAT_MODEL.md missing adversarial host boundary coverage: $pattern" >&2
        exit 1
    fi
done
if grep -rnE "\b(SPEC|ENCL|HAVH)-[0-9]+\b" specs/ docs/HARDWARE_SEMANTICS.md docs/THREAT_MODEL.md Makefile; then
    echo "  [!] FAIL: Internal tracking codes detected in boundary/hardware specifications." >&2
    exit 1
fi
echo "  ✓ Formal TLA+ session model, STPA/PASTA host threat model, and silicon memory-ordering specs verified."

echo "================================================================="
echo "DOCUMENTATION AUDIT SWEEP COMPLETE"
echo "================================================================="
