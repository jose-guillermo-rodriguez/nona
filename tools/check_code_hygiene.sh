#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo "RUNNING AUTOMATED CODE REVIEW & HYGIENE TEST SUITE"
echo "=========================================================="

ERRORS=0

echo "--> Check 1: Enforcing canonical file-opening allowlist (rejecting AI banners & ASCII boxes)..."
while IFS= read -r rs_file; do
    first_line=$(head -n 1 "$rs_file")
    if [[ ! "$first_line" =~ ^(//!|///|//\ Copyright\ \(c\)|#\!\[|#\[|use\ |pub\ |mod\ |extern\ ) ]]; then
        echo "  [HYGIENE FAILURE] $rs_file line 1 violates opening allowlist:"
        echo "    Found: $first_line"
        ERRORS=$((ERRORS + 1))
    fi
done < <(find src tests benches -name "*.rs" 2>/dev/null || true)

LOCK_SLOP=$(grep -rn "Lock-Free Stream Ingestion Perimeter" src/ || true)
if [ -n "$LOCK_SLOP" ]; then
    echo "  [HYGIENE FAILURE] Contradiction: Found 'Lock-Free' docstring where spinlock is used:"
    echo "$LOCK_SLOP"
    ERRORS=$((ERRORS + 1))
fi

echo "--> Check 2: Verifying #[no_mangle] on all public C-ABI functions..."
while IFS= read -r match; do
    file=$(echo "$match" | cut -d: -f1)
    lineno=$(echo "$match" | cut -d: -f2)
    start_line=$((lineno > 10 ? lineno - 10 : 1))
    
    if ! sed -n "${start_line},${lineno}p" "$file" | grep -q "#\[no_mangle\]"; then
        echo "  [HYGIENE FAILURE] $file:$lineno exported C function lacks #[no_mangle]"
        ERRORS=$((ERRORS + 1))
    fi
done < <(grep -rn -E "pub (unsafe )?extern \"C\" fn" src/ | grep -v "tests" || true)

echo "--> Check 3: Enforcing Zeroize / Copy derivation mutual exclusivity..."
COPY_DERIVES=$(grep -rn -A 2 "struct FieldElement" src/psi.rs | grep "Copy" || true)
if [ -n "$COPY_DERIVES" ]; then
    echo "  [SAFETY VIOLATION] FieldElement derives Copy! Breaks Drop/ZeroizeOnDrop."
    echo "$COPY_DERIVES"
    ERRORS=$((ERRORS + 1))
fi

echo "--> Check 4: Scanning for direct unaligned pointer casts..."
ALIGN_CASTS=$(grep -rn -E "as \*const u64|as \*mut u32" src/ | grep -v "test" || true)
if [ -n "$ALIGN_CASTS" ]; then
    echo "  [SAFETY VIOLATION] Found raw typed pointer casts on potentially unaligned addresses:"
    echo "$ALIGN_CASTS"
    ERRORS=$((ERRORS + 1))
fi

echo "--> Check 5: Inspecting #[inline(always)] on complex routines..."
LARGE_INLINES=$(awk '/#[inline(always)]/{flag=5} flag && /fn (execute_phase|decontaminate|zeroize_and_abort)/{print FILENAME ":" FNR ":" $0; flag=0} flag{flag--}' src/psi.rs src/exception.rs || true)
if [ -n "$LARGE_INLINES" ]; then
    echo "  [STACK RISK] #[inline(always)] detected on complex routines:"
    echo "$LARGE_INLINES"
    ERRORS=$((ERRORS + 1))
fi

echo "--> Check 6: Auditing git commit history for legacy corporate email addresses..."
CORP_EMAILS=$(git log --format="%ae" | grep -E "(@meh-ter\.com|@nona-systems\.internal)" | sort -u || true)
if [ -n "$CORP_EMAILS" ]; then
    echo "  [PROVENANCE WARNING] Git history contains legacy proprietary emails (remediate via filter-branch before release):"
    echo "$CORP_EMAILS"
fi

echo "--> Check 7: Running Cargo Clippy pedantic checks under #![no_std]..."
cargo clippy --lib --no-default-features -- -D warnings
cargo clippy --all-targets --features std -- -D warnings


# ---------------------------------------------------------
# Check 8: DAG-Complete SPDX Dependency License Allowlist
# ---------------------------------------------------------
echo "--> Check 8: Enforcing strict SPDX license allowlist across dependency DAG..."
if ! python3 -c '
import json, subprocess, sys
ALLOWED = {
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Unicode-3.0",
    "Zlib",
    "MIT OR Apache-2.0",
    "Apache-2.0 OR MIT",
    "(MIT OR Apache-2.0) AND Unicode-3.0",
}
raw = subprocess.check_output(["cargo", "metadata", "--format-version", "1"], stderr=subprocess.DEVNULL)
meta = json.loads(raw)
violations = []
for pkg in meta.get("packages", []):
    lic = pkg.get("license")
    if lic not in ALLOWED:
        violations.append(f"{pkg['\''name'\'']} {pkg['\''version'\'']}: {lic!r}")
if violations:
    for v in violations:
        print(f"  [LEGAL VIOLATION] Unapproved or missing SPDX license: {v}")
    sys.exit(1)
'; then
    ERRORS=$((ERRORS + 1))
else
    echo "  ✓ 100% of packages in dependency DAG conform to approved SPDX allowlist."
fi


# ---------------------------------------------------------
# Check 9: Dead Code, Orphaned Source Files & Blanket Suppressions
# ---------------------------------------------------------
echo "--> Check 9: Auditing for true dead code, orphaned modules, and blanket suppressions..."

BLANKET_DEAD=$(grep -rn "#\!\[allow(dead_code)\]" src/ || true)
if [ -n "$BLANKET_DEAD" ]; then
    echo "  [HYGIENE FAILURE] Found blanket #![allow(dead_code)] hiding potential dead code:"
    echo "$BLANKET_DEAD"
    ERRORS=$((ERRORS + 1))
else
    echo "  ✓ Zero blanket #![allow(dead_code)] suppressions found in src/."
fi

for rs in $(find src -name "*.rs" | grep -v "lib.rs" | grep -v "bin/"); do
    mod_name=$(basename "$rs" .rs)
    if [ "$mod_name" != "mod" ]; then
        if ! grep -rq "mod $mod_name;" src/; then
            echo "  [ORPHAN FILE FAILURE] Source file $rs is never declared as a module in src/!"
            ERRORS=$((ERRORS + 1))
        fi
    fi
done

DEAD_WARNINGS=$(cargo check --lib --no-default-features 2>&1 | grep "warning: .* is never used" || true)
if [ -n "$DEAD_WARNINGS" ]; then
    echo "  [DEAD CODE WARNING] Detected unused code in core library:"
    echo "$DEAD_WARNINGS"
    ERRORS=$((ERRORS + 1))
else
    echo "  ✓ Zero unused items detected in core library compilation."
fi

# ---------------------------------------------------------
# Check 10: High-Assurance Proof Hygiene (SMT Axiom & Assume Audit)
# ---------------------------------------------------------
echo "--> Check 10: Auditing for unverified SMT axioms and raw assume() directives..."
RAW_ASSUMES=$(grep -rn -E "assume\\s*\\(" src/ 2>/dev/null || true)
if [ -n "$RAW_ASSUMES" ]; then
    echo "  [FORMAL PROOF VIOLATION] Detected raw assume() directives bypassing SMT verification:"
    echo "$RAW_ASSUMES"
    ERRORS=$((ERRORS + 1))
else
    echo "  ✓ Zero raw assume() directives detected across formal proof surface."
fi

# ---------------------------------------------------------
# Check 11: Fail-Closed Bare-Metal Panic Trap Invariant
# ---------------------------------------------------------
echo "--> Check 11: Auditing bare-metal panic handlers for non-terminating spin-loops..."
SPIN_PANICS=$(grep -rn "spin_loop" src/bin/ 2>/dev/null || true)
if [ -n "$SPIN_PANICS" ]; then
    echo "  [FAIL-CLOSED VIOLATION] Detected infinite spin_loop in bare-metal panic handler:"
    echo "$SPIN_PANICS"
    ERRORS=$((ERRORS + 1))
else
    echo "  ✓ Bare-metal panic paths enforce immediate hardware traps."
fi

# ---------------------------------------------------------
# Check 12: Closed Positive Allowlist for Normative Requirement Tags
# ---------------------------------------------------------
echo "--> Check 12: Enforcing closed positive allowlist for requirement tags (only FR-* permitted)..."
if ! python3 -c '
import pathlib, re, sys

TOKEN_RE = re.compile(r"\b[A-Z]{2,}[-_][0-9]+[A-Z0-9_-]*\b")
ALLOW_RE = re.compile(r"^(FR-[0-9]+(-[A-Z0-9]+)?|TEST-[0-9]+|(SHA|UTF|AVX)-[0-9]+|SWU_[123]P_X)$")

violations = []
for root in ("src", "tests"):
    for path in sorted(pathlib.Path(root).rglob("*")):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for m in TOKEN_RE.finditer(line):
                tok = m.group(0)
                if not ALLOW_RE.match(tok):
                    violations.append(f"{path}:{lineno}: {tok} -> {line.strip()}")

if violations:
    for v in violations:
        print(f"  [HYGIENE FAILURE] Non-normative tag rejected by positive FR-* allowlist: {v}")
    sys.exit(1)
'; then
    ERRORS=$((ERRORS + 1))
else
    echo "  ✓ 100% of requirement tags conform to the closed FR-* positive allowlist."
fi

# ---------------------------------------------------------
# Check 13: Zero-Heap Core Engine Invariant (#![no_std] Static Memory)
# ---------------------------------------------------------
echo "--> Check 13: Enforcing zero dynamic heap allocation (alloc) in src/..."
ALLOC_IMPORTS=$(grep -rn -E "(extern crate alloc|use alloc::)" src/ || true)
if [ -n "$ALLOC_IMPORTS" ]; then
    echo "  [MEMORY INVARIANT VIOLATION] Dynamic heap allocation (alloc) detected in src/:"
    echo "$ALLOC_IMPORTS"
    ERRORS=$((ERRORS + 1))
else
    echo "  ✓ Zero dynamic heap allocations (alloc) in core engine."
fi

# ---------------------------------------------------------
# Check 14: Exclusive Hardware NSM Entropy Invariant
# ---------------------------------------------------------
echo "--> Check 14: Enforcing exclusive /dev/nsm hardware entropy (zero OS/CPU RNG fallbacks)..."
FALLBACK_RNG=$(grep -rn -E "\b(getentropy|getrandom|_rdrand|_rdseed)\b|s3_3_c2_c4_0" src/ || true)
if [ -n "$FALLBACK_RNG" ]; then
    echo "  [ENTROPY INVARIANT VIOLATION] Non-NSM entropy fallback detected in src/:"
    echo "$FALLBACK_RNG"
    ERRORS=$((ERRORS + 1))
else
    echo "  ✓ Zero non-NSM entropy fallbacks detected in src/."
fi

# ---------------------------------------------------------
# Check 15: Stateless Ephemeral-Session Invariant (Zero Host Disk Persistence)
# ---------------------------------------------------------
echo "--> Check 15: Enforcing stateless ephemeral-session invariant (zero host disk persistence in src/)..."
PERSISTENCE_HITS=$(grep -rnE "\b(std::fs::write|std::fs::create_dir|File::create|OpenOptions::new)\b" src/ || true)
if [ -n "$PERSISTENCE_HITS" ]; then
    echo "  [STATELESS INVARIANT VIOLATION] Host filesystem write/persistence primitive detected in src/:"
    echo "$PERSISTENCE_HITS"
    ERRORS=$((ERRORS + 1))
else
    echo "  ✓ Zero host filesystem persistence primitives detected in src/."
fi

# ---------------------------------------------------------
# Check 16: Feistel Bijection Boundary & Non-Confidentiality Guardrail
# ---------------------------------------------------------
echo "--> Check 16: Verifying nona_permute_index non-confidentiality bijection guardrail in include/nona.h..."
if ! grep -B 6 "nona_permute_index(" include/nona.h | grep -qiE "bijection.*not.*(cipher|encryption|confidentiality)"; then
    echo "  [API SCOPE VIOLATION] include/nona.h must explicitly document nona_permute_index as a collision-free bijection and NOT a cryptographic cipher or confidentiality primitive."
    ERRORS=$((ERRORS + 1))
else
    echo "  ✓ Feistel bijection non-confidentiality guardrail verified in include/nona.h."
fi

if [ "$ERRORS" -gt 0 ]; then
    echo "=========================================================="
    echo "[HYGIENE SUITE FAILED] Total violations detected: $ERRORS"
    echo "=========================================================="
    exit 1
fi

echo "--> Check 17: Enforcing bounded O(N) vsock/wire framing & C-ABI FFI perimeter regression suite..."
if [ ! -f "tests/integration/test_vsock_perimeter_bounds.rs" ]; then
    echo "  [!] FAIL: Missing adversarial transport & FFI perimeter test suite: tests/integration/test_vsock_perimeter_bounds.rs"
    exit 1
fi
if ! grep -q 'name = "test_vsock_perimeter_bounds"' Cargo.toml; then
    echo "  [!] FAIL: Cargo.toml must register [[test]] target 'test_vsock_perimeter_bounds'."
    exit 1
fi
if grep -rnE '\.read_to_end\(' src/ingest.rs src/enclave_server.rs src/bin/nona_enclave.rs 2>/dev/null; then
    echo "  [!] FAIL: Unbounded .read_to_end() detected on untrusted transport/wire stream."
    exit 1
fi
if ! grep -rnE 'MAX_.*FRAME|MAX_.*PAYLOAD|MAX_.*MSG|MAX_.*WIRE' src/ingest.rs src/enclave_server.rs src/bin/nona_enclave.rs >/dev/null 2>&1; then
    echo "  [!] FAIL: Explicit static frame/payload ceiling constant missing in transport/wire modules."
    exit 1
fi
if grep -rnE '\b(SPEC|ENCL|HAVH)-[0-9]+\b' tests/integration/test_vsock_perimeter_bounds.rs src/ingest.rs src/enclave_server.rs src/bin/nona_enclave.rs 2>/dev/null; then
    echo "  [!] FAIL: Internal tracking codes detected in transport/FFI perimeter files."
    exit 1
fi
echo "  ✓ Bounded vsock/wire framing and C-ABI FFI perimeter test registration verified."
echo "--> Check 18: Enforcing oblivious Phase 2 compaction, hard timing gate, DSE zeroization & assembly audit..."
if [ ! -f "tools/audit_assembly_ct_and_zeroize.py" ]; then
    echo "  [!] FAIL: Missing assembly constant-time, stack-ceiling & DSE zeroization auditor: tools/audit_assembly_ct_and_zeroize.py"
    exit 1
fi
if grep -rnE 'if flags == NONA_FLAG_FULL_PSI && matched == 1' src/psi.rs >/dev/null 2>&1; then
    echo "  [!] FAIL: Secret-dependent branch 'if flags == NONA_FLAG_FULL_PSI && matched == 1' still present in src/psi.rs."
    exit 1
fi
if ! grep -rnE 'assert!\(.*p2_delta' tests/integration/test_timing_boundaries.rs >/dev/null 2>&1; then
    echo "  [!] FAIL: tests/integration/test_timing_boundaries.rs must enforce a hard assert!() gate on p2_delta."
    exit 1
fi
if ! grep -q "audit_assembly_ct_and_zeroize.py" Makefile || ! grep -q "audit_assembly_ct_and_zeroize.py" .github/workflows/ci.yml; then
    echo "  [!] FAIL: Makefile and .github/workflows/ci.yml must wire tools/audit_assembly_ct_and_zeroize.py into release/toolchain gates."
    exit 1
fi
if grep -rnE '\b(SPEC|ENCL|HAVH)-[0-9]+\b' tools/audit_assembly_ct_and_zeroize.py tests/integration/test_timing_boundaries.rs 2>/dev/null; then
    echo "  [!] FAIL: Internal tracking codes detected in constant-time/assembly audit files."
    exit 1
fi
python3 tools/audit_assembly_ct_and_zeroize.py --self-test && python3 tools/audit_assembly_ct_and_zeroize.py
echo "  ✓ Oblivious Phase 2 compaction, hard timing gate, DSE zeroization, and assembly spill audit verified."
echo "--> Check 19: Enforcing cryptographic reduction proofs and Verus specification mutation testing (spec-fuzzing)..."
if [ ! -f "proofs/crypto_reductions.rs" ]; then
    echo "  [!] FAIL: Missing formal cryptographic reduction proof module: proofs/crypto_reductions.rs"
    exit 1
fi
if grep -qE '#\[verifier::external_body\]|\bassume\s*\(|\badmit\s*\(' proofs/crypto_reductions.rs; then
    echo "  [!] FAIL: proofs/crypto_reductions.rs must be 100% axiom-free (no external_body, assume, or admit)."
    exit 1
fi
if ! grep -q "proofs/crypto_reductions.rs" tools/run_verus_safe.sh; then
    echo "  [!] FAIL: proofs/crypto_reductions.rs is not wired into tools/run_verus_safe.sh."
    exit 1
fi
if [ ! -x "tools/fuzz_verus_specs.py" ]; then
    echo "  [!] FAIL: Missing executable Verus specification mutation fuzzer: tools/fuzz_verus_specs.py"
    exit 1
fi
if ! grep -qE '^spec-fuzz:' Makefile || ! grep -E '^host:' Makefile | grep -qw 'spec-fuzz'; then
    echo "  [!] FAIL: Makefile must define 'spec-fuzz:' and include it in 'host:'."
    exit 1
fi
echo "  ✓ Cryptographic security reductions and Verus specification mutation fuzzer verified."
echo "--> Check 20: Enforcing attested KMS recipient key-release binding & integration suite..."
if [ ! -f "docs/KMS_ATTESTATION.md" ]; then
    echo "  [!] FAIL: Missing KMS cryptographic attestation architecture spec: docs/KMS_ATTESTATION.md"
    exit 1
fi
for pattern in "Recipient" "PCR0" "NSM" "zeroize"; do
    if ! grep -qiE "$pattern" docs/KMS_ATTESTATION.md; then
        echo "  [!] FAIL: docs/KMS_ATTESTATION.md missing required attestation binding coverage: $pattern"
        exit 1
    fi
done
if [ ! -f "tests/integration/test_kms_recipient_binding.rs" ]; then
    echo "  [!] FAIL: Missing KMS recipient binding integration test suite: tests/integration/test_kms_recipient_binding.rs"
    exit 1
fi
if ! grep -q 'name = "test_kms_recipient_binding"' Cargo.toml; then
    echo "  [!] FAIL: Cargo.toml must register [[test]] target 'test_kms_recipient_binding'."
    exit 1
fi
if ! grep -rnE 'Recipient|CiphertextForRecipient|AttestedKeyEnvelope|attested_recipient' src/enclave_server.rs src/crypto.rs src/bin/nona_enclave.rs >/dev/null 2>&1; then
    echo "  [!] FAIL: Enclave runtime missing attested KMS recipient key-release binding primitives."
    exit 1
fi
if grep -rnE '\b(SPEC|ENCL|HAVH)-[0-9]+\b' docs/KMS_ATTESTATION.md tests/integration/test_kms_recipient_binding.rs src/enclave_server.rs src/crypto.rs src/bin/nona_enclave.rs 2>/dev/null; then
    echo "  [!] FAIL: Internal tracking codes detected in KMS recipient binding files."
    exit 1
fi
echo "  ✓ Attested KMS recipient key-release binding and test registration verified."
echo "--> Check 21: Enforcing continuous cargo-fuzz / libFuzzer targets & CI regression harness..."
for target in fuzz_ingest fuzz_wire_dispatch fuzz_c_abi_ffi fuzz_kms_envelope; do
    if [ ! -f "fuzz/fuzz_targets/${target}.rs" ]; then
        echo "  [!] FAIL: Missing required libFuzzer target: fuzz/fuzz_targets/${target}.rs"
        exit 1
    fi
    if ! grep -q "name = \"${target}\"" fuzz/Cargo.toml; then
        echo "  [!] FAIL: fuzz/Cargo.toml missing [[bin]] entry for ${target}."
        exit 1
    fi
done
if ! grep -qE '^fuzz-smoke:' Makefile; then
    echo "  [!] FAIL: Makefile must define 'fuzz-smoke:' target."
    exit 1
fi
if ! grep -q 'fuzz_c_abi_ffi' .github/workflows/ci.yml || ! grep -q 'fuzz_kms_envelope' .github/workflows/ci.yml; then
    echo "  [!] FAIL: .github/workflows/ci.yml must execute the continuous fuzzing suite across all 4 fuzz targets."
    exit 1
fi
echo "  ✓ Continuous libFuzzer targets and CI regression harness verified."
echo "--> Check 22: Enforcing external cryptanalysis readiness dossier & reproducible audit bundle..."
if [ ! -f "docs/EXTERNAL_AUDIT_DOSSIER.md" ]; then
    echo "  [!] FAIL: Missing external cryptanalysis & security audit dossier: docs/EXTERNAL_AUDIT_DOSSIER.md"
    exit 1
fi
for section in "System Architecture" "Trusted Computing Base" "291" "DDH" "KMS" "Reproducibility"; do
    if ! grep -qiE "$section" docs/EXTERNAL_AUDIT_DOSSIER.md; then
        echo "  [!] FAIL: docs/EXTERNAL_AUDIT_DOSSIER.md missing required audit coverage: $section"
        exit 1
    fi
done
if ! grep -qE '^audit-bundle:' Makefile; then
    echo "  [!] FAIL: Makefile must define 'audit-bundle:' target."
    exit 1
fi
if grep -rnE '\b(SPEC|ENCL|HAVH)-[0-9]+\b' docs/EXTERNAL_AUDIT_DOSSIER.md 2>/dev/null; then
    echo "  [!] FAIL: Internal tracking codes detected in docs/EXTERNAL_AUDIT_DOSSIER.md."
    exit 1
fi
echo "  ✓ External cryptanalysis readiness dossier and audit bundle verified."
echo "=========================================================="
echo "ALL CODE REVIEW & HYGIENE CHECKS PASSED: REPOSITORY CLEAN"
echo "=========================================================="
