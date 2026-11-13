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

if [ "$ERRORS" -gt 0 ]; then
    echo "=========================================================="
    echo "[HYGIENE SUITE FAILED] Total violations detected: $ERRORS"
    echo "=========================================================="
    exit 1
fi

echo "=========================================================="
echo "ALL CODE REVIEW & HYGIENE CHECKS PASSED: REPOSITORY CLEAN"
echo "=========================================================="
