#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo "RUNNING AUTOMATED CODE REVIEW & HYGIENE TEST SUITE"
echo "=========================================================="

ERRORS=0

echo "--> Check 1: Inspecting for AI header banners & syntax narration..."
BANNERS=$(grep -rn -E "(//[[:space:]]*PROJECT:[[:space:]]*Nona Core Engine|//[[:space:]]*MODULE:.*-)" src/ src/bin/ benches/ || true)
if [ -n "$BANNERS" ]; then
    echo "  [HYGIENE FAILURE] Found mechanical header banners:"
    echo "$BANNERS"
    ERRORS=$((ERRORS + 1))
fi

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
# Check 8: Dependency License & Copyleft Contamination Audit
# ---------------------------------------------------------
echo "--> Check 8: Auditing dependencies for Copyleft/GPL contamination..."
COPYLEFT_HITS=$(cargo metadata --format-version 1 2>/dev/null | grep -iE "\"license\":\s*\"[^\"]*(gpl|agpl|lgpl)" || true)
if [ -n "$COPYLEFT_HITS" ]; then
    echo "  [LEGAL VIOLATION] Detected copyleft license in dependency tree:"
    echo "$COPYLEFT_HITS"
    ERRORS=$((ERRORS + 1))
else
    echo "  ✓ Zero copyleft (GPL/AGPL) dependencies detected in build graph."
fi


# ---------------------------------------------------------
# Check 9: Dead Code, Orphaned Source Files & Blanket Suppressions
# ---------------------------------------------------------
echo "--> Check 9: Auditing for true dead code, orphaned modules, and blanket suppressions..."

# 1. Prohibit blanket crate-level #![allow(dead_code)]
BLANKET_DEAD=$(grep -rn "#\!\[allow(dead_code)\]" src/ || true)
if [ -n "$BLANKET_DEAD" ]; then
    echo "  [HYGIENE FAILURE] Found blanket #![allow(dead_code)] hiding potential dead code:"
    echo "$BLANKET_DEAD"
    ERRORS=$((ERRORS + 1))
else
    echo "  ✓ Zero blanket #![allow(dead_code)] suppressions found in src/."
fi

# 2. Check for orphaned Rust files not referenced in lib.rs or binaries
for rs in $(find src -name "*.rs" | grep -v "lib.rs" | grep -v "bin/"); do
    mod_name=$(basename "$rs" .rs)
    if [ "$mod_name" != "mod" ]; then
        if ! grep -rq "mod $mod_name;" src/; then
            echo "  [ORPHAN FILE FAILURE] Source file $rs is never declared as a module in src/!"
            ERRORS=$((ERRORS + 1))
        fi
    fi
done

# 3. Enforce strict dead code rejection across the library build graph
DEAD_WARNINGS=$(cargo check --lib --no-default-features 2>&1 | grep "warning: .* is never used" || true)
if [ -n "$DEAD_WARNINGS" ]; then
    echo "  [DEAD CODE WARNING] Detected unused code in core library:"
    echo "$DEAD_WARNINGS"
    ERRORS=$((ERRORS + 1))
else
    echo "  ✓ Zero unused items detected in core library compilation."
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
