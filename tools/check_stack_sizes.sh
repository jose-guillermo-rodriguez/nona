#!/usr/bin/env bash
# Copyright (c) 2026 Nona Contributors.
# Licensed under the Apache License, Version 2.0 or the MIT License.
#
# GATE 2: Fail-Closed Static Machine Stack Ceiling Audit
# Audits machine stack allocations against a strict 4096-byte ceiling.
# Enforces non-vacuous execution: fails if audited site cardinality < S_min.

set -euo pipefail

STACK_LIMIT_BYTES="${STACK_LIMIT_BYTES:-4096}"
MIN_ALLOCATION_SITES="${MIN_ALLOCATION_SITES:-100}"

echo "[GATE 2] Executing static machine stack frame ceiling audit (< ${STACK_LIMIT_BYTES} B)..."

# Ensure optimized release static library is current
cargo build --release --lib --quiet

TARGET_STATIC="target/release/libnona_core.a"
if [ ! -f "$TARGET_STATIC" ]; then
    echo "[GATE 2 FAILED] Required audit target '$TARGET_STATIC' does not exist." >&2
    exit 1
fi

python3 - "$TARGET_STATIC" "$STACK_LIMIT_BYTES" "$MIN_ALLOCATION_SITES" << 'PYEOF'
import sys, subprocess, re, os, shutil

TARGET = sys.argv[1]
LIMIT = int(sys.argv[2])
MIN_SITES = int(sys.argv[3])

inspected = []
violations = []

def audit_disassembly(cmd_args, arch):
    try:
        raw = subprocess.check_output(cmd_args, text=True, stderr=subprocess.PIPE)
    except Exception as e:
        print(f"[GATE 2 FAILED] Disassembly command failed ({' '.join(cmd_args)}): {e}", file=sys.stderr)
        sys.exit(1)

    # Multi-architecture stack frame decrement patterns
    aarch64_patterns = [
        re.compile(r"sub\s+sp,\s*sp,\s*#([0-9a-fx]+)", re.I),
        re.compile(r"stp\s+[wx\d]+,\s*[wx\d]+,\s*\[sp,\s*#-([0-9a-fx]+)\]!", re.I),
        re.compile(r"str\s+[wx\d]+,\s*\[sp,\s*#-([0-9a-fx]+)\]!", re.I),
    ]
    x86_patterns = [
        re.compile(r"sub\s+\$(0x[0-9a-f]+|[0-9]+),\s*%rsp", re.I),
        re.compile(r"sub\s+%rsp,\s*\$(0x[0-9a-f]+|[0-9]+)", re.I),
        re.compile(r"sub\s+rsp,\s*(0x[0-9a-f]+|[0-9]+)", re.I),
    ]

    patterns = aarch64_patterns if ("arm" in arch or "aarch64" in arch) else x86_patterns

    for line in raw.splitlines():
        for pat in patterns:
            m = pat.search(line)
            if m:
                v_str = m.group(1)
                sz = int(v_str, 16) if v_str.startswith(("0x", "0X")) else int(v_str)
                inspected.append((sz, line.strip()))
                if sz > LIMIT:
                    violations.append((sz, line.strip()))

def audit_elf_stack_sizes():
    readelf_bin = shutil.which("llvm-readelf") or shutil.which("readelf")
    if not readelf_bin:
        return False

    parsed_any = False
    for root, _, files in os.walk("target/release/deps"):
        for f in files:
            if f.endswith(".o"):
                obj_path = os.path.join(root, f)
                try:
                    res = subprocess.check_output([readelf_bin, "--stack-sizes", obj_path], text=True, stderr=subprocess.DEVNULL)
                    for rline in res.splitlines():
                        parts = rline.strip().split()
                        if len(parts) >= 2 and parts[0].isdigit():
                            sz = int(parts[0])
                            sym = parts[1]
                            inspected.append((sz, sym))
                            parsed_any = True
                            if sz > LIMIT:
                                violations.append((sz, f"Symbol {sym}"))
                except Exception:
                    continue
    return parsed_any

# Execution Strategy:
# 1. On Darwin: Execute native otool or objdump disassembly
# 2. On Linux: Try .stack_sizes sections first; fall back to objdump if uninstrumented (stable toolchain)
if sys.platform == "darwin":
    disasm_bin = shutil.which("otool")
    if disasm_bin:
        audit_disassembly([disasm_bin, "-tv", TARGET], "aarch64")
    else:
        objdump_bin = shutil.which("llvm-objdump") or shutil.which("objdump")
        if not objdump_bin:
            print("[GATE 2 FAILED] Neither 'otool' nor 'objdump' available on macOS host.", file=sys.stderr)
            sys.exit(1)
        audit_disassembly([objdump_bin, "-d", TARGET], "aarch64")
else:
    found_elf_sections = audit_elf_stack_sizes()
    if not found_elf_sections:
        objdump_bin = shutil.which("llvm-objdump") or shutil.which("objdump")
        if not objdump_bin:
            print("[GATE 2 FAILED] Linux build lacks .stack_sizes and no objdump available.", file=sys.stderr)
            sys.exit(1)
        machine = os.uname().machine.lower()
        audit_disassembly([objdump_bin, "-d", TARGET], machine)

# Enforce Invariant 1: Non-vacuous cardinality check
total = len(inspected)
if total < MIN_SITES:
    print(f"[GATE 2 FAILED] Vacuous audit failure: Only {total} frame allocation sites audited (required >= {MIN_SITES}).", file=sys.stderr)
    print("  Verify that compiler emitted symbols or disassembly tools are operational.", file=sys.stderr)
    sys.exit(1)

# Enforce Invariant 2: Stack frame size ceiling
if violations:
    print(f"[GATE 2 FAILED] {len(violations)} function frame(s) breached the {LIMIT}-byte ceiling:", file=sys.stderr)
    for sz, site in violations:
        print(f"  [BREACH] Allocates {sz} bytes: {site}", file=sys.stderr)
    sys.exit(1)

inspected.sort(key=lambda x: x[0], reverse=True)
max_sz, max_site = inspected[0]
print(f"  ✓ Stack ceiling invariant satisfied across {total} sites statically audited.")
print(f"    Maximum stack allocation: {max_sz} B <= {LIMIT} B ({max_site})")
PYEOF
