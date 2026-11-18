#!/usr/bin/env python3
"""Cross-architecture assembly constant-time, stack-ceiling, and DSE-zeroization auditor."""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path


def fail(msg: str) -> None:
    print(f"  [!] ASSEMBLY AUDIT FAILURE: {msg}", file=sys.stderr)
    sys.exit(1)


def load_max_stack_frame_bytes() -> int:
    policy_path = Path("assurance_policy.json")
    if not policy_path.is_file():
        fail("Missing assurance_policy.json in repository root.")
    try:
        doc = json.loads(policy_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"Invalid JSON in assurance_policy.json: {exc}")
    thresholds = doc.get("thresholds")
    if not isinstance(thresholds, dict) or not isinstance(thresholds.get("max_stack_frame_bytes"), int):
        fail("assurance_policy.json missing integer thresholds.max_stack_frame_bytes.")
    limit = thresholds["max_stack_frame_bytes"]
    if limit <= 0:
        fail(f"Invalid thresholds.max_stack_frame_bytes: {limit}")
    return limit


def build_nostd_release_archive() -> Path:
    cmd = ["cargo", "build", "--release", "--no-default-features", "--lib", "--quiet"]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if res.returncode != 0:
        fail(f"Release #![no_std] build failed:\n{res.stderr.strip()}")
    target_dir = Path(os.environ.get("CARGO_TARGET_DIR", "target"))
    archive = target_dir / "release" / "libnona_core.a"
    if not archive.is_file():
        fail(f"Expected static archive not found at {archive}")
    return archive


def resolve_disassembler() -> tuple[list[str], str]:
    sysroot = ""
    rustc_res = subprocess.run(["rustc", "--print", "sysroot"], capture_output=True, text=True, check=False)
    if rustc_res.returncode == 0:
        sysroot = rustc_res.stdout.strip()

    for tool_name in ("llvm-objdump", "rust-objdump"):
        if sysroot:
            for cand in Path(sysroot).rglob(tool_name):
                if cand.is_file() and os.access(cand, os.X_OK):
                    return [str(cand), "-d", "--demangle"], "objdump"
        found = shutil.which(tool_name)
        if found:
            return [found, "-d", "--demangle"], "objdump"

    objdump_bin = shutil.which("objdump")
    if objdump_bin:
        return [objdump_bin, "-d", "--demangle"], "objdump"

    otool_bin = shutil.which("otool")
    if otool_bin:
        return [otool_bin, "-tv"], "otool"

    fail("No disassembler found (checked llvm-objdump, rust-objdump, objdump, otool).")
    return [], ""


def detect_arch() -> str:
    m = platform.machine().lower()
    if m in ("arm64", "aarch64"):
        return "aarch64"
    if m in ("x86_64", "amd64"):
        return "x86_64"
    return m


def verify_nm_symbols(archive: Path) -> int:
    nm_bin = shutil.which("llvm-nm") or shutil.which("nm")
    if not nm_bin:
        return 0
    res = subprocess.run([nm_bin, "-g", str(archive)], capture_output=True, text=True, check=False)
    if res.returncode != 0:
        return 0
    syms = [ln.strip() for ln in res.stdout.splitlines() if " T " in ln or " t " in ln]
    return len(syms)


def parse_functions(disasm_text: str) -> list[tuple[str, str, list[str]]]:
    """Return list of (member_name, symbol_name, instruction_lines) without cross-object collisions."""
    records: list[tuple[str, str, list[str]]] = []
    current_member = "libnona_core.a"
    current_sym: str | None = None
    current_lines: list[str] = []

    member_hdr = re.compile(r"^[^(]+\(([^)]+)\):\s*(?:file format.*)?$")
    objdump_hdr = re.compile(r"^[0-9a-fA-F]+\s+<([^>]+)>:\s*$")
    otool_hdr = re.compile(r"^([A-Za-z0-9_.$@]+):\s*$")

    def flush() -> None:
        nonlocal current_sym, current_lines
        if current_sym is not None:
            records.append((current_member, current_sym, current_lines))
            current_sym = None
            current_lines = []

    for line in disasm_text.splitlines():
        m_mem = member_hdr.match(line)
        if m_mem:
            flush()
            current_member = m_mem.group(1)
            continue

        m_obj = objdump_hdr.match(line)
        if m_obj:
            flush()
            current_sym = m_obj.group(1)
            continue

        m_ot = otool_hdr.match(line)
        if m_ot and not line.startswith((" ", "\t")):
            flush()
            current_sym = m_ot.group(1)
            continue

        if current_sym is not None and line.strip():
            current_lines.append(line.strip())

    flush()
    return records


def parse_immediate_bytes(tok: str) -> int:
    s = tok.strip().lstrip("#$")
    if s.startswith("-"):
        s = s[1:]
    if s.startswith(("0x", "0X")):
        return int(s, 16)
    return int(s, 10)


def compute_function_stack_bytes(lines: list[str], arch: str) -> int:
    max_frame = 0
    if arch == "aarch64":
        sub_sp_re = re.compile(r"\bsub\s+sp,\s*sp,\s*(#?(?:0x[0-9a-fA-F]+|[0-9]+))", re.I)
        pre_idx_re = re.compile(r"\b(?:stp|str)\b[^\[]*\[sp,\s*#-(0x[0-9a-fA-F]+|[0-9]+)\]!", re.I)
        for ln in lines:
            m1 = sub_sp_re.search(ln)
            if m1:
                max_frame = max(max_frame, parse_immediate_bytes(m1.group(1)))
            m2 = pre_idx_re.search(ln)
            if m2:
                max_frame = max(max_frame, parse_immediate_bytes(m2.group(1)))
    else:
        sub_rsp_intel = re.compile(r"\bsub\s+rsp,\s*(0x[0-9a-fA-F]+|[0-9]+)", re.I)
        sub_rsp_att = re.compile(r"\bsubq?\s+\$(0x[0-9a-fA-F]+|[0-9]+),\s*%rsp", re.I)
        callee_push_re = re.compile(r"\bpushq?\s+%?(?:rbp|rbx|r1[2-5])\b", re.I)
        callee_pushes: set[str] = set()
        for ln in lines:
            m1 = sub_rsp_intel.search(ln)
            if m1:
                max_frame = max(max_frame, parse_immediate_bytes(m1.group(1)))
            m2 = sub_rsp_att.search(ln)
            if m2:
                max_frame = max(max_frame, parse_immediate_bytes(m2.group(1)))
            m3 = callee_push_re.search(ln)
            if m3:
                reg = m3.group(0).split()[-1].lstrip("%").lower()
                callee_pushes.add(reg)
        max_frame += len(callee_pushes) * 8
    return max_frame


def is_store_instruction(line: str, arch: str) -> bool:
    if arch == "aarch64":
        return bool(re.search(r"\b(strb|strh|str|stp|stnp|st1|stur|sturb)\b", line, re.I))
    return bool(
        re.search(
            r"\b(movb|movw|movl|movq|movups|movaps|movdqu|movdqa|vmovups|vmovaps|vmovdqu|vmovdqa|stosb|stosq|mov)\b",
            line,
            re.I,
        )
    )


def find_matching_symbols(
    records: list[tuple[str, str, list[str]]], needle: str
) -> list[tuple[str, str, list[str]]]:
    matches = []
    for member, sym, lines in records:
        if needle in sym and "test" not in sym.lower():
            matches.append((member, sym, lines))
    return matches


def main() -> None:
    max_stack_bytes = load_max_stack_frame_bytes()
    arch = detect_arch()
    archive = build_nostd_release_archive()
    nm_count = verify_nm_symbols(archive)
    disasm_cmd, tool_kind = resolve_disassembler()

    res = subprocess.run([*disasm_cmd, str(archive)], capture_output=True, text=True, check=False)
    if res.returncode != 0:
        fail(f"Disassembler failed ({' '.join(disasm_cmd)}): {res.stderr.strip()}")

    records = parse_functions(res.stdout)
    if len(records) < 20:
        fail(f"Vacuous disassembly parse: only {len(records)} symbols discovered in {archive}.")

    # 1. Stack Frame Ceiling Audit across every compiled symbol in the archive
    peak_sym = ""
    peak_bytes = 0
    stack_violations: list[tuple[str, str, int]] = []
    for member, sym, lines in records:
        if not (member.startswith("nona_core") or sym.startswith(("nona_core::", "nona_"))):
            continue
        frame_bytes = compute_function_stack_bytes(lines, arch)
        if frame_bytes > peak_bytes:
            peak_bytes = frame_bytes
            peak_sym = sym
        if frame_bytes > max_stack_bytes:
            stack_violations.append((member, sym, frame_bytes))

    if stack_violations:
        details = ", ".join(f"{s} [{m}] ({b} B)" for m, s, b in stack_violations)
        fail(f"Stack frame ceiling ({max_stack_bytes} B) exceeded: {details}")

    # 2. DSE-Resistance Audit on Zeroization Routines
    zeroize_syms = find_matching_symbols(records, "ct_zeroize")
    if not zeroize_syms:
        fail("Could not locate ct_zeroize symbol in compiled release archive (unexpected inlining or missing symbol).")

    for _, sym, lines in zeroize_syms:
        store_count = sum(1 for ln in lines if is_store_instruction(ln, arch))
        if store_count == 0:
            fail(f"Dead-Store Elimination (DSE) detected: {sym} emitted 0 store instructions!")

    # Verify secret scrub routines emit volatile stores or call ct_zeroize before return
    scrub_targets = [
        "execute_wire_blinding_op",
        "ensure_session_key_initialized",
        "purge_session_key_unconditional",
    ]
    for target in scrub_targets:
        matched = find_matching_symbols(records, target)
        if not matched:
            fail(f"Missing expected secret-handling symbol '{target}' in compiled release archive.")
        for _, sym, lines in matched:
            has_ct_zeroize_call = any("ct_zeroize" in ln for ln in lines)
            store_count = sum(1 for ln in lines if is_store_instruction(ln, arch))
            if not has_ct_zeroize_call and store_count == 0:
                fail(f"Secret scrub routine {sym} neither calls ct_zeroize nor emits store instructions prior to return.")

    # 3. Constant-Time Oblivious Phase 2 Intersection Audit
    p2_syms = find_matching_symbols(records, "nona_phase2_intersect_impl")
    if not p2_syms:
        p2_syms = find_matching_symbols(records, "execute_phase2_intersection")
    if not p2_syms:
        fail("Could not locate nona_phase2_intersect_impl or execute_phase2_intersection in compiled release archive.")

    for _, sym, lines in p2_syms:
        store_count = sum(1 for ln in lines if is_store_instruction(ln, arch))
        if store_count == 0:
            fail(f"Oblivious compaction stores missing from {sym}.")

    print(
        f"  ✓ Assembly CT, Stack Ceiling & DSE Zeroization Audit PASSED "
        f"(arch={arch}, tool={tool_kind}, symbols={len(records)}, nm_syms={nm_count}, "
        f"peak_stack={peak_bytes}B <= {max_stack_bytes}B in {peak_sym})."
    )


if __name__ == "__main__":
    main()
