#!/usr/bin/env python3
"""Lemniscate Assurance Ratchet (LAR): declarative policy, git monotonicity, and introspection."""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

SEALED_V101_FLOOR = {
    "min_verified_smt_targets": 146,
    "max_external_body_axioms": 7,
    "max_stack_frame_bytes": 1408,
    "min_hygiene_checks": 16,
    "require_non_mutating_eif_manifest": True,
}

REQUIRED_THRESHOLDS = (
    "min_verified_smt_targets",
    "max_external_body_axioms",
    "max_stack_frame_bytes",
    "min_hygiene_checks",
)

REQUIRED_GATES = (
    "require_non_mutating_eif_manifest",
    "require_tla_model_check",
    "require_p2_timing_hard_gate",
    "require_assembly_spill_audit",
    "require_kms_recipient_binding",
    "require_spec_fuzzing",
    "require_continuous_fuzzing",
    "require_external_audit_dossier",
)

RUNTIME_ABI_EXCLUSIONS = {
    "rust_eh_personality",
}


def fail(msg: str) -> None:
    print(f"  [!] RATCHET FAILURE: {msg}", file=sys.stderr)
    sys.exit(1)


def is_strict_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def validate_policy_schema(doc: object, label: str, *, is_baseline: bool = False) -> dict:
    if not isinstance(doc, dict):
        fail(f"{label} must be a JSON object.")

    for key in ("schema_version", "active_release", "stage_gate"):
        val = doc.get(key)
        if not isinstance(val, str) or not val.strip():
            fail(f"{label}.{key} must be a non-empty string.")

    thresholds = doc.get("thresholds")
    if not isinstance(thresholds, dict):
        fail(f"{label}.thresholds must be a JSON object.")

    for key in REQUIRED_THRESHOLDS:
        if key not in thresholds:
            fail(f"{label}.thresholds missing required key '{key}'.")
        val = thresholds[key]
        if not is_strict_int(val) or val < 0:
            fail(f"{label}.thresholds.{key} must be a non-negative integer (got {val!r}).")

    if thresholds["max_stack_frame_bytes"] == 0:
        fail(f"{label}.thresholds.max_stack_frame_bytes must be > 0.")

    gates = doc.get("gates")
    if not isinstance(gates, dict):
        fail(f"{label}.gates must be a JSON object.")

    required_gates = (
        tuple(g for g in REQUIRED_GATES if g not in ("require_spec_fuzzing", "require_continuous_fuzzing", "require_external_audit_dossier"))
        if is_baseline
        else REQUIRED_GATES
    )
    for key in required_gates:
        if key not in gates:
            fail(f"{label}.gates missing required key '{key}'.")
        if not isinstance(gates[key], bool):
            fail(f"{label}.gates.{key} must be a boolean (got {gates[key]!r}).")

    for key, val in gates.items():
        if not isinstance(val, bool):
            fail(f"{label}.gates.{key} must be a boolean (got {val!r}).")

    return doc


def run_git(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
        check=False,
    )


def resolve_baseline_ref() -> str | None:
    for ref in ("origin/main", "main"):
        res = run_git(["rev-parse", "--verify", "--quiet", ref])
        if res.returncode == 0 and res.stdout.strip():
            return ref

    tags = run_git(["tag", "-l", "v*", "--sort=-v:refname"])
    if tags.returncode == 0:
        for line in tags.stdout.splitlines():
            tag = line.strip()
            if tag:
                return tag
    return None


def verify_git_monotonicity(head_policy: dict) -> None:
    head_t = head_policy["thresholds"]
    head_g = head_policy["gates"]

    baseline_ref = resolve_baseline_ref()
    if baseline_ref is None:
        print("  [*] Baseline ref unavailable; enforcing sealed v1.0.1 bootstrap floor.")
        enforce_sealed_floor(head_t, head_g)
        return

    show_res = run_git(["show", f"{baseline_ref}:assurance_policy.json"])
    if show_res.returncode != 0:
        print(
            f"  [*] assurance_policy.json not present on {baseline_ref} (bootstrap PR); "
            "enforcing sealed v1.0.1 floor."
        )
        enforce_sealed_floor(head_t, head_g)
        return

    try:
        raw_base = json.loads(show_res.stdout)
    except json.JSONDecodeError as exc:
        fail(f"Invalid JSON in {baseline_ref}:assurance_policy.json: {exc}")

    base_policy = validate_policy_schema(raw_base, f"{baseline_ref}:assurance_policy.json", is_baseline=True)
    base_t = base_policy["thresholds"]
    base_g = base_policy["gates"]

    if head_t["min_verified_smt_targets"] < base_t["min_verified_smt_targets"]:
        fail(
            f"Monotonicity violation: min_verified_smt_targets regressed from "
            f"{base_t['min_verified_smt_targets']} ({baseline_ref}) to {head_t['min_verified_smt_targets']}."
        )
    if head_t["max_external_body_axioms"] > base_t["max_external_body_axioms"]:
        fail(
            f"Monotonicity violation: max_external_body_axioms weakened from "
            f"{base_t['max_external_body_axioms']} ({baseline_ref}) to {head_t['max_external_body_axioms']}."
        )
    if head_t["max_stack_frame_bytes"] > base_t["max_stack_frame_bytes"]:
        fail(
            f"Monotonicity violation: max_stack_frame_bytes relaxed from "
            f"{base_t['max_stack_frame_bytes']} ({baseline_ref}) to {head_t['max_stack_frame_bytes']}."
        )
    if head_t["min_hygiene_checks"] < base_t["min_hygiene_checks"]:
        fail(
            f"Monotonicity violation: min_hygiene_checks regressed from "
            f"{base_t['min_hygiene_checks']} ({baseline_ref}) to {head_t['min_hygiene_checks']}."
        )

    for gate_name, base_enabled in base_g.items():
        if base_enabled is True and head_g.get(gate_name) is not True:
            fail(
                f"Monotonicity violation: sealed boolean gate '{gate_name}' was disabled "
                f"relative to {baseline_ref}."
            )

    print(f"  ✓ Git-anchored monotonicity verified against {baseline_ref}.")


def enforce_sealed_floor(thresholds: dict, gates: dict) -> None:
    if thresholds["min_verified_smt_targets"] < SEALED_V101_FLOOR["min_verified_smt_targets"]:
        fail(
            f"Bootstrap floor violation: min_verified_smt_targets "
            f"({thresholds['min_verified_smt_targets']}) < {SEALED_V101_FLOOR['min_verified_smt_targets']}."
        )
    if thresholds["max_external_body_axioms"] > SEALED_V101_FLOOR["max_external_body_axioms"]:
        fail(
            f"Bootstrap floor violation: max_external_body_axioms "
            f"({thresholds['max_external_body_axioms']}) > {SEALED_V101_FLOOR['max_external_body_axioms']}."
        )
    if thresholds["max_stack_frame_bytes"] > SEALED_V101_FLOOR["max_stack_frame_bytes"]:
        fail(
            f"Bootstrap floor violation: max_stack_frame_bytes "
            f"({thresholds['max_stack_frame_bytes']}) > {SEALED_V101_FLOOR['max_stack_frame_bytes']}."
        )
    if thresholds["min_hygiene_checks"] < SEALED_V101_FLOOR["min_hygiene_checks"]:
        fail(
            f"Bootstrap floor violation: min_hygiene_checks "
            f"({thresholds['min_hygiene_checks']}) < {SEALED_V101_FLOOR['min_hygiene_checks']}."
        )
    if gates["require_non_mutating_eif_manifest"] is not True:
        fail("Bootstrap floor violation: gates.require_non_mutating_eif_manifest must be true.")
    print("  ✓ Sealed v1.0.1 bootstrap watermark floor satisfied.")


def verify_live_ground_truth(policy: dict) -> None:
    thresholds = policy["thresholds"]

    # 0. Active release parity against Cargo.toml
    cargo_toml = Path("Cargo.toml")
    if not cargo_toml.is_file():
        fail("Missing Cargo.toml.")
    m_ver = re.search(r'^version\s*=\s*"([^"]+)"', cargo_toml.read_text(encoding="utf-8"), re.M)
    if not m_ver:
        fail("Could not parse crate version from Cargo.toml.")
    if m_ver.group(1) != policy["active_release"]:
        fail(
            f"Release parity violation: assurance_policy.json active_release "
            f"({policy['active_release']!r}) != Cargo.toml ({m_ver.group(1)!r})."
        )

    # 1. Verus SMT verification log ground truth
    verus_log = Path("proofs/verus_verification.log")
    if not verus_log.is_file():
        fail("Missing proofs/verus_verification.log.")

    log_text = verus_log.read_text(encoding="utf-8")
    result_matches = re.findall(
        r"verification results::\s*(\d+)\s+verified,\s*(\d+)\s+errors",
        log_text,
    )
    if not result_matches:
        fail("No 'verification results::' lines parsed in proofs/verus_verification.log.")

    total_verified = 0
    for verified_s, errors_s in result_matches:
        errors = int(errors_s)
        if errors != 0:
            fail(f"proofs/verus_verification.log contains non-zero verification errors ({errors}).")
        total_verified += int(verified_s)

    min_smt = thresholds["min_verified_smt_targets"]
    if total_verified < min_smt:
        fail(
            f"Verified SMT targets ({total_verified}) below policy floor ({min_smt})."
        )
    print(f"  ✓ Live SMT targets verified: {total_verified} >= {min_smt} (0 errors).")

    # 2. Live #[verifier::external_body] attributes across src/
    ext_attr_re = re.compile(r"^\s*#\[verifier::external_body\]")
    ext_sites: list[str] = []
    for rs_path in sorted(Path("src").rglob("*.rs")):
        for lineno, line in enumerate(rs_path.read_text(encoding="utf-8").splitlines(), 1):
            if ext_attr_re.match(line):
                ext_sites.append(f"{rs_path}:{lineno}")

    max_ext = thresholds["max_external_body_axioms"]
    if len(ext_sites) > max_ext:
        fail(
            f"Live #[verifier::external_body] count ({len(ext_sites)}) exceeds policy ceiling "
            f"({max_ext}): {', '.join(ext_sites)}"
        )
    print(f"  ✓ Live #[verifier::external_body] axioms: {len(ext_sites)} <= {max_ext}.")

    # 3. Live hygiene checks in tools/check_code_hygiene.sh
    hygiene_script = Path("tools/check_code_hygiene.sh")
    if not hygiene_script.is_file():
        fail("Missing tools/check_code_hygiene.sh.")

    hygiene_text = hygiene_script.read_text(encoding="utf-8")
    checks = re.findall(r"--> Check [0-9]+:", hygiene_text)
    min_checks = thresholds["min_hygiene_checks"]
    if len(checks) < min_checks:
        fail(
            f"Hygiene check count ({len(checks)}) in tools/check_code_hygiene.sh "
            f"is below policy floor ({min_checks})."
        )
    print(f"  ✓ Live hygiene gates verified: {len(checks)} >= {min_checks}.")


def strip_c_comments(header_text: str) -> str:
    without_block = re.sub(r"/\*.*?\*/", "", header_text, flags=re.DOTALL)
    return re.sub(r"//.*", "", without_block)


def discover_rust_c_abi_symbols() -> set[str]:
    symbols: set[str] = set()
    no_mangle_re = re.compile(r"^\s*#\[no_mangle\]")
    extern_fn_re = re.compile(r'\bpub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+([A-Za-z0-9_]+)\b')

    for rs_path in sorted(Path("src").rglob("*.rs")):
        # Exclude binary entrypoint targets (e.g., enclave _start / main)
        if "bin" in rs_path.parts:
            continue
        lines = rs_path.read_text(encoding="utf-8").splitlines()
        pending_no_mangle = False
        window = 0
        for line in lines:
            if no_mangle_re.match(line):
                pending_no_mangle = True
                window = 0
                continue
            if pending_no_mangle:
                window += 1
                m = extern_fn_re.search(line)
                if m:
                    sym = m.group(1)
                    if sym not in RUNTIME_ABI_EXCLUSIONS:
                        symbols.add(sym)
                    pending_no_mangle = False
                elif window > 15 or re.match(r"^\s*(pub\s+)?(fn|struct|enum|impl|mod|static|const)\b", line):
                    pending_no_mangle = False
    return symbols


def introspect_static_archives(expected_symbols: set[str], declared_headers: str) -> int:
    archives = sorted(Path("target").glob("**/libnona_core.a")) if Path("target").is_dir() else []
    if not archives:
        return 0

    nm_bin = shutil.which("llvm-nm") or shutil.which("nm")
    if nm_bin is None:
        return 0

    audited = 0
    for archive in archives:
        res = subprocess.run(
            [nm_bin, "-g", "--defined-only", str(archive)],
            capture_output=True,
            text=True,
            check=False,
        )
        if res.returncode != 0:
            res = subprocess.run(
                [nm_bin, "-g", str(archive)],
                capture_output=True,
                text=True,
                check=False,
            )
        if res.returncode != 0:
            continue

        defined_nona_syms: set[str] = set()
        for line in res.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2 and parts[-2] in ("T", "t"):
                raw_sym = parts[-1].lstrip("_")
                if raw_sym.startswith("nona_"):
                    defined_nona_syms.add(raw_sym)

        if not defined_nona_syms:
            continue

        undeclared_in_headers = sorted(
            sym for sym in defined_nona_syms
            if not re.search(rf"\b{re.escape(sym)}\s*\(", declared_headers)
        )
        if undeclared_in_headers:
            fail(
                f"Static archive {archive} exports C-ABI symbol(s) absent from C headers: "
                f"{', '.join(undeclared_in_headers)}"
            )

        missing_from_archive = sorted(expected_symbols - defined_nona_syms)
        if missing_from_archive:
            fail(
                f"Static archive {archive} is missing expected C-ABI export(s): "
                f"{', '.join(missing_from_archive)}"
            )
        audited += 1
    return audited


def verify_introspection_and_gates(policy: dict) -> None:
    gates = policy["gates"]

    # 1. C-ABI symbol introspection across src/, include/, and compiled static archives
    header_files = [Path("include/nona.h"), Path("include/nona_udf.h")]
    missing_headers = [str(p) for p in header_files if not p.is_file()]
    if missing_headers:
        fail(f"Missing required C-ABI header(s): {', '.join(missing_headers)}")

    header_corpus = "\n".join(
        strip_c_comments(p.read_text(encoding="utf-8")) for p in header_files
    )

    exported_symbols = discover_rust_c_abi_symbols()
    if not exported_symbols:
        fail('Zero #[no_mangle] pub extern "C" symbols discovered in src/.')

    undocumented = sorted(
        sym for sym in exported_symbols
        if not re.search(rf"\b{re.escape(sym)}\s*\(", header_corpus)
    )
    if undocumented:
        fail(
            "Exported Rust C-ABI symbol(s) missing from include/nona.h or include/nona_udf.h: "
            + ", ".join(undocumented)
        )

    archives_checked = introspect_static_archives(exported_symbols, header_corpus)
    archive_note = (
        f"; cross-checked {archives_checked} compiled libnona_core.a archive(s)"
        if archives_checked > 0
        else ""
    )
    print(
        f"  ✓ C-ABI symbol introspection verified: {len(exported_symbols)} exported symbols "
        f"declared in C headers{archive_note}."
    )

    # 2. Non-mutating EIF manifest gate
    if gates["require_non_mutating_eif_manifest"]:
        eif_builder = Path("tools/build_nitro_eif.sh")
        if not eif_builder.is_file():
            fail("Missing tools/build_nitro_eif.sh while require_non_mutating_eif_manifest is true.")
        builder_text = eif_builder.read_text(encoding="utf-8")
        if re.search(r'MANIFEST_OUTPUT="\$\{MANIFEST_DIR\}/enclave_manifest_', builder_text):
            fail("tools/build_nitro_eif.sh mutates tracked manifests/ directly.")
        if "--bless-manifest" not in builder_text:
            fail("tools/build_nitro_eif.sh lacks explicit --bless-manifest guard.")
        print("  ✓ Stage gate active: non-mutating EIF manifest hygiene enforced.")

    # 3. TLA+ model-checking stage gate
    if gates["require_tla_model_check"]:
        tla_specs = sorted(Path("specs").glob("*.tla")) if Path("specs").is_dir() else []
        if not tla_specs:
            fail("gates.require_tla_model_check is true, but no specs/*.tla files exist.")
        ci_text = Path(".github/workflows/ci.yml").read_text(encoding="utf-8") if Path(".github/workflows/ci.yml").is_file() else ""
        if "verify-models" not in ci_text or "tla2tools.jar" not in ci_text:
            fail("gates.require_tla_model_check is true, but .github/workflows/ci.yml does not execute TLC verify-models.")
        print(
            f"  ✓ Stage gate active: discovered {len(tla_specs)} TLA+ specification(s) & CI TLC model-check gate: "
            + ", ".join(str(p) for p in tla_specs)
        )
    else:
        print("  [*] Stage gate inactive: require_tla_model_check=false.")


    # 4. Verus specification mutation fuzzing gate
    if gates["require_spec_fuzzing"]:
        fuzzer = Path("tools/fuzz_verus_specs.py")
        if not fuzzer.is_file():
            fail("gates.require_spec_fuzzing is true, but tools/fuzz_verus_specs.py is missing.")
        makefile_text = Path("Makefile").read_text(encoding="utf-8") if Path("Makefile").is_file() else ""
        if not re.search(r"^spec-fuzz:", makefile_text, re.M):
            fail("gates.require_spec_fuzzing is true, but Makefile lacks 'spec-fuzz:' target.")
        print("  ✓ Stage gate active: Verus specification mutation fuzzer enforced.")

    # 5. Continuous fuzzing CI gate
    if gates["require_continuous_fuzzing"]:
        fuzz_toml = Path("fuzz/Cargo.toml")
        if not fuzz_toml.is_file():
            fail("gates.require_continuous_fuzzing is true, but fuzz/Cargo.toml is missing.")
        ci_text = Path(".github/workflows/ci.yml").read_text(encoding="utf-8") if Path(".github/workflows/ci.yml").is_file() else ""
        if "fuzz" not in ci_text.lower():
            fail("gates.require_continuous_fuzzing is true, but .github/workflows/ci.yml lacks continuous fuzzing step.")
        print("  ✓ Stage gate active: continuous fuzzing CI harness enforced.")

    # 6. External cryptanalysis & independent security audit dossier gate
    if gates["require_external_audit_dossier"]:
        dossier = Path("docs/EXTERNAL_AUDIT_DOSSIER.md")
        if not dossier.is_file():
            fail("gates.require_external_audit_dossier is true, but docs/EXTERNAL_AUDIT_DOSSIER.md is missing.")
        makefile_text = Path("Makefile").read_text(encoding="utf-8") if Path("Makefile").is_file() else ""
        if not re.search(r"^audit-bundle:", makefile_text, re.M):
            fail("gates.require_external_audit_dossier is true, but Makefile lacks 'audit-bundle:' target.")
        print("  ✓ Stage gate active: external cryptanalysis & audit readiness dossier enforced.")

def main() -> None:
    policy_path = Path("assurance_policy.json")
    if not policy_path.is_file():
        fail("Missing root declarative policy: assurance_policy.json")

    try:
        raw_policy = json.loads(policy_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"Invalid JSON in assurance_policy.json: {exc}")

    policy = validate_policy_schema(raw_policy, "assurance_policy.json")
    print(
        f"  [*] Loaded assurance_policy.json (schema={policy['schema_version']}, "
        f"release={policy['active_release']}, stage={policy['stage_gate']})"
    )

    verify_git_monotonicity(policy)
    verify_live_ground_truth(policy)
    verify_introspection_and_gates(policy)


if __name__ == "__main__":
    main()
