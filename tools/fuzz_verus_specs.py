#!/usr/bin/env python3
"""Deterministic Verus Specification Mutation Fuzzer (Fail-Closed Contract Gate)."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SpecMutant:
    mutant_id: str
    source_path: str
    target_fn: str
    category: str
    description: str
    original_snippet: str
    mutated_snippet: str


MUTANTS: tuple[SpecMutant, ...] = (
    SpecMutant(
        mutant_id="MUT-01",
        source_path="proofs/crypto_reductions.rs",
        target_fn="lemma_xor256_involution",
        category="postcondition-corruption",
        description="Corrupt 256-bit XOR involution postcondition from plaintext recovery (== m) to key recovery (== k)",
        original_snippet="pub proof fn lemma_xor256_involution(m: Block256, k: Block256)\n    ensures\n        spec_xor256(spec_xor256(m, k), k) == m,",
        mutated_snippet="pub proof fn lemma_xor256_involution(m: Block256, k: Block256)\n    ensures\n        spec_xor256(spec_xor256(m, k), k) == k,",
    ),
    SpecMutant(
        mutant_id="MUT-02",
        source_path="proofs/crypto_reductions.rs",
        target_fn="lemma_ddh_rerandomize_preserves_ddh",
        category="postcondition-negation",
        description="Invert DDH rerandomization preservation postcondition from is_ddh_triple to is_non_ddh_triple",
        original_snippet="        ({\n            let (a_prime, b_prime, c_prime) = ddh_rerandomize(a, b, c, r, s, q);\n            is_ddh_triple(a_prime, b_prime, c_prime, q)\n        }),",
        mutated_snippet="        ({\n            let (a_prime, b_prime, c_prime) = ddh_rerandomize(a, b, c, r, s, q);\n            is_non_ddh_triple(a_prime, b_prime, c_prime, q)\n        }),",
    ),
    SpecMutant(
        mutant_id="MUT-03",
        source_path="proofs/crypto_reductions.rs",
        target_fn="lemma_ddh_rerandomize_preserves_non_ddh_gap",
        category="precondition-corruption",
        description="Corrupt DDH non-gap invertibility precondition ((r * r_inv) % q == 1 -> == 0) to admit zero multiplier r = 0",
        original_snippet="        is_non_ddh_triple(a, b, c, q),\n        0 < r < q,\n        (r * r_inv) % q == 1,",
        mutated_snippet="        is_non_ddh_triple(a, b, c, q),\n        0 <= r < q,\n        (r * r_inv) % q == 0,",
    ),
    SpecMutant(
        mutant_id="MUT-04",
        source_path="proofs/crypto_reductions.rs",
        target_fn="lemma_mod_exp_inverse_cancellation",
        category="precondition-corruption",
        description="Admit degenerate blinding scalar alpha == 0 by mutating modular inverse precondition to (alpha * alpha_inv) % q == 0",
        original_snippet="pub proof fn lemma_mod_exp_inverse_cancellation(x: int, alpha: int, alpha_inv: int, q: int)\n    requires\n        q > 1,\n        0 <= x < q,\n        (alpha * alpha_inv) % q == 1,",
        mutated_snippet="pub proof fn lemma_mod_exp_inverse_cancellation(x: int, alpha: int, alpha_inv: int, q: int)\n    requires\n        q > 1,\n        0 <= x < q,\n        (alpha * alpha_inv) % q == 0,",
    ),
    SpecMutant(
        mutant_id="MUT-05",
        source_path="proofs/crypto_reductions.rs",
        target_fn="lemma_dh_psi_set_intersection_soundness_and_completeness",
        category="postcondition-corruption",
        description="Flip DH-PSI set-intersection soundness/completeness biconditional from (hx == hy) to (hx != hy)",
        original_snippet="    ensures\n        ((((hx * alpha) % q) * beta) % q == (((hy * beta) % q) * alpha) % q) <==> (hx == hy),",
        mutated_snippet="    ensures\n        ((((hx * alpha) % q) * beta) % q == (((hy * beta) % q) * alpha) % q) <==> (hx != hy),",
    ),
    SpecMutant(
        mutant_id="MUT-06",
        source_path="src/obfuscation.rs",
        target_fn="lemma_feistel_bijection_64",
        category="postcondition-negation",
        description="Break 4-round Feistel round-trip bijection postcondition (== x -> != x)",
        original_snippet="pub proof fn lemma_feistel_bijection_64(x: u64, f1: u32, f2: u32, f3: u32, f4: u32)\n    ensures\n        spec_invert_64(spec_permute_64(x, f1, f2, f3, f4), f1, f2, f3, f4) == x,",
        mutated_snippet="pub proof fn lemma_feistel_bijection_64(x: u64, f1: u32, f2: u32, f3: u32, f4: u32)\n    ensures\n        spec_invert_64(spec_permute_64(x, f1, f2, f3, f4), f1, f2, f3, f4) != x,",
    ),
    SpecMutant(
        mutant_id="MUT-07",
        source_path="src/obfuscation.rs",
        target_fn="lemma_feistel_injective_64",
        category="precondition-corruption",
        description="Invert Feistel injectivity precondition from equal outputs to distinct outputs implying equal preimages",
        original_snippet="pub proof fn lemma_feistel_injective_64(x1: u64, x2: u64, f1: u32, f2: u32, f3: u32, f4: u32)\n    requires\n        spec_permute_64(x1, f1, f2, f3, f4) == spec_permute_64(x2, f1, f2, f3, f4),",
        mutated_snippet="pub proof fn lemma_feistel_injective_64(x1: u64, x2: u64, f1: u32, f2: u32, f3: u32, f4: u32)\n    requires\n        spec_permute_64(x1, f1, f2, f3, f4) != spec_permute_64(x2, f1, f2, f3, f4),",
    ),
    SpecMutant(
        mutant_id="MUT-08",
        source_path="src/allocator.rs",
        target_fn="bump_allocate",
        category="invariant-corruption",
        description="Corrupt 64-byte L1 cache-line alignment invariant from (addr % 64 == 0) to (addr % 64 == 1)",
        original_snippet="pub open spec fn is_aligned_64(addr: int) -> bool {\n    addr % 64 == 0\n}",
        mutated_snippet="pub open spec fn is_aligned_64(addr: int) -> bool {\n    addr % 64 == 1\n}",
    ),
    SpecMutant(
        mutant_id="MUT-09",
        source_path="src/psi.rs",
        target_fn="reduce_final",
        category="postcondition-corruption",
        description="Shift Solinas modular reduction postcondition off-by-one ((sum % p) + 1)",
        original_snippet="fn reduce_final(sum: [u64; 4]) -> (res: [u64; 4])\n    requires\n        (FieldElement { limbs: sum }).to_nat() < 2 * spec_p(),\n    ensures\n        (FieldElement { limbs: res }).is_valid(),\n        (FieldElement { limbs: res }).to_nat() == ((FieldElement { limbs: sum }).to_nat() % spec_p()),",
        mutated_snippet="fn reduce_final(sum: [u64; 4]) -> (res: [u64; 4])\n    requires\n        (FieldElement { limbs: sum }).to_nat() < 2 * spec_p(),\n    ensures\n        (FieldElement { limbs: res }).is_valid(),\n        (FieldElement { limbs: res }).to_nat() == ((FieldElement { limbs: sum }).to_nat() % spec_p()) + 1,",
    ),
    SpecMutant(
        mutant_id="MUT-10",
        source_path="src/psi.rs",
        target_fn="validate_c_abi_batch_bounds",
        category="postcondition-weakening",
        description="Weaken C-ABI ingress buffer capacity postcondition from (in_len >= n_elements * 64) to (in_len >= n_elements * 32)",
        original_snippet="pub fn validate_c_abi_batch_bounds(n_elements: usize, in_len: usize, out_len: usize) -> (ok: bool)\n    ensures\n        ok <==> (\n            1 <= n_elements &&\n            n_elements <= 128 &&\n            in_len >= n_elements * 64 &&",
        mutated_snippet="pub fn validate_c_abi_batch_bounds(n_elements: usize, in_len: usize, out_len: usize) -> (ok: bool)\n    ensures\n        ok <==> (\n            1 <= n_elements &&\n            n_elements <= 128 &&\n            in_len >= n_elements * 32 &&",
    ),
)


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    runner = repo_root / "tools" / "run_verus_safe.sh"
    if not runner.is_file():
        print(f"[ERROR] Missing Verus verification harness: {runner}", file=sys.stderr)
        return 1

    print("=================================================================")
    print("NONA CORE ENGINE: VERUS SPECIFICATION MUTATION FUZZER (FAIL-CLOSED)")
    print("=================================================================")
    print(f"[*] Executing {len(MUTANTS)} deterministic specification mutants in isolated /tmp workspace...")

    killed = 0
    with tempfile.TemporaryDirectory(prefix="nona_spec_fuzz_", dir="/tmp") as tmp_dir:
        tmp_root = Path(tmp_dir)
        for idx, mutant in enumerate(MUTANTS, start=1):
            src_file = repo_root / mutant.source_path
            if not src_file.is_file():
                print(f"  [!] ERROR: Target source file missing: {src_file}", file=sys.stderr)
                return 1

            original_text = src_file.read_text(encoding="utf-8")
            occurrences = original_text.count(mutant.original_snippet)
            if occurrences != 1:
                print(
                    f"  [!] ERROR: Mutant {mutant.mutant_id} expected exactly 1 anchor occurrence in "
                    f"{mutant.source_path}, found {occurrences}.",
                    file=sys.stderr,
                )
                return 1

            mutated_text = original_text.replace(mutant.original_snippet, mutant.mutated_snippet, 1)
            tmp_rs = tmp_root / f"{mutant.mutant_id}_{Path(mutant.source_path).name}"
            tmp_rs.write_text(mutated_text, encoding="utf-8")

            try:
                proc = subprocess.run(
                    [str(runner), "--native-host", str(tmp_rs), mutant.target_fn],
                    cwd=str(repo_root),
                    capture_output=True,
                    text=True,
                    check=False,
                )
            finally:
                if tmp_rs.exists():
                    tmp_rs.unlink()

            if proc.returncode == 0:
                print(
                    f"  [!] SURVIVED MUTANT [{idx}/{len(MUTANTS)}] {mutant.mutant_id} "
                    f"({mutant.source_path}::{mutant.target_fn}) [{mutant.category}]: {mutant.description}",
                    file=sys.stderr,
                )
                print(proc.stdout, file=sys.stderr)
                return 1

            killed += 1
            print(
                f"  [KILLED {idx:02d}/{len(MUTANTS):02d}] {mutant.mutant_id} "
                f"({mutant.source_path}::{mutant.target_fn}) [{mutant.category}] -> rejected (rc={proc.returncode})"
            )

    kill_rate = (killed * 100.0) / len(MUTANTS)
    print("-----------------------------------------------------------------")
    print(f"[✓] SPEC-FUZZING SEALED: {killed}/{len(MUTANTS)} MUTANTS KILLED ({kill_rate:.1f}% KILL RATE, 0 SURVIVORS)")
    print("=================================================================")
    return 0


if __name__ == "__main__":
    sys.exit(main())
