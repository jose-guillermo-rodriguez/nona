# Nona Core Engine: Trusted Computing Base (TCB) Specification

**Specification Version:** 1.0.0-RELEASE
**Classification:** Formal Verification Trust Boundaries & Axiom Catalog
**Target Environments:** #![no_std] Bare-Metal | AWS Nitro Enclaves

---

## 1. Scope of the Trusted Computing Base

The Trusted Computing Base (TCB) consists of the minimal set of hardware, software, and tools whose correctness is necessary to guarantee the security properties of Nona.

- Target Silicon (ARM64 / x86_64): Hardware instruction semantics. ARM64 execution targets AWS Graviton3 (Neoverse V1 / c7g) or later, requiring native ARMv8.5 FEAT_RNG (RNDR / mrs s3_3_c2_c4_0) for constant-time branchless hardware entropy.
- AWS Nitro Enclave NSM: Cryptographic hardware attestation
- Rust Compiler (rustc) & LLVM: Translation to machine instructions
- Verus & Z3 SMT Solver: Machine-checked proof soundness
- Nona Core Engine (libnona_core.a): Formally verified #![no_std] application code

---

## 2. Zero-Dependency Perimeter

Nona cryptographic core eliminates operating system and runtime dependencies:
- Zero Standard Library: Compiles under #![no_std] with zero reliance on std::alloc, std::net, or std::fs.
- Zero Third-Party Runtime Dependencies: 100% of finite-field math, elliptic curve operations, and byte normalization routines are implemented directly in the codebase without third-party crates. Core finite-field arithmetic, complete elliptic curve projective arithmetic (RCB 2016 Alg 4), constant-time scalar multiplication ladder, and Feistel permutations are formally verified in Verus; Simplified SWU hash-to-curve and point decompression operate in the high-assurance #![no_std] runtime perimeter.
- Excluded Symbols: Statically enforced via llvm-nm to contain zero references to malloc, free, realloc, calloc, or __rust_alloc.

---

## 3. Formal Verification Axioms & Proof Scope

Nona formal proofs are machine-checked via Verus using Z3 with an explicit resource limit budget (rlimit = 1,000,000):

- src/psi.rs (92 SMT Targets: 30 Lemmas + 62 Contracts): Solinas reduction, complete homogeneous projective P^2 point addition & doubling (RCB 2016 Alg 4 complete addition), constant-time 256-bit scalar multiplication ladder, field arithmetic, non-overflow (total 122 global SMT targets: 46 inductive lemmas + 76 verified contracts)
- src/obfuscation.rs (22 SMT Targets: 14 Lemmas + 8 Contracts): 4-round Feistel bijection, non-identity permutations, key diffusion (VERIF-01)
- src/normalization.rs (4 SMT Targets: 4 Contracts): Monomorphic 64-byte bounded transformations, memory safety
- src/allocator.rs (1 SMT Target: 1 Contract): Pointer alignment invariants and static arena safety
- src/crypto.rs (3 SMT Targets: 2 Lemmas + 1 Contract): Ghost ChannelToken sequence monotonicity and branchless borrow-bit adaptive VOLE routing circuit (VERIF-03)

### High-Assurance Runtime Cryptographic Boundary (`src/crypto.rs`) [VERIF-03]
Cryptographic components in `src/crypto.rs` are partitioned between the machine-checked core and the runtime perimeter:
- **Machine-Checked SMT Surface (Tier 1):** Ghost `ChannelToken` linear sequence progression and the branchless adaptive VOLE router borrow-bit extraction (`lemma_adaptive_route_borrow_bit`) are formally verified in Verus without axiomatic assumptions.
- **High-Assurance Runtime Perimeter (Tier 3):** RFC 9380 Simplified SWU hash-to-curve, Montgomery batch coordinate inversion, affine point decompression ($y = \sqrt{x^3 + 7} \pmod p$), SIMD normalization kernels (AVX-512, AVX2, NEON), C-ABI FFI entry points (`nona_phase1_blind`, `nona_phase2_reblind`), SHA-512, and `Scalar` group arithmetic modulo $q$ (including `vole_subfield_eval`) are explicitly scoped out of the formal SMT verification perimeter. Non-linear degree-2 scalar reduction modulo the non-Solinas group order $q$ is governed under the High-Assurance Runtime Perimeter, verified empirically via differential oracle test suites (`tests/integration/test_field_differential.rs`), boundary sweeps (`tests/integration/test_crypto_boundaries.rs`), and external dudect timing neutrality audits.

### Live Trusted Computing Base (`#[verifier::external_body]`) Sites
Automated SMT solvers operate within bounded quantifier-free and linear integer arithmetic theories. Due to fundamental SMT decidability limits on non-linear multivariate integer polynomials and cross-radix bit extraction, exactly 4 bounded primitive sites in `src/psi.rs` bypass machine induction and form part of the live TCB (as specified in `SPECIFICATION.md §4.5.1`):

| Target Identifier | Category | Preconditions (`requires`) & Postconditions (`ensures`) | Soundness Rationale |
|---|---|---|---|
| `lemma_multi_limb_bit_to_nat` (`src/psi.rs:2687`) | Proof Lemma | **Requires:** 0 <= j < 256<br>**Ensures:** `fe.limbs[j/64] >> (j%64) % 2 == (fe.to_nat() / 2^j) % 2` | Radix-2^64 limb projection to 256-bit integer bit slice. Pure mathematical bridge without inductive loop contracts. |
| `add_nocarry` (`src/psi.rs:3197`) | Runtime Primitive | **Requires:** None<br>**Ensures:** `res.0 in {0,1} && res.0 * 2^256 + res.1.to_nat() == a.to_nat() + b.to_nat()` | 256-bit unrolled multi-limb addition with carry. Bypasses multi-word ADC carry-chain modeling. |
| `sub_noborrow` (`src/psi.rs:3229`) | Runtime Primitive | **Requires:** None<br>**Ensures:** `res.0 in {0,1} && (a >= b ==> res.0==0 && res.1==a-b) && (a < b ==> res.0==1 && res.1==a+2^256-b)` | 256-bit unrolled multi-limb subtraction with borrow. SMT borrow-propagation semantics isolated at boundary. |
| `FieldElement::mul` (`src/psi.rs:3676`) | Runtime Primitive | **Requires:** `self.is_valid() && other.is_valid()`<br>**Ensures:** `res.is_valid() && res.to_nat() == (self.to_nat() * other.to_nat()) % p` | 256-bit modular multiplication (512-bit product reduced mod p). Non-linear degree-2 reduction treated as axiomatic computation. Audited under VERIF-02: dead internal proof assertions stripped to guarantee an honest SMT trust boundary. |

### Unproven Assumptions & Axiomatic Boundary
1. Arithmetic Semantics: Mathematical axioms of integer arithmetic and prime fields are assumed sound.
2. SMT Solver Soundness: Z3 and Verus are assumed to have no unsound proof-generation bugs under the specified resource limit.
3. Hardware Execution: The underlying CPU instructions execute according to architecture specifications without memory-bit flips or hardware faults.

---

## 4. Machine Stack Verification Ground Truth

To guarantee stack safety in embedded enclaves:
- ELF Stack Sizes (readelf): The .stack_sizes metadata section is audited using readelf / llvm-readelf under Linux musl. Peak frame consumption is strictly bounded (<= 4,096 bytes).
- Compile-Time Ceiling: Machine code is constrained to sub-4 KiB machine frames via LLVM machine stack measurements.
