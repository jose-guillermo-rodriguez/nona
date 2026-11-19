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

- src/psi.rs (176 SMT Targets: 61 Lemmas + 115 Contracts): Zero-axiom 256-bit Solinas modular multiplication, radix-2^64 multi-limb carry/borrow chains, cross-radix bit projection, complete homogeneous projective P^2 point addition & doubling (RCB 2016 Alg 4 complete addition), constant-time 256-bit scalar multiplication ladder, and Tier 3 algebraic/boundary invariants (total 291 global SMT targets: 103 inductive & reduction lemmas + 188 verified executive, boundary & reduction obligations)
- src/obfuscation.rs (22 SMT Targets: 14 Lemmas + 8 Contracts): 4-round Feistel bijection, non-identity permutations, key diffusion (VERIF-01)
- src/normalization.rs (9 SMT Targets: 9 Contract/Loop Targets): Monomorphic 64-byte bounded transformations, output delimiter elimination & zero-padding completeness
- src/allocator.rs (2 SMT Targets: 2 Contract Targets): 64-byte pointer alignment preservation invariants and static arena safety
- src/crypto.rs (3 SMT Targets: 2 Lemmas + 1 Contract): Ghost ChannelToken sequence monotonicity and branchless borrow-bit adaptive VOLE routing circuit (VERIF-03)
- src/enclave_boundaries.rs (17 SMT Targets: 3 Lemmas + 14 Boundary Contracts): AWS Nitro `/dev/nsm` IOCTL/CBOR framing, monotonic enclave session operation ceiling, 64-byte vsock wire framing bijectivity, `CLOCK_MONOTONIC` & `recv_exact` syscall models, FFI spatial disjointness, 128-byte ring pre-flight framing, and branchless exception cursor advancement (ENCL-12)
- proofs/crypto_reductions.rs (62 SMT Targets: 23 Reduction Lemmas + 39 Spec/Termination Obligations): Prime-order cyclic subgroup exponent algebra, constructive Extended Euclidean Bezout modular inverses, DH-PSI set-intersection soundness & completeness, DDH self-randomizability & strict non-DDH gap preservation, and 256-bit/64-bit XOR one-time-pad payload confidentiality & element-domain separation (verified fail-closed by `tools/fuzz_verus_specs.py`)

### High-Assurance Runtime Cryptographic Boundary (`src/crypto.rs`) [VERIF-03]
Cryptographic components in `src/crypto.rs` are partitioned between the machine-checked core and the runtime perimeter:
- **Machine-Checked SMT Surface (Tier 1):** Ghost `ChannelToken` linear sequence progression and the branchless adaptive VOLE router borrow-bit extraction (`lemma_adaptive_route_borrow_bit`) are formally verified in Verus without axiomatic assumptions.
- **High-Assurance Runtime Perimeter (Tier 3):** Core algebraic and boundary invariants for Simplified SWU denominator/isogeny consistency, Montgomery batch-inversion telescoping steps, secp256k1 curve equation & generator membership (`verify_curve_point_on_secp256k1`), VOLE subfield linear MAC homomorphism, SIMD lane-select equivalence, DP cardinality clamping bounds, and C-ABI batch buffer validation (`validate_c_abi_batch_bounds`) are formally verified in Verus (`src/psi.rs`). Full runtime execution pipelines—RFC 9380 SWU end-to-end orchestration, batch inversion loops, affine square-root decompression, SIMD vector intrinsics (AVX-512, AVX2, NEON), C-ABI pointer entry points (`nona_phase1_blind`, `nona_phase2_reblind`), SHA-512, and `Scalar` arithmetic modulo $q$—operate in the High-Assurance Runtime Perimeter, verified empirically via differential oracle test suites (`tests/integration/test_field_differential.rs`), boundary sweeps (`tests/integration/test_crypto_boundaries.rs`), and external dudect timing neutrality audits. Non-linear degree-2 scalar reduction modulo the non-Solinas group order $q$ is governed under the High-Assurance Runtime Perimeter, verified empirically via differential oracle test suites (`tests/integration/test_field_differential.rs`), boundary sweeps (`tests/integration/test_crypto_boundaries.rs`), and external dudect timing neutrality audits.

### Live Trusted Computing Base (`#[verifier::external_body]`) Sites
All 4 arithmetic primitives in `src/psi.rs` (`lemma_multi_limb_bit_to_nat`, `add_nocarry`, `sub_noborrow`, and `FieldElement::mul`) have been discharged into machine-checked Verus proofs with zero axiomatic overrides (`0` `#[verifier::external_body]` sites in `src/psi.rs`). The live `#[verifier::external_body]` TCB is reduced strictly to the 3 irreducible external hardware and OS kernel syscall interfaces in `src/enclave_boundaries.rs` (as specified in `SPECIFICATION.md §4.5.1`):

| Target Identifier | Category | Preconditions (`requires`) & Postconditions (`ensures`) | Soundness Rationale |
|---|---|---|---|
| `ffi_nsm_ioctl_raw_contract` (`src/enclave_boundaries.rs:50`) | Hardware Boundary | **Requires:** `ioctl_cmd == SPEC_NSM_IOCTL_RAW && msg.wf(512, 12288)`<br>**Ensures:** `res.0 == 0 ==> (0 < res.1 <= msg.response.len) && (res.0 != 0 ==> res.1 == 0)` | Irreducible Linux `/dev/nsm` `ioctl(NSM_IOCTL_RAW)` kernel/hypervisor hardware attestation boundary contract. |
| `ffi_clock_monotonic_ns` (`src/enclave_boundaries.rs:202`) | OS Syscall Boundary | **Requires:** None<br>**Ensures:** `now_ns >= prev_ns` | Irreducible POSIX `clock_gettime(CLOCK_MONOTONIC)` monotonic kernel clock boundary model. |
| `ffi_vsock_recv_exact` (`src/enclave_boundaries.rs:211`) | OS Syscall Boundary | **Requires:** `expected_len <= buf_cap`<br>**Ensures:** `Ok(n) ==> n == expected_len` | Irreducible `AF_VSOCK` / `AF_UNIX` kernel socket byte-stream framing boundary model. |

### Unproven Assumptions & Axiomatic Boundary
1. Arithmetic Semantics: Mathematical axioms of integer arithmetic and prime fields are assumed sound.
2. SMT Solver Soundness: Z3 and Verus are assumed to have no unsound proof-generation bugs under the specified resource limit.
3. Hardware Execution: The underlying CPU instructions execute according to architecture specifications without memory-bit flips or hardware faults.

---

## 4. Machine Stack Verification Ground Truth

To guarantee stack safety in embedded enclaves:
- ELF Stack Sizes (readelf): The .stack_sizes metadata section is audited using readelf / llvm-readelf under Linux musl. Peak frame consumption is strictly bounded (<= 4,096 bytes).
- Compile-Time Ceiling: Machine code is constrained to sub-4 KiB machine frames via LLVM machine stack measurements.
