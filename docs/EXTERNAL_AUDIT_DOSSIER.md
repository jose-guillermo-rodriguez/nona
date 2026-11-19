# Nona Core Engine: External Cryptanalysis & Independent Security Audit Dossier

**Document Version:** 1.1.0-SEALED  
**Target Release:** `nona-core` v1.1.0 (`track3-external-audit-sealed`)  
**Classification:** External Cryptanalysis, Formal Verification & Enclave Security Audit Briefing  
**Target Environments:** AWS Nitro Enclaves (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`) | `#![no_std]` Bare-Metal  

---

## 1. System Architecture & Trust Boundaries

Nona (`libnona_core.a` / `nona_enclave`) is a zero-dependency, `#![no_std]` cryptographic engine engineered for two-party Private Set Intersection (PSI), private set intersection cardinality (`PSI-CA`), deterministic byte normalization, and constant-time index obfuscation inside hardware-isolated AWS Nitro Enclaves.

### 1.1 Cryptographic Primitives & Protocol Perimeter
- **Curve & Field Substrate (`src/psi.rs`):** Prime-order elliptic curve `secp256k1` ($E(\mathbb{F}_p): y^2 \equiv x^3 + 7 \pmod p$, prime field $p = 2^{256} - 2^{32} - 977$, prime subgroup order $q = \text{0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141}$, cofactor $h = 1$). Arithmetic operates in homogeneous projective $\mathbb{P}^2$ coordinates $(X : Y : Z)$ using Renes-Costello-Batina (2016) Algorithm 4 complete addition formulas and a fixed 256-step constant-time Montgomery ladder (`ProjectivePoint::scalar_mul`).
- **Hash-to-Curve & Domain Separation (`src/crypto.rs`):** RFC 9380 Simplified Shallue-van de Woestijne-Ulas (SWU) map-to-curve over `secp256k1` with explicit domain separation (`H_1` element-to-curve mapping vs. `H_2` key derivation) and Montgomery simultaneous batch inversion (`FieldElement::batch_invert`) for affine serialization.
- **Two-Party Commutative DH-PSI & Adaptive VOLE-PSI Router (`src/crypto.rs`, `src/psi.rs`):**
  - *Phase 1 (`nona_phase1_blind`):* Client/Party A blinds input elements $x_i$ as $H_1(x_i)^a \in E(\mathbb{F}_p)$ using ephemeral scalar $a \in \mathbb{Z}_q^*$.
  - *Phase 2 (`nona_phase2_reblind`):* Enclave/Party B re-blinds Party A's elements to $H_1(x_i)^{ab}$, evaluates its own blinded items $H_1(y_j)^b$, and performs oblivious constant-time matching over canonical affine $x$-coordinates (`NONA_FLAG_FULL_PSI` or `NONA_FLAG_PSI_CA` with differential-privacy Laplace cardinality noise).
  - *Adaptive Threshold Router:* Branchless arithmetic routing (`ct_route_adaptive_psi`) selects between Commutative DH-PSI and subfield VOLE-PSI without secret-dependent control flow.

### 1.2 Hardware Isolation & Zero-Heap Static Memory Architecture
- **Zero-Trust Host Model (`docs/THREAT_MODEL.md`):** The parent EC2 host OS, hypervisor control plane, and `AF_VSOCK` proxy are modeled as actively adversarial intermediaries capable of arbitrary frame injection, replay, truncation, reordering, pointer aliasing (Iago attacks), and wall-clock manipulation (`CLOCK_REALTIME`).
- **Exclusive `/dev/nsm` Hardware Entropy (`src/attestation.rs`):** All session keys and ephemeral scalars are seeded exclusively from the AWS Nitro Security Module (`/dev/nsm` `GetRandom` IOCTL). OS and CPU RNG fallbacks (`getrandom`, `getentropy`, `RDRAND`, `RNDR`) are forbidden by static hygiene checks; any `/dev/nsm` fault triggers immediate volatile memory decontamination and hardware trap abort (`ud2` / `brk`).
- **Zero Dynamic Heap (`#![no_std]`):** `libnona_core.a` compiles under `--no-default-features` with zero `alloc` imports and zero dynamic allocator symbols (`malloc`, `free`, `realloc`, `calloc`, `__rust_alloc` count $= 0$). All buffers reside in 64-byte cache-line-aligned static arenas (`StaticArena<N>`, `EnclaveConnectionSlot`) or bounded stack frames (`<= 1408 B` audited assembly frame ceiling; `<= 4096 B` ELF/Mach-O ceiling).
- **Bounded `AF_VSOCK` & C-ABI Perimeter (`src/enclave_server.rs`, `src/gatekeeper.rs`):** Fixed 64-byte request/response headers (`NONA_VSOCK_MAGIC`), exact frame reads (`recv_exact`), strict interval disjointness and alignment validation (`nona_validate_ffi_bounds`), opaque wire error responses (`NONA_WIRE_ERR_OPAQUE = -1`), and 250-microsecond constant-floor response pacing (`WIRE_FRAME_FLOOR_NS`).

---

## 2. Cryptographic Protocol & Game-Based Security Reductions (`proofs/crypto_reductions.rs`)

All algebraic protocol invariants and game-based cryptographic reductions are machine-checked in Verus (`proofs/crypto_reductions.rs`, 62 SMT targets, 0 axioms):

1. **Prime-Order Cyclic Subgroup Exponent Algebra:**
   - Formalizes multiplicative identity (`lemma_mod_exp_identity`), sequential scalar blinding associativity (`lemma_mod_exp_associativity`), and commutative double-blinding equivalence:
     $$(x \cdot \alpha) \cdot \beta \equiv (x \cdot \beta) \cdot \alpha \pmod q$$
     (`lemma_commutative_double_blinding`), plus constructive Extended Euclidean Bezout modular inverse existence (`lemma_bezout_mod_inverse_exists`) for every $\alpha \in \mathbb{Z}_q^*$.
2. **DH-PSI Intersection Soundness & Completeness:**
   - *Completeness (`lemma_dh_psi_completeness`):* Equal canonical items $x = y$ produce identical double-blinded exponents $(x \cdot \alpha) \cdot \beta \equiv (y \cdot \beta) \cdot \alpha \pmod q$.
   - *Soundness (`lemma_dh_psi_soundness`):* Distinct items $x \not\equiv y \pmod q$ blinded under non-zero scalars $\alpha, \beta \in \mathbb{Z}_q^*$ never collide modulo $q$ (zero false-positive intersection probability in the prime-order group).
3. **Decisional Diffie-Hellman (DDH) Self-Randomizability & Non-DDH Gap Preservation:**
   - *DDH Tuple Preservation (`lemma_ddh_rerandomization_preserves_dh`):* Given a valid DH tuple $(a, b, c = ab \bmod q)$ and fresh randomizer $r \in \mathbb{Z}_q^*$, the rerandomized tuple $(a, b \cdot r \bmod q, c \cdot r \bmod q)$ remains a valid DH tuple.
   - *Non-DDH Gap Preservation (`lemma_ddh_rerandomization_preserves_non_dh`):* Given a non-DH tuple $(a, b, c \not\equiv ab \pmod q)$ and $r \in \mathbb{Z}_q^*$, $(a, b \cdot r \bmod q, c \cdot r \bmod q)$ strictly satisfies $c \cdot r \not\equiv a \cdot (b \cdot r) \pmod q$, establishing tight single-instance-to-batch DDH self-reducibility for blinded PSI transcript indistinguishability.
4. **$\kappa_j$ XOR-Fold One-Time-Pad Payload Confidentiality & Domain Separation:**
   - Formalizes involution ($c \oplus \kappa = m$), uniformity/injectivity of key-stream masking (`lemma_xor_otp_256_confidentiality`, `lemma_xor_otp_64_confidentiality`), and strict domain separation between element-blinding hashes ($H_1$) and key-derivation hashes ($H_2$) (`lemma_domain_separated_hashes_distinct`).
5. **Differential Privacy Cardinality & Explicit Non-Confidentiality Disclosure:**
   - `PSI-CA` mode (`NONA_FLAG_PSI_CA`) adds bounded discrete Laplace noise calibrated to sensitivity $\Delta = 1$ with deterministic saturation clamping to $[0, N_{\max}]$.
   - **Auditor Note on `nona_permute_index` (`src/obfuscation.rs`):** The 4-round Feistel network over $\mathbb{Z}_{2^{64}}$ is machine-proven to be a collision-free bijection ($f^{-1}(f(x)) = x$, 22 Verus SMT targets). It is strictly a deterministic index permutation primitive and is **not** a cryptographic cipher or pseudorandom permutation (PRP) providing confidentiality against chosen-plaintext attacks.

---

## 3. Machine-Checked Formal Verification & Trusted Computing Base (`291` SMT Targets, `3` TCB Sites)

Nona's formal verification surface is machine-checked via Verus and Z3 (`rlimit = 1,000,000`) and locked against regression by the declarative **Lemniscate Assurance Ratchet** (`assurance_policy.json` + `tools/verify_assurance_ratchet.py`).

### 3.1 Breakdown of All 291 Verified Verus SMT Targets (`proofs/verus_verification.log`)

| Module | Verified Domain | Ghost Lemmas | Executive & Boundary Contracts | Total SMT Targets | Errors |
| :--- | :--- | :---: | :---: | :---: | :---: |
| `src/psi.rs` | Zero-axiom 256-bit Solinas modular multiplication, carry/borrow chains, complete $\mathbb{P}^2$ point addition (RCB 2016 Alg 4), 256-bit scalar multiplication ladder, and Tier 3 algebraic/boundary invariants | 61 | 115 | **176** | 0 |
| `src/normalization.rs` | Monomorphic 64-byte stack-window byte sanitizer & delimiter elimination | 0 | 9 | **9** | 0 |
| `src/obfuscation.rs` | 4-round Feistel bijection ($f^{-1}(f(x)) = x$), injectivity, surjectivity & non-identity | 14 | 8 | **22** | 0 |
| `src/allocator.rs` | Static arena 64-byte alignment preservation (`offset % 64 == 0`) & bounds safety | 0 | 2 | **2** | 0 |
| `src/crypto.rs` | Monotonic ghost `ChannelToken` sequence & branchless adaptive VOLE borrow-bit router | 2 | 1 | **3** | 0 |
| `src/enclave_boundaries.rs` | `/dev/nsm` IOCTL/CBOR ABI, session op ceiling, 64-byte vsock framing, FFI disjointness & exception cursor | 3 | 14 | **17** | 0 |
| `proofs/crypto_reductions.rs` | Cyclic subgroup algebra, Bezout inverses, DH-PSI soundness/completeness, DDH self-randomizability & OTP confidentiality | 23 | 39 | **62** | 0 |
| **Total** | **Complete Verified Core & Reduction Surface** | **103** | **188** | **291** | **0** |

### 3.2 Zero Arithmetic Axioms & Exact 3-Site Irreducible TCB (`docs/TCB.md`)
All 4 historical arithmetic `#[verifier::external_body]` axioms in `src/psi.rs` (`FieldElement::mul`, `add_nocarry`, `sub_noborrow`, and `lemma_multi_limb_bit_to_nat`) have been discharged into full machine-checked proofs (`0` arithmetic axioms across the entire repository). Exactly **3** irreducible OS/hardware syscall boundary contracts remain in `src/enclave_boundaries.rs`:

1. `ffi_nsm_ioctl_raw_contract` (`src/enclave_boundaries.rs:50`): Models Linux `/dev/nsm` `ioctl(NSM_IOCTL_RAW)` buffer bounds and return-length invariants.
2. `ffi_clock_monotonic_ns` (`src/enclave_boundaries.rs:202`): Models POSIX `clock_gettime(CLOCK_MONOTONIC)` non-decreasing monotonic timestamps.
3. `ffi_vsock_recv_exact` (`src/enclave_boundaries.rs:211`): Models exact-length `AF_VSOCK` / `AF_UNIX` stream framing (`Ok(n) ==> n == expected_len`).

### 3.3 TLA+ Session State Machine & Specification Mutation Testing
- **TLA+ Model (`specs/vsock_session.tla`, `specs/vsock_session.cfg`):** Exhaustively models `AF_VSOCK` session transitions (`Init`, `Attested`, `Ingested`, `Blinded`, `ClosedZeroized`) under adversarial packet drop, replay, reordering, truncation, and out-of-phase injection, verifying `TypeInvariant`, `DeadlockFreedom`, `SafetyPhaseMonotonicity`, `SafetyFailClosedZeroization`, `SessionCompleteness`, and `LivelockFreedom`.
- **Verus Specification Mutation Fuzzer (`tools/fuzz_verus_specs.py`):** Injects automated semantic mutations into Verus `ensures` postconditions and `requires` preconditions (weakened bounds, flipped signs, dropped zeroization/alignment clauses) and fails closed if any mutant survives verification (**100% mutant kill rate**).

---

## 4. Microarchitectural Side-Channel & Silicon Memory Semantics (`docs/HARDWARE_SEMANTICS.md`)

- **Branchless Constant-Time Arithmetic:** Carry/borrow chains (`add`/`adc` and `sub`/`sbb` on `x86_64`), complete $\mathbb{P}^2$ point addition without exceptional-point branches, fixed 256-step Montgomery ladder (`cmovnz` on `x86_64`, `csel` on `aarch64` with `FEAT_DIT` data-independent timing), and tableless transformations eliminate secret-dependent control flow and cache-line indexing.
- **Oblivious Phase 2 Compaction (`src/psi.rs`):** Phase 2 intersection output assembly executes constant-time conditional selection (`ct_select_u64` / `ct_select_limbs_256`) across all candidate indices rather than branching on match outcomes.
- **Empirical `dudect` Welch's $t$-Statistic Verification:** Evaluated across $\ge 100{,}000$ interleaved traces (`tests/integration/test_timing_boundaries.rs` + external `dudect` harness), enforcing $|t| < 4.5$ and hard bounds on Phase 2 delta (`p2_delta`), with measured $|t| = 0.58$.
- **DSE-Immune Volatile Zeroization & Cross-Architecture Disassembly Audit:** Every secret container (`FieldElement`, `Scalar`, `AlignedKeyBuffer`, `RingSlot`, `EnclaveConnectionSlot`, ephemeral KMS scalars) scrubs memory on drop, error, or signal trap (`SIGINT`/`SIGTERM`) via `core::ptr::write_volatile` followed by `core::sync::atomic::compiler_fence(Ordering::SeqCst)`. `tools/audit_assembly_ct_and_zeroize.py` disassembles the release `#![no_std]` static archive (`libnona_core.a`) on `x86_64` and `aarch64` to verify absence of secret-dependent branches, preservation of volatile zeroing stores against LLVM Dead-Store Elimination (DSE), and compliance with the `<= 1408 B` stack frame ceiling.

---

## 5. AWS Nitro Enclave & KMS `Recipient` Attested Key-Release Protocol (`docs/KMS_ATTESTATION.md`)

To provision session blinding keys without exposing plaintext key material to the untrusted parent EC2 instance (`proxy_bridge`), Nona implements an attested AWS KMS `Recipient` key-release protocol (`AttestedKeyEnvelope` in `src/crypto.rs`, `CMD_KMS_RECIPIENT_UNWRAP` in `src/enclave_server.rs`):

1. **Hardware Entropy & Ephemeral Keypair Generation:** On `CMD_ATTEST`, the enclave draws a 256-bit ephemeral scalar $k_{\text{eph}} \in \mathbb{Z}_q^*$ directly from `/dev/nsm` (`fill_nsm_entropy_or_abort`), derives the 33-byte SEC 1 compressed `secp256k1` public key $P_{\text{eph}} = [k_{\text{eph}}]G$ (`derive_secp256k1_compressed_pubkey`), and binds $\text{SHA-512}(P_{\text{eph}})$ into the NSM attestation `user_data` field alongside the single-use `challenge_nonce` and hardware `PCR0`/`PCR1`/`PCR2` measurements.
2. **KMS Policy Verification & Recipient Encryption:** AWS KMS verifies the Nitro Root CA certificate chain (`src/aws_root_ca.rs`), `COSE_Sign1` ES384 signature, and `kms:RecipientAttestation:PCR0/1/2` key policy conditions before encrypting the session secret $r$ under $P_{\text{eph}}$ (`CiphertextForRecipient`).
3. **In-Enclave EtM Unwrapping & Immediate Ephemeral Destruction:** Upon receiving the 258-byte `AttestedKeyEnvelope`, the enclave validates curve membership of sender ephemeral point $E_{\text{kms}}$, derives domain-separated encryption and MAC keys ($K_{\text{enc}}, K_{\text{mac}}$) from ECDH shared secret $[k_{\text{eph}}]E_{\text{kms}}$, verifies the 128-bit SHA-512 Encrypt-then-MAC tag over `(P_eph, nonce, PCR0, PCR1, PCR2, E_kms, wrapped_key)`, enforces single-use nonce replay rejection and pinned `PCR0`/`PCR1`/`PCR2` equality, and immediately scrubs $k_{\text{eph}}$ via `ct_zeroize` + `SeqCst` fence on both success and failure paths.

---

## 6. Continuous Fuzzing, Supply Chain & Deterministic Reproducibility Guide

### 6.1 Continuous ASan + SanitizerCoverage Fuzzing Suite
Four libFuzzer targets (`fuzz/Cargo.toml`) continuously exercise all untrusted input boundaries under AddressSanitizer and 8-bit SanitizerCoverage (`-runs=500 -max_len=4096` in CI; `make fuzz-smoke` locally):
- `fuzz_ingest`: Raw wire stream deserialization and bounded framing.
- `fuzz_wire_dispatch`: `AF_VSOCK` command dispatch, phase ordering, and error handling.
- `fuzz_c_abi_ffi`: C-ABI FFI pointer alignment, buffer aliasing, and length boundary checks.
- `fuzz_kms_envelope`: Attested KMS `Recipient` envelope parsing, curve validation, and tag authentication.

### 6.2 Step-by-Step Auditor Verification Commands
Independent auditors can verify every mathematical, binary, supply-chain, and policy invariant directly from a clean checkout:

```bash
# 1. Execute the unified read-only audit verification bundle
make audit-bundle

# 2. Verify documentation, TCB axiom count, and version alignment ([AUDIT 1] - [AUDIT 9])
./tools/audit_doc_alignment.sh

# 3. Execute all 22 automated code hygiene, clippy, SPDX, and assembly audits
./tools/check_code_hygiene.sh

# 4. Enforce declarative policy & git-anchored monotonicity against origin/main
python3 tools/verify_assurance_ratchet.py

# 5. Execute the complete host verification suite (TLA+, no_std, SBOM, Verus, spec-fuzz, fuzz-smoke, tests, gates, linkage, sanitizers, assembly)
make host

# 6. Verify pure bare-metal #![no_std] cross-compilation (zero OS / zero alloc)
cargo check --no-default-features --target x86_64-unknown-none
```

### 6.3 CycloneDX v1.5 SBOM & Non-Mutating EIF Reproducibility
- **Supply-Chain Attestation (`nona-core.cdx.json`):** Verified via `make sbom` to conform to CycloneDX v1.5 with zero workstation path leakage and pinned offline dependencies (`vendor/`).
- **Reproducible Nitro EIF Packaging (`tools/build_nitro_eif.sh`):** Uses digest-pinned base images (`Dockerfile.reproducible`), `--frozen --offline` compilation, `--remap-path-prefix`, and `SOURCE_DATE_EPOCH=1700000000` to emit deterministic `.eif` images and SHA-384 `PCR0`/`PCR1`/`PCR2` measurements into `target/enclave/` without mutating tracked `manifests/` unless `--bless-manifest` is explicitly passed.
