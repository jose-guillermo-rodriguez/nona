# High-Assurance Verification Harness (HAVH)

**Specification Version:** 1.0.0-RELEASE  
**Classification:** Canonical Assurance & Invariant Verification Matrix  
**Target Architecture:** `#![no_std]` Static Substrate | AWS Nitro Enclaves  

---

## 1. Assurance Philosophy: Beyond the Testing Pyramid

Nona rejects the traditional "Testing Pyramid" (Unit -> Integration -> End-to-End) in favor of an invariant-driven **High-Assurance Verification Harness (HAVH)**.

The testing pyramid is an empirical framework designed for business-tier applications. It relies on empirical sampling: asserting that an implementation yields an expected output given an anticipated input under benign execution conditions. For zero-allocation, confidential computing cryptographic engines, empirical sampling is epistemologically insufficient:
- It samples a negligible fraction of large input spaces (N ≈ 10^2 vs. 2^256).
- It is blind to CPU microarchitectural side channels and cache timing variance.
- It assumes an ambient operating system allocator (malloc/free) and unconstrained stack frames.
- It treats compiler output as a trusted black box without verifying emitted machine instructions.

Furthermore, empirical testing inherently suffers from **author confirmation bias**: whoever writes the software inevitably encodes their implicit assumptions and boundary blind spots into the test assertions. While human engineers possess retrospective awareness to eventually revisit omissions, relying on memory for cryptographic and memory correctness introduces unacceptable operational risk.

By enforcing external, non-negotiable mathematical proofs and machine-level binary inspections, the HAVH framework replaces trust with mechanical falsification—hardening the engineering pipeline upstream.

---

## 2. The Five Tiers of the HAVH Matrix

```
+------------------------------------------------------------------------+
|             HIGH-ASSURANCE VERIFICATION HARNESS (HAVH)                 |
+-----------------------------------+------------------------------------+
                                    |
    +-------------------------------+-------------------------------+
    |                                                               |
    v                                                               v
+---------------------------------------+   +---------------------------------------+
|     HOST / NATIVE DOMAIN              |   |     HERMETIC CONTAINER DOMAIN         |
|     (Zero Container Overhead)         |   |     (Podman / Docker Isolation)       |
+---------------------------------------+   +---------------------------------------+
| Tier 1: Formal SMT Proofs (122/122)   |   | Tier 2: -Z emit-stack-sizes musl      |
| Tier 2: Zero-Heap Symbol Audit        |   | Tier 3: 100k Cycle dudect Empirical   |
| Tier 2: Sub-4 KiB Mach-O Stack Check  |   | Tier 4: Real-Kernel Signal Traps      |
| Tier 2: C-ABI Bijectivity Gates 1-5   |   | Tier 4: Database C-UDF Frame Purge    |
| Tier 3: Degenerate Timing Invariance  |   | Tier 5: 14-Layer HACVS-V2 Container   |
| Tier 3: 9x Dynamic UBSan Matrix       |   | Tier 5: Scenarios A, B, and C         |
| Tier 4: Remanence Post-Purge Canary   |   | Tier 5: AWS Nitro Enclave EIF & PCRs  |
+---------------------------------------+   +---------------------------------------+
```

### Tier 1: Mathematical Truth (Formal SMT Proofs)
Core algorithms are not merely tested against vectors—they are mathematically proven correct using Verus and Z3:
- **122 / 122 SMT Targets Machine-Checked:** Machine-checked proofs comprising 46 mathematical lemmas and 76 inductive function contracts/state invariants covering secp256k1 finite field arithmetic, constant-time scalar multiplication loops, 4-round Feistel permutations over $\mathbb{Z}_{2^{64}}$ (bijectivity, injectivity, and surjectivity), static arena 64-byte pointer alignment, and sequence monotonicity.
- **State-Space Totality:** Proves total absence of arithmetic overflow, underflow, out-of-bounds indexing, and panics across all 2^256 inputs.
- **Proof Hygiene & Zero-Axiom Invariant (Gate 10):** Mechanical pre-commit scanners reject any raw SMT `assume(...)` directives across the verification boundary, guaranteeing all 122 inductive targets remain strictly machine-checked without unverified assumptions.

### Tier 2: Machine-Level & Binary Invariants
High-assurance software verifies the emitted machine code directly:
- **Sub-4 KiB Machine Stack Frame Ceiling:** Measured during Linux musl compilation via -Z emit-stack-sizes and on Darwin Mach-O binaries via otool disassembly. Peak machine frame is strictly bounded (Peak: 3,584 bytes in nona_phase1_blind <= 4,096-byte limit).
- **Static Zero-Heap Verification:** Release static archives (libnona_core.a) undergo automated inspection via llvm-nm. The presence of any dynamic allocator symbol (malloc, free, realloc, __rust_alloc) immediately halts the pipeline with an error.
- **C-ABI Bijectivity & Layout Contracts:** Mechanical runtime gates enforce exact, collision-free bidirectional mappings across status codes, alignment constraints, and non-overlapping FFI memory buffers.

### Tier 3: Microarchitectural Side-Channel Resistance
Because standard unit testing cannot detect whether data-dependent branches leak secrets across the CPU cache, Tier 3 introduces statistical execution verification:
- **Empirical Timing Neutrality (dudect Audit):** Constant-time cryptographic flows are evaluated across $10^5$ samples with Welch's two-sample t-statistic, enforcing $|t| < 4.5$ to confirm that execution duration remains uncorrelated with input secrets (validated via external dudect audit harness at $|t| = 0.58$ under hardware carry/borrow-chain arithmetic).
- **Degenerate Scalar Invariance:** Validates that operations involving edge-case parameters (point at infinity, generator identity, zero scalars) execute within a < 2% timing variance ratio compared to pseudo-random coordinates.
- **Dynamic Sanitizer Matrix:** 9 dedicated C-ABI test runners execute under UndefinedBehaviorSanitizer (UBSan) and AddressSanitizer (ASan) with -fno-sanitize-recover=all.

### Tier 4: Memory Remanence & Operational Hygiene
Confidential computing models mandate that sensitive memory must not persist in DRAM:
- **Zero Remanence (H(R) = 0):** High-assurance memory canaries verify that volatile memory regions are zeroized immediately after execution, confirming zero residual entropy.
- **Asynchronous Signal Decontamination:** Enclosing runtime supervisors intercept POSIX process termination signals (SIGINT, SIGTERM) to trigger synchronous volatile scrubs (`nona_ct_zeroize`) across active memory buffers before handing control to the host kernel.
- **Core Dump Suppression:** RLIMIT_CORE limits are programmatically set to zero
- **Fail-Closed Hardware Trapping (Gate 11):** Bare-metal enclave panic handlers are forbidden from executing non-terminating spin loops. Panics must emit explicit invalid instruction traps (`ud2` on x86_64, `brk` on aarch64) to ensure hypervisor-level fail-closed termination. (via feature = "host-defense" on POSIX hosts; bare-metal enclaves execute with zero crash dumping facilities) to prevent crash dumps from persisting plaintext cryptographic state on host disks.

### Tier 5: Supply-Chain Hermeticity & Cryptographic Attestation
- **Deterministic Reproducibility:** Hermetic container configurations pin compiler base images and set explicit timestamps (SOURCE_DATE_EPOCH=1700000000) to eliminate build-time variance down to the individual bit.
- **Platform Configuration Register (PCR) Calculation:** AWS Nitro Enclave packaging scripts calculate cryptographic measurements (PCR0: Enclave Image, PCR1: Linux Kernel/Boot, PCR2: Application IAM/Metadata) to allow remote verifying parties to validate enclave integrity.
- **Footprint Constraint:** Enclave binary footprint is enforced strictly below 16 MB (Current: 397,488 bytes).
- **Negative Attestation & Manifest Falsification:** Mechanical suites verify that the client attestation verifier fails closed when encountering dummy signatures, broken certificate paths, or deceptive JSON manifest key structures.

---

## 3. Operational Interface

The harness provides three entry points via the root Makefile:

- Host Native Suite (Instantaneous feedback, zero container required): `make host`
- Hermetic Container Suite (Requires active Podman or Docker daemon): `make container-all`
- Unified End-to-End Certification: `make all`
