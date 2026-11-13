# Security Policy & Threat Model

**Specification Version:** 1.0.0-RELEASE  
**Baseline Implementation:** Release v1.0.0 Formally Verified & Sealed  

**Project:** Nona Core Engine  
**Classification:** Confidential Computing & OEM High-Assurance Cryptographic Substrate  
**Target Environments:** AWS Nitro Enclaves (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`), `#![no_std]` Bare-Metal  
**Verification Level:** 146 Machine-Checked Verus SMT Verification Targets (0 Errors)

---

## 1. Scope & Security Objectives

Nona is an OEM cryptographic engine engineered for Private Set Intersection (PSI), vectorized database UDF acceleration, elastic byte normalization, and constant-time index obfuscation within hardware-enforced Trusted Execution Environments (TEEs).

The primary security objectives are:
1. **Confidentiality:** Zero leakage of private sets, secret scalar keys, intermediate point coordinates, or unmasked permutation states to the host operating system, hypervisor, or co-located tenants.
2. **Integrity:** Protection against malicious manipulation of intersection results, vector states, or memory layouts by compromised parent instances or hypervisors.
3. **Non-Repudiation & Attestation:** Enclave measurements (PCR0, PCR1, PCR2) cryptographically bind executing code and configuration to reproducible, publicly verifiable source commits.

---

## 2. Comprehensive Threat Model

### 2.1 Attacker Capabilities & Trust Boundaries

| Boundary Layer | Trust Assumption | Security Posture & Mitigations |
| :--- | :--- | :--- |
| **Enclave Hardware (TEE)** | **Trusted** | Relies on hardware-enforced CPU isolation (AWS Nitro security chip / SEV-SNP / CCA). Enclave memory is hardware-isolated from the parent EC2 instance. |
| **Enclave Firmware & Kernel** | **Trusted** | Stripped Linux kernel pinned to deterministic SHA-256 digest with immutable initramfs. |
| **Nona Engine Core** | **Trusted** | `#![no_std]`, zero dynamic heap allocation, verified by 146 Verus SMT verification targets across core algebraic and memory invariants. |
| **Parent EC2 Host OS** | **Untrusted** | Assumed fully compromised (malicious root access, rogue drivers, compromised kernel). The parent cannot read, write, or interrupt enclave memory directly. |
| **Host Hypervisor** | **Untrusted** | Hypervisor has no direct memory snooping capability into the Nitro Enclave memory space. All I/O is restricted to `AF_VSOCK`. |
| **Network & Transit** | **Untrusted** | All data entering or exiting the enclave across `AF_VSOCK` must be authenticated and decrypted within the enclave boundary. |

### 2.2 Physical Memory Snooping & Cold-Boot Mitigations

Even under hostile physical memory tap or unexpected instance termination:
- **Zero Dynamic Heap Allocations:** Eliminates heap fragmentation, dangling pointers, and residual artifacts in free lists. All buffers reside in stack frames or 64-byte aligned static memory (`StaticArena<N>`).
- **Volatile Entropy Collapse:** Upon context termination, drop, or interrupt signal, all buffers containing private scalars or coordinates undergo constant-time zeroization ($H(W) = 0$). Memory barriers (`compiler_fence(Ordering::SeqCst)`) prevent LLVM Dead-Code Elimination (DCE).

### 2.3 Microarchitectural & Speculative Execution Side Channels

- **Branchless Arithmetic:** All scalar multiplication, Montgomery powering ladders, and modular reduction paths are branchless with data-independent execution profiles.
- **Timing Invariance:** Enforces $\Delta\tau \le 1$ CPU cycle and $|t| < 4.5$ under Welch's t-test across $\ge 100{,}000$ execution traces.
- **Speculative Execution Barriers:** Critical coordinate transformations and permutation stages employ memory fences (`core::sync::atomic::compiler_fence`) to prevent out-of-order execution leakage across speculative windows.

### 2.4 Cache-Timing & Vector SIMD Invariants

- **Tableless Transformations:** AES and normalization routines avoid data-dependent lookup tables (S-Boxes in RAM) to eliminate cache-line collision attacks.
- **Cache-Line Alignment:** Structures crossing FFI boundaries or vector operations are 64-byte aligned (`#[repr(C, align(64))]`), preventing false sharing and cache-straddling timing variance.
- **Vectorized Register Scrubbing:** AVX-512 and ARM Neon registers holding intermediate state are cleared via vector zeroing intrinsics immediately upon loop termination.

---

## 3. Cryptographic Invariants & Verification Guarantees

- **SMT Arithmetic Boundary Theorems:** 146 machine-checked Verus SMT targets (50 mathematical lemmas and 96 verified executive & boundary contracts) verify no integer overflow, underflow, or memory out-of-bounds indexing occurs across core cryptographic paths.
- **Stack Budget:** Single-frame context size is bounded at $\le 2{,}560$ bytes. Overall machine stack frame ceiling is strictly bounded at $\le 4{,}096\text{ bytes}$ (peak measured frame: 3,584 bytes in `nona_phase1_blind`), safeguarded by stack-pointer assertions and recommended `-C probe-stack` compiler options.
- **Zero Dynamic Symbol Linkage:** Enclave release binaries disallow dynamic linking to heap allocation symbols:
  $$\text{count}(\text{symbols} \in \{\text{malloc}, \text{free}, \text{realloc}, \text{calloc}, \text{\_\_rust\_alloc}\}) = 0$$

---

## 4. Coordinated Vulnerability Disclosure (CVD)

We welcome vulnerability reports from security researchers and auditors under our Coordinated Vulnerability Disclosure process.

### 4.1 Reporting a Security Vulnerability

If you discover a security vulnerability or timing leakage within the Nona Core Engine:
- **Do not open a public GitHub issue.**
- Submit reports via encrypted email to: `security@nona-engine.internal` or via GitHub Private Vulnerability Reporting.
- Include:
  1. Detailed description of the vulnerability (arithmetic flaw, side-channel observation, memory bounds bypass).
  2. Complete environment specifications (CPU model, microcode version, host OS, hypervisor, target architecture).
  3. Reproducible proof-of-concept (PoC) code or script.
  4. Trace logs or Welch's t-test data (for side-channel claims).

### 4.2 Response Timetable & SLA

- **Initial Acknowledgment:** Within **24 hours** of submission.
- **Triage & Reproducibility Assessment:** Within **72 hours**.
- **Remediation & Patch Target:** Critical issues patched within **14 calendar days**.
- **Coordinated Disclosure:** Public disclosure occurs only after an enclave image update and PCR manifest release have been made available.

### 4.3 Safe Harbor

Activities conducted in good-faith compliance with this policy are considered authorized, and we will not pursue legal action against researchers for research adhering to these guidelines.
