# Nona Core Engine: Threat Model & Security Boundaries

**Specification Version:** 1.0.0-RELEASE
**Classification:** Authoritative Security Architecture & Adversary Model
**Target Environments:** AWS Nitro Enclaves | #![no_std] Bare-Metal

---

## 1. Adversary Model & Trust Architecture

Nona operates under a Zero-Trust Host Model. In confidential computing, the host operating system, hypervisor, kernel drivers, and adjacent virtual machines are assumed to be malicious, compromised, or untrusted.

The Trusted Computing Base (TCB) consists strictly of:
- Hardware-isolated vCPU and physical memory (AWS Nitro Enclave)
- The #![no_std] core engine static archive (libnona_core.a)
- The Gatekeeper validation boundary (bounds, disjointness, alignment)
- Formally verified constant-time cryptographic primitives

All external interactions pass across the AF_VSOCK / C-ABI boundary, where all inputs are treated as untrusted and potentially adversarial.

---

## 2. In-Scope Threats & Defensive Guarantees

### 2.1 Iago Attacks (Hostile ABI & Memory Aliasing)
- Threat: A compromised host passes overlapping pointer regions, unaligned addresses, or pointers that alias internal enclave stack variables.
- Defense: The gatekeeper module validates pointer alignment (64-byte boundaries), buffer bounds, and memory disjointness before reading or writing data: is_disjoint(ptr_A, len_A, ptr_B, len_B) == 1. Any boundary violation immediately aborts execution without memory corruption.

### 2.2 Wire Deserialization & Framing Corruption
- Threat: The host injects truncated packets, oversized frames, or malformed protocol magic over the VSOCK interface.
- Defense: Deserialization is bounded by a strict 64-byte window. Packet headers, framing limits, and command opcodes are validated with bijective status codes (nona_status_t). Malformed wire boundaries fail closed.

### 2.3 Microarchitectural Side-Channel Leakage
- Threat: The host monitors CPU cache lines, execution time, or branch predictors to infer private set intersection elements.
- Defense:
  - Complete elimination of secret-dependent branches and memory lookup tables.
  Constant-time execution is structurally enforced via branchless straight-line arithmetic (unrolled hardware carry/borrow chains `add`/`adc`, `sub`/`sbb`, branchless selection `ct_select_u64`/`ct_cmov`, and complete group laws RCB 2016 Alg 4). Microarchitectural timing neutrality is validated under Welch's two-sample t-test ($|t| < 4.5$ over $10^5$ samples via external dudect audit harness; benchmark validation recorded $|t| = 0.58$).
  - Degenerate scalar timing invariance verified within < 2% timing variance.

### 2.4 Cold Boot & Memory Remanence (H(R) = 0)
- Threat: Secrets persist in volatile DRAM after process termination or abnormal exits.
- Defense:
  - Context drop and purge routines execute volatile zeroization bounded by compiler memory barriers (compiler_fence(Ordering::SeqCst)) to eliminate compiler dead-code elimination.
  The `#![no_std]` core static library enforces deterministic volatile zeroization on all drop/exit paths and panics via `ct_zeroize` and `zeroize_and_abort`. For POSIX process termination signals (SIGINT, SIGTERM), the enclosing runtime daemon or enclave supervisor intercepts signals and invokes `nona_ct_zeroize` prior to process termination.
  - Core dump generation is programmatically disabled via RLIMIT_CORE = 0 (enabled via feature = "host-defense" on POSIX hosts; native bare-metal enclaves execute without core-dump facilities).

### 2.5 Malicious Entropy Injection
- Threat: The host hypervisor returns degraded, static, or predictable random numbers to weaken blinding factors.
- Defense: Entropy is harvested solely via direct `/dev/nsm` `GetRandom` IOCTL requests. Short reads, all-zero blocks, device unavailability, or harvest failures trigger an immediate `zeroize_and_abort(NONA_ERR_INTERNAL_PANIC)` with zero fallback to CPU RNG instructions, OS syscalls, or system clocks.

---

## 3. Out-of-Scope Threats

1. Hardware Fault Injection: Physical electron microscopy, decapping, or voltage glitching of the physical silicon die.
2. Side-Channels in Unpatched Silicon: Hardware-level speculative execution vulnerabilities lacking microcode mitigation.
3. Compromised Hardware Root CA: Compromise of the Amazon Nitro Root CA private signing keys.
