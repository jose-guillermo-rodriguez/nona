# Nona Core Engine: Threat Model & Adversarial Host Boundaries

**Specification Version:** 1.1.0-HARDENING  
**Classification:** Authoritative Security Architecture, STPA Hazard Analysis & PASTA Threat Decomposition  
**Target Environments:** AWS Nitro Enclaves (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`) | `#![no_std]` Bare-Metal  

---

## 1. Zero-Trust Host Adversary Model & Architectural Boundaries

Nona operates under a strict **Zero-Trust Host Model** with zero benign host assumptions. In confidential computing deployments on AWS Nitro Enclaves, the parent EC2 operating system, hypervisor control plane, kernel drivers, host storage, network interfaces, and co-resident virtual machines are treated as actively malicious, compromised, or under full adversarial control.

### 1.1 Trusted Computing Base (TCB) Perimeter
The Trusted Computing Base is restricted to:
1. Hardware-isolated enclave vCPUs and encrypted physical memory carve-out (AWS Nitro Hypervisor hardware memory isolation).
2. The AWS Nitro Security Module (`/dev/nsm`) hardware root of trust and ECDSA-P384 attestation signing engine.
3. The `#![no_std]` zero-heap core static archive (`libnona_core.a`) and statically linked musl enclave daemon (`nona_enclave`).
4. The FFI Gatekeeper (`src/gatekeeper.rs`), vsock framing boundary (`src/enclave_server.rs`), and machine-checked Verus cryptographic primitives (`src/psi.rs`, `src/crypto.rs`, `src/obfuscation.rs`, `src/enclave_boundaries.rs`).

### 1.2 Adversarial Host Capabilities
The untrusted parent host and intermediary transport proxy possess full capability to:
- Inspect, drop, duplicate, replay, reorder, truncate, or bit-flip every byte crossing the `AF_VSOCK` (CID/port 5005) or `AF_UNIX` transport channel.
- Supply hostile, unaligned, overlapping (Iago), or integer-overflowing pointer/length arguments across C-ABI boundaries.
- Manipulate host wall-clock time (`CLOCK_REALTIME` / NTP / hypervisor RTC) arbitrarily forward or backward (time-warp attacks).
- Schedule co-resident host workloads on shared physical CPU sockets, shared L3 last-level caches (LLC), or sibling SMT/hyperthreading logical cores to observe cache-line contention and execution timing.
- Withhold `/dev/nsm` access or attempt to inject degraded/zero entropy across hypervisor IOCTL boundaries.

---

## 2. Systems-Theoretic Process Analysis (STPA) Control-Loop Hazard Analysis

To eliminate emergent boundary failures arising from unsafe interactions between the untrusted parent host and the isolated enclave controller, Nona models the host-enclave interface as a formal **STPA Control Loop**.

### 2.1 Hierarchical Control Structure

```
+-----------------------------------------------------------------------+
|  UNTRUSTED PARENT HOST / HYPERVISOR PROXY (Adversarial Intermediary)  |
|  - Controls: AF_VSOCK virtio rings, host wall-clock, scheduling, IPC  |
+-------------------+-----------------------------------+---------------+
                    | Control Actions (Wire Frames)     ^ Feedback (Opaque
                    v                                   | Status & Ciphertext)
+-----------------------------------------------------------------------+
|  ENCLAVE INGRESS CONTROLLER (enclave_server.rs & gatekeeper.rs)       |
|  - Enforces: 64-byte header framing, recv_exact, phase state machine, |
|    pointer disjointness, alignment, wire floor pacing (250 us)        |
+-------------------+-----------------------------------+---------------+
                    | Validated Session Commands        ^ Hardware Entropy &
                    v                                   | COSE_Sign1 Quote
+-----------------------------------------------------------------------+
|  CRYPTOGRAPHIC EXECUTION CORE & /dev/nsm BOUNDARY                     |
|  - Enforces: ChannelToken op ceilings, constant-time Montgomery       |
|    ladder, ct_zeroize (write_volatile + SeqCst), fail-stop NSM IOCTL  |
+-----------------------------------------------------------------------+
```

### 2.2 System-Level Losses (L) and Hazards (H)

| Loss ID | System-Level Loss Definition | Associated Hazards |
| :--- | :--- | :--- |
| **L-1** | Disclosure of enclave ephemeral private scalar $k_b$ or plaintext PSI input elements $x_i, y_j$. | **H-1**, **H-3**, **H-4** |
| **L-2** | Execution of Phase 1 blinding or Phase 2 reblinding/intersection out of cryptographic sequence or on an unattested channel. | **H-2**, **H-5** |
| **L-3** | Acceptance of a replayed, expired, or MITM-substituted attestation document by the client or enclave. | **H-2**, **H-6** |
| **L-4** | Persistence of secret scalars, intermediate projective coordinates, or plaintext payloads in DRAM after session completion or abort ($H(R) > 0$). | **H-1**, **H-4** |

- **H-1 (Memory Boundary & Remanence Hazard):** Host-supplied buffers alias enclave stack frames, exceed 64-byte alignment/size ceilings, or leave non-zeroed secret state in staging slots or DRAM across session teardown or signal traps.
- **H-2 (Protocol Phase-Ordering Hazard):** Vsock command frames (`CMD_INGEST`, `CMD_BLIND_PHASE1`, Phase 2 reblinding/intersection) execute out of monotonic session order or without prior `/dev/nsm` attestation key binding.
- **H-3 (Microarchitectural Side-Channel Hazard):** Secret-dependent branches, memory indexing, variable-time wire error responses, or shared L3/SMT contention leak private scalar bits or set cardinality.
- **H-4 (Entropy Starvation / Fallback Hazard):** Enclave key generation proceeds with degraded, zero, or host-predicted entropy when `/dev/nsm` fails.
- **H-5 (Transport Framing & Replay Hazard):** Truncated, duplicated, reordered, or corrupted vsock frames cause partial reads, state desynchronization, or replay of prior blinding/attestation responses.
- **H-6 (Temporal Integrity / Time-Warp Hazard):** Hypervisor clock skew causes premature/delayed session expiration, certificate validity bypass, or challenge nonce reuse.

### 2.3 Unsafe Control Actions (UCAs) & Enclave Safety Constraints

| Control Action | Not Providing | Providing Incorrectly / Out-of-Order | Wrong Timing / Replay / Time-Warp | Stopped Too Soon / Truncated | Enforced Enclave Safety Constraint |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`CMD_ATTEST` Handshake** | **UCA-1:** Host drops attestation request or response, stalling session establishment. | **UCA-2:** Host substitutes rogue public key or malformed CBOR/COSE structure. | **UCA-3:** Host replays prior attestation quote or warps `CLOCK_REALTIME` backward to validate expired certs. | **UCA-4:** Host truncates COSE_Sign1 payload or certificate chain mid-stream. | Client binds 256-bit OS CSPRNG nonce + `CLOCK_MONOTONIC` RTT (`<= 30s`) + monotonic HWM; enclave binds `sha512(pubkey)` into hardware-signed `user_data`. |
| **`CMD_INGEST` (128B Ring Push)** | **UCA-5:** Host withholds stream chunks indefinitely. | **UCA-6:** Host sends unaligned lengths (`len % 128 != 0`), oversized payloads (`> 4096 B`), or injects `CMD_INGEST` pre-attestation. | **UCA-7:** Host floods ring buffer beyond 128-slot capacity (`occupied_mask == u128::MAX`). | **UCA-8:** Host closes socket mid-frame after header transmission. | `recv_exact` enforces full frame receipt; `check_ring_ingest_preflight` rejects unaligned/overflowing frames; `EnclaveConnectionSlot` purges on drop. |
| **`CMD_BLIND_PHASE1` / Phase 2 Ops** | **UCA-9:** Host drops blinding response, forcing client timeout. | **UCA-10:** Host injects Phase 2 intersection before Phase 1 blinding, or submits non-curve affine coordinates ($x \ge p$ or $y^2 \not\equiv x^3 + 7$). | **UCA-11:** Host replays Phase 1 frames to exceed session operation ceiling (`MAX_SESSION_OPS`). | **UCA-12:** Host terminates connection mid-scalar-multiplication or sends `SIGTERM`/`SIGINT`. | Formal phase monotonicity (`specs/vsock_session.tla`); `ChannelToken` monotonic op ceiling (`1,000,000`); `NONA_ERR_INVALID_CURVE_POINT` (-13); `ct_zeroize` on drop & signal trap. |
| **FFI C-ABI Entry Points** | **UCA-13:** Caller passes null output/key pointer. | **UCA-14:** Caller passes overlapping `in_ptr` and `out_ptr` (Iago aliasing) or unaligned pointers. | **UCA-15:** Caller triggers concurrent re-entrancy on shared ingest ring. | **UCA-16:** Caller supplies `out_len < expected_out_len`. | `nona_validate_ffi_bounds` enforces non-null, 64-byte alignment, strict interval disjointness, and bounded lengths before touching memory. |

---

## 3. Process for Attack Simulation and Threat Analysis (PASTA) Decomposition

Nona structures adversarial host threat modeling across the seven PASTA stages:

1. **Stage 1 — Security & Assurance Objectives:** Maintain cryptographic confidentiality of private scalars ($H(R) = 0$ post-execution), zero-knowledge blindness of non-intersecting set elements, deterministic fail-closed termination on any protocol anomaly, and microarchitectural timing neutrality ($|t| < 4.5$).
2. **Stage 2 — Technical Scope & Attack Surface Enumeration:**
   - Surface A: Untrusted host shared memory rings, virtio-vsock transport buffers, and C-ABI FFI pointer parameters.
   - Surface B: `AF_VSOCK` binary wire framing (`EnclaveRequestHeader` / `EnclaveResponseHeader`).
   - Surface C: CPU microarchitecture (L3 cache hierarchy, SMT/hyperthreading execution units, branch target buffers, store buffers).
   - Surface D: Hypervisor virtualized time sources (`CLOCK_REALTIME` vs. `CLOCK_MONOTONIC`) and `/dev/nsm` IOCTL boundary.
3. **Stage 3 — Application Decomposition & Trust Boundaries:** All external frames enter `handle_enclave_client_with_staging` into 64-byte aligned `EnclaveConnectionSlot` buffers (`in_buffer`, `out_buffer`, `scratch_buffer`, `attestation_doc`) governed by RAII `StagingBufferGuard` (`Drop` -> `purge()`).
4. **Stage 4–6 — Threat Simulation & Attack Surface Mitigations:** Detailed below across the four primary adversarial host attack vectors.
5. **Stage 7 — Residual Risk & Verification Mapping:** Every mitigation is bound to automated falsification gates in `Makefile` (`verify-models`, `formal`, `gates`, `linkage`, `sanitizers`).

### 3.1 Untrusted Shared Memory Rings & DMA/MMIO Boundary Surfaces
- **Threat Simulation:** A malicious parent kernel or compromised device driver manipulates virtio-vsock shared memory rings, attempts DMA/MMIO remapping into enclave physical pages, triggers core dumps / swap-out of sensitive pages, or executes Iago memory-aliasing attacks across C-ABI boundaries.
- **Architectural Controls:**
  - **Hypervisor Memory Carve-Out & IOMMU Isolation:** AWS Nitro Enclaves execute in dedicated physical memory pages carved out by the Nitro hypervisor with zero host page-table mappings, zero persistent block storage, and zero external NIC access; virtio-vsock mediates strictly serialized byte streams.
  - **Bounce-Buffered 64-Byte Aligned Staging:** Untrusted wire payloads are copied via `recv_exact` into statically allocated, 64-byte cache-line aligned `EnclaveConnectionSlot` buffers (`ENCLAVE_STAGING_POOL_SLOTS = 16`) before cryptographic processing, preventing TOCTOU mutations on shared ring memory.
  - **Iago Pointer & Bounds Gatekeeper (`src/gatekeeper.rs`):** `nona_validate_ffi_bounds` enforces non-null pointers, 64-byte alignment (`(ptr as usize) & 63 == 0`), integer wraparound checks (`base.checked_add(len)`), and strict spatial disjointness (`a_end <= b_start || b_end <= a_start`) prior to dereferencing any pointer.
  - **OS Memory Disclosure Hardening (`harden_enclave_process`):** Sets `RLIMIT_CORE = 0`, invokes `prctl(PR_SET_DUMPABLE, 0)`, marks `SESSION_KEY` and `STAGING_POOL` with `madvise(..., MADV_DONTDUMP)`, and pins pages with `mlockall(MCL_CURRENT | MCL_FUTURE)` under `host-defense`.

### 3.2 Vsock Packet Injection, Replay, Truncation, Reordering & Asymmetric Delay
- **Threat Simulation:** The parent host vsock proxy injects out-of-phase commands (e.g., `CMD_BLIND_PHASE1` before `CMD_ATTEST`), replays captured `CMD_ATTEST` or blinding frames across sessions, truncates 64-byte headers or payloads, reorders queued frames, or introduces asymmetric delays to measure response timing differences.
- **Architectural Controls:**
  - **Exact Fixed-Header Framing:** `EnclaveRequestHeader` and `EnclaveResponseHeader` are fixed 64-byte cache-aligned structures (`NONA_VSOCK_MAGIC = 0x4E4F4E41`, `NONA_VSOCK_VERSION = 1`). `recv_exact` and `send_exact` loop until exact byte counts are transferred or fail closed on EOF/error.
  - **Opaque Error Oracle Suppression:** Any parsing, bounds, curve validation, or phase violation maps to a single opaque wire error code (`NONA_WIRE_ERR_OPAQUE = -1`) with zero error-specific payload bytes, preventing oracle-assisted probing.
  - **Constant-Floor Wire Pacing (`WIRE_FRAME_FLOOR_NS`):** `enforce_wire_frame_floor` pads every wire frame response to a minimum 250-microsecond floor measured against `CLOCK_MONOTONIC`, eliminating early-exit timing leaks on malformed headers or rejected frames.
  - **Fail-Closed Connection Teardown & Formal Model:** On any error status (`wire_status != 0`), `handle_enclave_client_with_staging` immediately purges the connection slot (`slot.purge()`) and closes the socket (`libc::close(client_fd)`). Exhaustive state-space verification under arbitrary packet drop, duplication, reordering, truncation, and out-of-phase injection is specified in `specs/vsock_session.tla`.

### 3.3 Shared L3 Cache-Line Contention, SMT/Hyperthreading Co-Residency & Microarchitectural Timing Channels
- **Threat Simulation:** On multi-tenant or parent-host-scheduled physical sockets, an adversary co-schedules spy threads on sibling SMT/hyperthreading cores or monitors shared L3 cache sets (Prime+Probe, Evict+Time, Flush+Reload, execution port contention) while the enclave executes scalar multiplication or index permutation.
- **Architectural Controls:**
  - **Single-Threaded Non-Concurrent Enclave Substrate:** The core cryptographic engine executes strictly single-threaded with zero intra-enclave shared-memory worker threads, eliminating internal lock contention and cross-thread cache thrashing. Production Nitro Enclave deployments allocate dedicated physical cores (`--cpu-count 2` isolates full physical core pairs without host SMT sharing).
  - **64-Byte Cache-Line Isolation & Explicit Cache Eviction:** All secret-bearing structures (`FieldElement`, `Scalar`, `AlignedKeyBuffer`, `RingSlot`, `EnclaveConnectionSlot`) are `#[repr(C, align(64))]` to prevent false sharing across cache lines. `ZeroCopyRingBuffer::flush_and_fence_slot` executes explicit cache-line flushes (`_mm_clflush` on `x86_64`, `dc cvac` on `aarch64`) bracketed by `Acquire`/`Release` memory fences after slot decontamination.
  - **Zero Secret-Dependent Branches or Table Lookups:** Scalar multiplication uses a fixed 256-step Montgomery ladder with complete homogeneous $\mathbb{P}^2$ addition (RCB 2016 Algorithm 4) and branchless conditional moves (`cmovnz` on `x86_64`, `csel` on `aarch64`), eliminating cache-line access patterns dependent on secret scalar bits.
  - **Empirical Statistical Verification:** Continuous `dudect` regression testing validates Welch's two-sample $|t| < 4.5$ across $\ge 100{,}000$ samples (recorded $|t| = 0.58$).

### 3.4 Hypervisor-Controlled Clock Skew (Time-Warp Attacks) & Monotonic/Challenge-Nonce Defenses
- **Threat Simulation:** A compromised hypervisor or host OS slews or steps `CLOCK_REALTIME` (`SystemTime`) backward by years to resurrect expired COSE_Sign1 attestation documents or X.509 certificates, or steps time forward to expire active sessions prematurely or induce nonce collisions.
- **Architectural Controls:**
  - **Complete Isolation from Untrusted Wall-Clock Time:** Live attestation (`NonaClient::attest_and_bind`) never reads `SystemTime` or `CLOCK_REALTIME`.
  - **256-Bit OS CSPRNG + Monotonic Counter Challenge Nonces:** `generate_client_challenge_nonce` hashes 32 bytes of `/dev/urandom` entropy, monotonic `Instant::elapsed()` nanoseconds, and a strictly increasing `AtomicU64` sequence counter via SHA-512, ensuring nonces never repeat even if system clocks are frozen or reversed.
  - **Monotonic Round-Trip Interval Bound:** Challenge-response latency is measured via local `CLOCK_MONOTONIC` (`Instant`) and rejected if `rtt_ns > MAX_CHALLENGE_RESPONSE_INTERVAL_NS` (30 seconds), defeating slow-relay and offline replay attacks.
  - **Monotonic High-Water Marks & Operation Ceilings:** `enforce_monotonic_attest_hwm` rejects any hardware-signed NSM timestamp that regresses below previously observed attestation timestamps (within a bounded 60-second tolerance). Detached verification uses `advance_monotonic_reference_secs` anchored to `Instant` so reference time can never move backward. Inside the enclave, `advance_session_op_counter` enforces a hard `MAX_SESSION_OPS = 1_000_000` ceiling via `AtomicU64` CAS, purging the session key unconditionally upon exhaustion without querying any clock.

---

## 4. Out-of-Scope Threats & Physical Assumptions

1. **Invasive Physical Silicon Attacks:** Decapping, focused ion beam (FIB) probing, laser fault injection, or physical DRAM cold-boot extraction on bare-metal blades outside AWS Nitro hardware memory encryption.
2. **Unpatched Hardware Errata Lacking Microcode/Firmware Mitigation:** Zero-day silicon microarchitectural vulnerabilities where neither CPU microcode updates nor compiler/barrier mitigations exist.
3. **Compromise of AWS Nitro Hardware Root CA:** Compromise of the offline Amazon Nitro Enclaves Root CA private key or NSM hardware fuse secrets.
