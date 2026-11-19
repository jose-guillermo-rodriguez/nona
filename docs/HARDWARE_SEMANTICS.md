# Nona Core Engine: Silicon Semantic Gap Analysis

**Specification Version:** 1.1.0-HARDENING  
**Classification:** Microarchitectural Memory Consistency, Speculation & Compiler Semantics Audit  
**Target Architectures:** `x86_64` (AWS Nitro Intel Xeon / AMD EPYC) | `aarch64` (AWS Graviton3 Neoverse V1 / Apple Silicon)  

---

## 1. Bridging the Abstract Machine to Physical Silicon

Formal verification in Verus/Z3 proves mathematical correctness over Rust's abstract operational semantics, and Rust's ownership model enforces memory safety at the source level. However, physical processors execute instructions out of order, buffer stores in private store queues, speculate across branches and memory disambiguators, and optimize register allocation via LLVM backend passes.

This document audits the semantic gap between Nona's Rust/Verus guarantees and physical execution on `x86_64` and `aarch64` silicon across four critical hardware surfaces:
1. Memory consistency models and store-buffer visibility (`TSO` vs. `aarch64` weak memory ordering).
2. Out-of-order execution boundaries, branch-predictor isolation, and speculative execution barriers.
3. Dead-Store Elimination (DSE) prevention and register/stack spill exposure surfaces.
4. Architecture-specific CPU errata and microarchitectural timing behaviors.

---

## 2. Memory Consistency Models: `x86_64` TSO vs. `aarch64` Weak Memory Ordering

### 2.1 Architectural Ordering Comparison

| Memory Ordering Dimension | `x86_64` Total Store Order (TSO) | `aarch64` Weak Memory Ordering (ARMv8.5 / Neoverse V1 / Apple Silicon) | Nona Security Implication |
| :--- | :--- | :--- | :--- |
| **Load $\rightarrow$ Load** | Preserved in program order | **Reordering permitted** across independent addresses | Ring-buffer consumer reads and status flag checks require explicit `Acquire` ordering. |
| **Load $\rightarrow$ Store** | Preserved in program order | **Reordering permitted** across independent addresses | Secret key load followed by status update cannot rely on implicit hardware ordering on `aarch64`. |
| **Store $\rightarrow$ Store** | Preserved in program order (FIFO store buffer) | **Reordering permitted** across independent cache lines | Zeroizing a secret buffer before clearing `occupied_mask` or `ACTIVE_BUFFER` can be reordered on `aarch64` without hardware fences. |
| **Store $\rightarrow$ Load** | **Reordering permitted** (store-buffer forwarding to local loads) | **Reordering permitted** across independent addresses | Local loads can speculatively bypass earlier stores to different addresses on both architectures. |
| **Multi-Copy Atomicity** | Guaranteed (stores become visible to all cores simultaneously once drained from store buffer) | Other-multi-copy atomic (ARMv8.0+); requires `DMB ISH` / `STLR` for cross-core visibility | Slot decontamination must complete globally before releasing slot ownership. |
| **Cache Maintenance Ordering** | `CLFLUSH` ordered w.r.t. `MFENCE` and locked instructions | `DC CVAC` is **not** ordered w.r.t. normal loads/stores without `DSB ISH` | `aarch64` cache clean requires explicit `Release` / `DSB` barrier sequencing. |

### 2.2 Audit of Nona Fence & Synchronization Primitives

1. **`core::sync::atomic::compiler_fence(Ordering::SeqCst)`:**
   - **Locations:** `src/crypto.rs` (`ct_select_u64`, `ct_eq_32_bytes`, `ct_zeroize`), `src/psi.rs` (Montgomery ladder step, SWU, batch inversion), `src/gatekeeper.rs`, `src/lib.rs`.
   - **Hardware Emission:** Emits **zero** hardware barrier instructions on both `x86_64` and `aarch64`. It acts strictly as an LLVM scheduling barrier preventing the compiler from hoisting, sinking, or merging memory operations across the fence boundary.
   - **Design Rationale:** Inside single-threaded constant-time arithmetic loops (such as the 256-step Montgomery ladder), `compiler_fence(Ordering::SeqCst)` prevents LLVM from coalescing conditional moves into branches or reordering volatile zeroization stores without incurring a ~20–40 cycle `MFENCE`/`DMB` penalty on every bit iteration.

2. **`core::sync::atomic::fence(Ordering::SeqCst)` / `Acquire` / `Release`:**
   - **Locations:** `src/lib.rs` (`unregister_active_buffer`), `src/ring_buffer.rs` (`flush_and_fence_slot`), and `AtomicBool`/`AtomicU8`/`AtomicU64` CAS operations in `src/ingest.rs` and `src/enclave_server.rs`.
   - **Hardware Emission:**
     - On `x86_64`: `Ordering::SeqCst` emits `mfence` (or `lock or byte ptr [rsp], 0`), draining the local store buffer before subsequent loads execute. `Acquire` and `Release` compile to compiler barriers because TSO natively preserves Load-Load, Load-Store, and Store-Store ordering.
     - On `aarch64`: `Ordering::SeqCst` emits `dmb ish` (full inner-shareable data memory barrier), `Ordering::Acquire` emits `dmb ishld`, and `Ordering::Release` emits `dmb ish`.
   - **Store-Buffer Visibility Invariant:** In `ZeroCopyRingBuffer::try_pop` (`src/ring_buffer.rs`), `commit_pop_transaction` clears `occupied_mask` before `zero_slot` overwrites the 128-byte payload, and `StagingBufferGuard::drop` (`src/enclave_server.rs`) invokes `self.pair.purge()` (`ct_zeroize`) *before* `self.pool.in_use[slot_index].store(false, Ordering::Release)`. On `aarch64`, that `Ordering::Release` store lowers to `stlr`, guaranteeing that all volatile zero stores in `purge()` are globally visible before any core observes `in_use == false`.

3. **Cache-Line Eviction Ordering (`_mm_clflush` vs. `dc cvac`):**
   - In `ZeroCopyRingBuffer::flush_and_fence_slot` (`src/ring_buffer.rs`), cache maintenance is bracketed by `fence(Ordering::Acquire)` before and `fence(Ordering::Release)` after flushing both 64-byte cache lines of the 128-byte `RingSlot`.
   - On `x86_64`, `_mm_clflush` evicts the cache line from all cache levels; the trailing `fence(Ordering::Release)` + `SeqCst` operations serialize visibility.
   - On `aarch64`, `dc cvac` cleans the dirty cache line by virtual address to the Point of Coherency (PoC). Under the ARMv8 architecture manual, `dc cvac` completion is only guaranteed after a Data Synchronization Barrier (`dsb ish`), whereas `fence(Ordering::Release)` emits `dmb ish`. Because `ZeroCopyRingBuffer` operates within a single-threaded enclave address space and zeroes the slot via `zero_128` prior to flushing, stale DRAM visibility is prevented; any future cross-domain DMA handoff on `aarch64` must pair `dc cvac` with `dsb ish` + `isb`.

---

## 3. Out-of-Order Execution, Branch-Predictor Isolation & Speculative Execution Barriers

Modern out-of-order superscalar cores (`x86_64` Intel Golden Cove / AMD Zen 3–4 and `aarch64` Neoverse V1 / Apple Firestorm–Avalanche) speculatively execute instructions tens to hundreds of cycles ahead of retirement across conditional branches (Spectre-PHT / v1), indirect jumps (Spectre-BTB / v2), return stack buffers (Spectre-RSB), and store-to-load disambiguators (Spectre-v4 / SSB).

### 3.1 Elimination of Secret-Dependent Control Flow & Addressing
Nona structurally eliminates Spectre-PHT and cache-timing gadgets in cryptographic code paths:
- **Branchless Inline Assembly (`src/psi.rs`):**
  - 256-bit carry/borrow chains (`add_nocarry`, `sub_noborrow`) execute straight-line `add`/`adc`/`adc`/`adc`/`setc` and `sub`/`sbb`/`sbb`/`sbb`/`setc` instructions with zero conditional jumps.
  - Constant-time selection (`ct_select_u64`, `ct_is_zero_u64`, `ProjectivePoint::ct_cmov`) emits explicit hardware conditional move/select instructions: `test {cond}, {cond}; cmovnz {res}, {b}` on `x86_64` and `cmp {cond}, #0; csel {res}, {b}, {a}, ne` on `aarch64`. Unlike conditional branches (`jcc` / `b.cond`), `cmovnz` and `csel` execute as pure data-flow ALU operations without consulting the Pattern History Table (PHT) or Branch Target Buffer (BTB).
- **Complete Group Law & Straight-Line Hash-to-Curve:**
  - Elliptic curve point addition uses Renes-Costello-Batina (2016) Algorithm 4 complete formulas over homogeneous $\mathbb{P}^2$ coordinates—a fixed 33-step polynomial DAG with no exceptional-point branches (`P == Q`, `P == -Q`, `P == O`).
  - Hash-to-curve (RFC 9380 Simplified SWU) evaluates both candidate branches unconditionally and selects via `ct_cmov`, eliminating quadratic-residue trial-and-error loops.
- **No Secret-Indexed Memory Lookups:** Scalar multiplication uses a fixed 256-step Montgomery ladder (`r0`, `r1`) with constant-time swap (`ct_cmov`) rather than windowed precomputation tables (`wNAF`), preventing speculative or cache-bank-conflict table leaks.

### 3.2 Speculative Execution Barriers (`lfence` / `dsb` / `isb` / `csdb`)
At trust boundaries where untrusted host inputs enter the enclave or where secret buffers are scrubbed, speculative execution can transiently bypass bounds checks (Spectre-v1) or forward stale store-buffer values (Spectre-v4):
- **`x86_64` Speculation Barrier (`lfence`):** `lfence` acts as a dispatch-serializing instruction on both Intel and AMD processors: no subsequent instruction can execute—even speculatively—until all prior instructions have completed locally and prior bounds checks (`nona_validate_ffi_bounds`, `EnclaveRequestHeader` length validation) have resolved.
- **`aarch64` Speculation Barriers (`dsb sy` + `isb` / `csdb`):** On `aarch64`, `csdb` (Consumption of Speculative Data Barrier) prevents conditional select (`csel`) outputs from being used for speculative memory addresses or branch resolution, while `dsb ish` followed by `isb` flushes the instruction pipeline and completes all pending memory and cache operations before subsequent instructions decode.
- **Boundary Enforcement:** Nona pairs gatekeeper length/disjointness checks (`src/gatekeeper.rs`), wire header validation (`src/enclave_server.rs`), and volatile zeroization (`src/crypto.rs`, `src/lib.rs`) with `SeqCst` fences and opaque constant-floor responses (`WIRE_FRAME_FLOOR_NS = 250_000` ns) so transient speculative windows cannot leak validation outcomes over the vsock timing channel.

---

## 4. Dead-Store Elimination (DSE) Prevention & Register/Stack Spill Surfaces

### 4.1 Dead-Store Elimination (DSE) Semantics
Under the Rust and LLVM abstract machine, writing zeros to a stack buffer or struct field immediately before the object goes out of scope (`Drop`) or before `libc::_exit` is classified as a dead store. Because no subsequent abstract-machine load reads that memory, LLVM's `DeadStoreElimination` (DSE) pass is permitted to elide the zeroing stores entirely, leaving plaintext private scalars in DRAM.

Nona prevents DSE across all secret-bearing types via three layered mechanisms:
1. **Volatile Byte-by-Byte Stores (`ct_zeroize` in `src/crypto.rs`):** Iterates over every byte in the target slice and executes `core::ptr::write_volatile(byte, 0)`, which LLVM models as an observable side-effecting memory write that cannot be eliminated, merged, or reordered past volatile operations.
2. **Trailing `compiler_fence(Ordering::SeqCst)`:** Prevents LLVM from reordering non-volatile reads/writes around the volatile scrub loop.
3. **Deterministic RAII `ZeroizeOnDrop` (`FieldElement`, `Scalar`, `AlignedKeyBuffer`, `RingSlot`, `EnclaveFrameBuffer`):** Guarantees every exit path—including early error returns (`NONA_ERR_INVALID_CURVE_POINT`, framing errors) and fatal signal handlers (`enclave_fatal_signal_handler`)—executes `ct_zeroize` before releasing stack or static pool memory.

### 4.2 Register & Stack Spill Surface Analysis
While `core::ptr::write_volatile` guarantees memory-backed fields are zeroed in L1/DRAM, physical CPUs and optimizing compilers introduce a residual exposure surface in **architectural registers** and **compiler-generated stack spills**:
- **General-Purpose & SIMD Vector Registers:** During 256-bit Montgomery ladder iterations (`src/psi.rs`) and 128-byte SIMD ring copies/zeroes (`src/ring_buffer.rs`), secret scalar limbs and intermediate projective coordinates reside in `x86_64` GPRs (`rax`, `rcx`, `rdx`, `rsi`, `rdi`, `r8`–`r15`), AVX2/AVX-512 registers (`ymm0`–`ymm15`, `zmm0`–`zmm31`), or `aarch64` GPRs (`x0`–`x30`) and NEON registers (`v0`–`v31`). Rust's `Drop` trait operates exclusively on addressable memory values and does not clear architectural registers upon function return.
- **LLVM Stack Spill Slots & Red Zone:** Under register pressure (such as RCB 2016 Algorithm 4 complete projective addition with 12 multiplications and 17 additions), LLVM may spill intermediate `FieldElement` limbs to anonymous stack slots or the 128-byte System V AMD64 red zone (`[rsp - 128]`). Those compiler-synthesized spill slots are not bound to a Rust `Drop` destructor.
- **Architectural Mitigations & Hardening Constraints:**
  1. **`#[inline(never)]` Isolation Boundaries:** `ct_zeroize`, `ensure_session_key_initialized`, `load_session_privkey_into`, `dispatch_frame_with_slot`, and `handle_enclave_client_with_staging` are marked `#[inline(never)]` so sensitive computations execute inside bounded, auditable stack frames rather than inlining into long-lived outer event loops.
  2. **Strict Sub-4 KiB Stack Ceiling & `-C panic=abort`:** Eliminates unwinding landing pads and bounds maximum stack spill depth (`<= 3,584` bytes measured via `-Z emit-stack-sizes`), ensuring subsequent stack frames rapidly overwrite residual spill slots.
  3. **Pre-Return Register & Stack Frame Scrubbing Contract:** Subsequent assembly-hardening stages require explicit caller/callee-saved register zeroing (`xor` / `vpxor` / `vzeroall` on `x86_64`; `mov xN, xzr` / `eor vN.16b, vN.16b, vN.16b` on `aarch64`) and bounded stack-frame wiping at phase exit boundaries before returning across the vsock/FFI perimeter.

---

## 5. Target CPU Errata & Microarchitectural Considerations

### 5.1 `x86_64` AWS Nitro Targets (Intel Xeon & AMD EPYC)
- **Intel Xeon (Skylake / Cascade Lake / Ice Lake Nitro Instances):**
  - *Transient Execution & Microarchitectural Data Sampling (MDS / TAA / L1TF):* Enclave vCPUs run with hypervisor-enforced L1D flush on VM entry and `VERW` buffer overwriting, and Nona enforces single-threaded non-concurrent execution with 64-byte cache-line alignment.
  - *Downfall / Gather Data Sampling (GDS, CVE-2022-40982):* Affects AVX2/AVX-512 `vpgather*` instructions on Intel Tiger Lake/Ice Lake cores. Nona uses **zero** gather instructions; `copy_128_avx512` and `zero_128_avx512` (`src/ring_buffer.rs`) exclusively use contiguous `_mm512_loadu_si512` / `_mm512_storeu_si512` operations.
  - *Hardware Entropy Errata:* Historical Intel `RDRAND`/`RDSEED` availability and resume-from-sleep errata are completely bypassed by Nona's fail-stop `/dev/nsm` `GetRandom` IOCTL policy (`fill_nsm_entropy_or_abort` in `src/attestation.rs`), which forbids `RDRAND`/`RDSEED` fallbacks.
  - *Constant-Time Integer Arithmetic:* Intel variable-latency `DIV`/`IDIV` instructions are eliminated from all secret paths via Montgomery modular reduction and Montgomery simultaneous batch inversion.
- **AMD EPYC (Zen 2 / Zen 3 / Zen 4 Nitro Instances):**
  - *Zenbleed (CVE-2023-20593):* Register-file merge optimization bug on Zen 2 (`vzeroupper` / YMM register state leakage across SMT threads). AWS Nitro hypervisor microcode patches mitigate cross-VM exposure, and Nona isolates physical cores (`--cpu-count 2`) without SMT co-residency.
  - *Speculative Store Bypass (SSB) & Inception (SRSO):* Mitigated via hypervisor `SPEC_CTRL` / `IBPB` / `SRSO` microcode controls combined with Nona's branchless `cmovnz` data-flow selection and `SeqCst` boundary fences.

### 5.2 `aarch64` AWS Graviton3 (Neoverse V1 / `c7g`) & Apple Silicon
- **Data Independent Timing (`FEAT_DIT` / `PSTATE.DIT`):**
  - ARMv8.4-A introduced `FEAT_DIT` (supported on AWS Graviton3 Neoverse V1 and Apple Silicon). When `PSTATE.DIT = 1`, the processor guarantees that data-processing instructions—specifically `CSEL`, `ADD`, `SUB`, `ADC`, `SBC`, `AND`, `ORR`, `EOR`, `MUL`, and NEON vector arithmetic—execute in constant time independent of operand values (suppressing operand-dependent fast-path early-outs).
  - Nona's `aarch64` `ct_select_u64` / `ct_is_zero_u64` (`cmp` + `csel` / `cset`) and NEON 128-byte block routines (`copy_128_neon`, `zero_128_neon`) map directly onto DIT-covered instructions.
- **Neoverse V1 Speculation & Cache Maintenance Considerations:**
  - *Speculative Memory Disambiguation & Spectre-BHB:* Neoverse V1 employs deep out-of-order speculative execution and branch history buffers. Nona avoids secret-dependent branches and indirect jumps entirely, and brackets cache-line cleaning (`dc cvac` in `flush_aarch64`) with `Acquire`/`Release` barriers (requiring `dsb ish` + `isb` when synchronizing with non-coherent observers).
  - *Exclusive NSM Entropy Path:* Although Graviton3 implements ARMv8.5 `FEAT_RNG` (`RNDR`), Nona enforces uniform `/dev/nsm` hardware attestation-backed entropy across both `x86_64` and `aarch64` Nitro Enclaves (`src/attestation.rs`), eliminating architecture-divergent RNG trust assumptions.
