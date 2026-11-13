# NONA Core Engine: Formally Verified Cryptographic Engine

[![Build Status](https://img.shields.io/badge/Build-Hermetic_Musl_PASS-brightgreen)](#5-reproducible-builds--hermetic-packaging)
[![Formal Proofs](https://img.shields.io/badge/Verus-146_Verified_0_Errors-blue)](#4-formal-smt-verification-matrix)
[![Assurance](https://img.shields.io/badge/Assurance-HAVH_5--Tier_Certified-success)](docs/HAVH.md)
[![Zero-Heap](https://img.shields.io/badge/Substrate-%23![no_std]_Zero--Heap-orange)](#1-architectural-invariants)
[![TEE Platform](https://img.shields.io/badge/Enclave-AWS_Nitro_Enclaves-blueviolet)](#6-aws-nitro-enclave-deployment)

The core engine (`libnona_core`) is a zero-dependency, `#![no_std]` high-assurance C-ABI primitive engineered for Private Set Intersection (PSI), vectorized database UDF acceleration, deterministic byte normalization, and constant-time index obfuscation. Supporting developer CLI utilities, NSM drivers, and test harnesses utilize pinned, offline-vendored dependencies. Designed as a foundational primitive for institutional and confidential computing environments, Nona guarantees compile-time memory safety via **146 machine-checked Verus SMT targets (50 ghost lemmas + 96 verified executive & boundary contracts)** and total absence of runtime dynamic heap allocation (`malloc`/`free`/`realloc`/`calloc`) strictly for `#![no_std]` targets compiled under `--no-default-features`.

> **Release Provenance:** Public open-source release v1.0.1 (Hardening Pass 1 on the 1.0.0-RELEASE specification), formally verified in Verus (146 SMT targets) and hardware-validated on AWS Nitro Enclaves.

---

## 1. Architectural Invariants

- **Machine-Checked SMT Verification:** 146 formal Verus theorems verify arithmetic boundary safety, Solinas modular reduction, inductive loop invariants of the scalar multiplication ladder, Feistel structural invertibility (proving round-trip bijectivity without asserting PRF diffusion or recovery resistance), and array indexing across core cryptographic modules. Production secp256k1 projective point addition (RCB 2016 Alg 4) and 256-bit scalar multiplication are machine-checked in Verus.
- **Zero Dynamic Heap Allocation:** Pure stack-allocated and static-memory architecture. Exactly 0 calls to `malloc`, `free`, `realloc`, or `calloc` in compiled release binaries, statically enforced by `nm -u` dynamic symbol audits. Zero dynamic allocation guarantees apply strictly to `#![no_std]` targets built with `--no-default-features`.
- **L1 Cache Line Alignment:** All context frames, scratchpads, and cryptographic structures are strictly 64-byte aligned (`#[repr(C, align(64))]`) to eliminate false sharing and maximize SIMD throughput (AVX-512 / ARM Neon).
- **Constant-Time Microarchitectural Invariance:** Multi-precision finite field arithmetic utilizes unrolled hardware carry and borrow chains (inline x86_64 `add`/`adc` and `sub`/`sbb` assembly) and branchless conditional selection (`ct_cmov`) paired with `SeqCst` compiler memory fences. Timing neutrality is continuously evaluated via `dudect` empirical statistical regression smoke tests (|t| < 4.5 under Welch's t-test over 100,000 interleaved samples; current release measures |t| = 0.58). Dudect serves as an empirical regression test rather than formal verification of microarchitectural side-channel resistance.
- **Volatile Memory Scrubbing:** Constant-time zero-on-drop memory decontamination on context teardown, drop, or signal trap using volatile pointer writes (`core::ptr::write_volatile`) paired with `SeqCst` compiler memory fences to prevent Dead-Code Elimination (DCE).
- **Stack Frame Ceiling:** FFI boundaries strictly limit execution stack expansion to < 4 KiB, protected by inline stack-pointer assertions.

---

## 2. Directory Topology

```
nona/
├── .cargo/
│   └── config.toml                  # Pinned offline toolchain flags (-C panic=abort, etc.)
├── .github/
│   └── workflows/
│       ├── ci.yml                   # SMT proof verification, musl static build, zero-heap symbol checks
│       └── audit.yml                # dudect constant-time & ASan/UBSan memory sanitizers
├── docs/
│   ├── C_ABI.md                     # Darwin/Apple Mach-O static linkage guide
│   ├── HAVH.md                      # High-Assurance Verification Harness (5-tier certification)
│   ├── TCB.md                       # Trusted Computing Base & SMT axiom boundaries
│   └── THREAT_MODEL.md              # Untrusted host & adversary threat boundaries
├── .dockerignore                    # Container build context exclusion filter for reproducible builds
├── .gitattributes                   # Deterministic line-ending enforcement (LF) across platforms
├── .gitignore                       # Repository hygiene and ephemeral artifact exclusion filters
├── Cargo.lock                       # Locked deterministic dependency manifest
├── Cargo.toml                       # Manifest: default = [], std = [] features
├── clippy.toml                      # Static analysis lint policy enforcing <= 4 KiB stack frame ceiling
├── deny.toml                        # cargo-deny security policy, license checks, advisory bans
├── Dockerfile.reproducible          # Bit-for-bit deterministic multi-arch builder (aarch64 / x86_64)
├── LICENSE-APACHE                   # Canonical Apache-2.0 license
├── LICENSE-MIT                      # Canonical MIT license
├── Makefile                         # Primary verification orchestrator (gates, sanitizers, formal proofs, EIF)
├── nona-core.cdx.json               # CycloneDX v1.5 Software Bill of Materials (SBOM) supply-chain attestation
├── README.md                        # Architecture topology, scorecard, 30s quickstart
├── rust-toolchain.toml              # Pinned Rust toolchain (1.98.0), targets (musl, darwin), and components
├── SECURITY.md                      # Untrusted hypervisor threat model & CVD policy
├── SPECIFICATION.md                 # Authoritative mathematical and boundary specification
├── benches/
│   └── engine_benchmarks.rs         # Criterion micro-benchmarks (blinding, batch affine)
├── deploy/
│   └── run_nitro.sh                 # One-command AWS Nitro Enclave provisioning harness
├── fuzz/
│   └── fuzz_targets/
│       ├── fuzz_ingest.rs           # Continuous fuzzing: raw stream deserialization
│       └── fuzz_wire_dispatch.rs    # Continuous fuzzing: vsock packet parsing
├── init.sh                          # Hermetic enclave PID 1 init entrypoint & devtmpfs bootstrap
├── include/                                  # Monomorphic C99 C-ABI headers
│   ├── nona.h                                # Exported types, status codes, and engine API
│   └── nona_udf.h                            # Thread-local scratchpad context for database UDFs
├── manifests/                                # Cryptographic NSM PCR reference manifests
│   ├── enclave_manifest.json                 # Target-independent attestation baseline
│   ├── enclave_manifest_aarch64.json         # Sealed AWS Nitro aarch64 image measurements
│   └── enclave_manifest_x86_64.json          # Sealed AWS Nitro x86_64 image measurements
├── proofs/
│   └── verus_verification.log       # Audit evidence: 146/146 SMT verification log
├── src/
│   ├── lib.rs                       # Pure #![no_std] engine entrypoint (libnona_core.a)
│   ├── psi.rs                       # 92 Verus proofs (Solinas reduction, RCB 2016 complete addition, and constant-time scalar multiplication ladder)
│   ├── ring_buffer.rs               # N=128 volatile ring buffer, cache line flushing
│   ├── obfuscation.rs               # 4-round Feistel over Z_(2^64) with HalfSipHash-32
│   ├── normalization.rs             # Monomorphic 64-byte stack window byte sanitizer
│   ├── crypto.rs                    # Constant-time equality, Ghost ChannelTokens, adaptive threshold router
│   ├── allocator.rs                 # StaticArena<N> bump allocator
│   ├── gatekeeper.rs                # nona_gatekeeper_validate defensive contract gate
│   ├── ingest.rs                    # Constant-time wire format ingestion & stream slicing
│   ├── attestation.rs               # In-enclave NSM driver (#![no_std]) & host verifier (std)
│   ├── enclave_server.rs            # Server daemon (AF_VSOCK:5005 & local socket fallback)
│   ├── client.rs                    # Host client driver (VSOCK + /tmp/nona.sock)
│   ├── exception.rs                 # Controlled abort replacing spin-loop
│   └── bin/
│       ├── nona_enclave.rs          # Production daemon for AWS Nitro Enclaves (.eif)
│       └── nona.rs                  # Developer CLI (pipes, match, JSON/CSV)
├── tests/
│   └── integration/                 # Complete HACVS-V2 14-layer test runners & C-ABI test suite
├── tools/
│   ├── build_nitro_eif.sh           # Architecture-guarded Nitro Enclave builder
│   ├── run_container_verification.sh # 14-layer container verification pipeline
│   ├── run_sanitizers.sh            # AddressSanitizer & UndefinedBehaviorSanitizer runner
│   ├── run_verus_safe.sh            # Portable Verus runner (dynamic git root resolution)
│   └── verify_linkage.sh            # Host native linkage & Mach-O/ELF hardening audit
└── vendor/                          # Fully vendored crates for offline/frozen builds
```

---

## 3. High-Assurance Verification Harness (HAVH)

Nona rejects standard unit-testing pyramids in favor of a 5-tier **High-Assurance Verification Harness (HAVH)** that enforces mathematical truth, machine-level binary constraints, and microarchitectural side-channel resistance. Complete specifications are documented in [`docs/HAVH.md`](docs/HAVH.md).

### Security Architecture & Governance
- **Canonical Assurance Specification:** [`docs/HAVH.md`](docs/HAVH.md)
- **Threat Model & Adversary Boundaries:** [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
- **Trusted Computing Base & SMT Axioms:** [`docs/TCB.md`](docs/TCB.md)
- **Machine Stack Verification:** Audited via `readelf --stack-sizes` (<= 4096 B)
- **Supply-Chain Provenance:** CycloneDX v1.5 JSON SBOM (`make sbom` / `nona-core.cdx.json`)

### Host Verification (Zero Container Overhead)
Executes all formal SMT proofs (146/146), pure `#![no_std]` compilation, code hygiene, Rust test matrices, mechanical gates 1–5, static zero-heap linkage audits, and dynamic memory sanitizers (UBSan & ASan):
```bash
make host
```

### Hermetic Container Verification (Podman / Docker)
Executes the 14-layer HACVS-V2 container matrix, edge scenarios A–C, `-Z emit-stack-sizes` machine stack audits, and reproducible AWS Nitro Enclave `.eif` packaging:
```bash
make container-all
```

### Full Certification Gate
Runs the turnkey, end-to-end certification pipeline across both host and container tiers:
```bash
make all
```

---

## 4. Formal SMT Verification Matrix

All mathematical models and SMT theorems are machine-checked using Verus and Z3 (rlimit = 1,000,000):

| Source Module | Target Domain | Theorems | Verified Status |
| :--- | :--- | :--- | :--- |
| `src/psi.rs` | Solinas reduction, complete homogeneous projective $\mathbb{P}^2$ point addition (RCB 2016 Alg 4 complete addition), and 256-bit scalar multiplication ladder on secp256k1 | 93 | 100% Passed (0 Errors) |
| `src/normalization.rs` | Monomorphic 64-byte bounded normalization & output sanitization completeness | 9 | 100% Passed (0 Errors) |
| `src/obfuscation.rs` | 4-round Feistel bijection & non-identity guarantees | 22 | 100% Passed (0 Errors) |
| `src/allocator.rs` | Pointer alignment preservation & static boundary safety | 2 | 100% Passed (0 Errors) |
| `src/crypto.rs` | Ghost ChannelTokens & adaptive threshold routing circuit | 3 | 100% Passed (0 Errors) |
| `src/enclave_boundaries.rs` | Hardware `/dev/nsm` IOCTL/CBOR ABI, session op ceiling, vsock wire framing, FFI disjointness & ring/exception boundaries | 17 | 100% Passed (0 Errors) |
| **Total** | **Nona Core Verified Surface (50 Lemmas + 96 Contracts)** | **146** | **146 Verified (0 Errors)** |

### Formal Verification Surface

Nona guarantees core cryptographic and state invariants through machine-checked verification via [Verus](https://github.com/verus-lang/verus) and the Z3 SMT solver:

- **146 Sealed SMT Verification Targets (0 Errors):** Partitioned into **50 compile-time ghost lemmas** (`proof fn` mathematical inductive steps) and **96 verified executive & boundary contracts** (runtime `fn` with machine-checked `requires`/`ensures` contracts) across finite field arithmetic, complete projective point addition, constant-time scalar multiplication loops, 64-bit Feistel permutation networks, static arena memory alignment, and monotonic cryptographic channel tokens.
- **Feistel Structural Invertibility:** The 4-round index permutation circuit (`src/obfuscation.rs`) is formally proven to be an exact mathematical bijection ($f^{-1}(f(x)) = x$), strictly collision-free (injective), and covering the entire 64-bit domain (surjective). Machine-checked theorems establish structural invertibility only; they do not guarantee cryptographic pseudorandom function (PRF) diffusion, statistical avalanche, or resistance against algebraic cryptanalysis.
- **Montgomery Ladder Correctness:** Constant-time 256-bit scalar multiplication ladder (`ProjectivePoint::scalar_mul`) and ladder loop invariants are formally verified inductively in Verus without raw `assume` directives. Production secp256k1 projective point addition (RCB 2016 Alg 4 complete addition) and doubling are machine-checked in the algebraic core.
- **Deterministic 64-Byte Alignment:** Arena bump allocation (`bump_allocate`) machine-proves that every offset satisfies `offset % 64 == 0`, eliminating AVX-512 misaligned load faults at the type level.
- **Bounded TCB:** Non-linear degree-2 multivariate field reduction ($512 \to 256$ bit) is isolated behind 7 audited `#[verifier::external_body]` sites (4 arithmetic primitives in `src/psi.rs` and 3 hardware/OS syscall boundary models in `src/enclave_boundaries.rs`), fully documented in `SPECIFICATION.md §4.5.1`. Runtime SIMD acceleration, Simplified SWU hash-to-curve (RFC 9380), batch inversion, point decompression, and C-ABI FFI entry points are part of the unverified runtime perimeter, validated through differential fuzzing and integration test suites.

---

## 5. Reproducible Builds & Hermetic Packaging

> **Manifest Provenance:** Both `enclave_manifest_x86_64.json` and `enclave_manifest_aarch64.json` are cryptographically sealed from deterministic builds. `enclave_manifest_aarch64.json` is verified and sealed directly on physical AWS Graviton3 silicon (`c7g.xlarge` / Neoverse V1, ARMv8.5 `FEAT_RNG`) with bit-for-bit hypervisor register fidelity.

Nona treats enclave image measurements (PCR0, PCR1, PCR2) as cryptographic identity contracts:
- **Pinned Digest Base Images:** Multi-arch manifest digests (`clux/muslrust@sha256:...`, `alpine@sha256:...`).
- **Hermetic Vendoring:** Built strictly using `--frozen --offline` against pinned `vendor` sources.
- **Path Sanitization:** Source directories remapped to `/nona` via `--remap-path-prefix`.
- **Timestamp Clamping:** OCI image layers and binary mtimes clamped to `SOURCE_DATE_EPOCH=1700000000`.

---

### Platform Support & Workstation Requirements

| Environment | Supported Runtimes | Deployment Target |
| :--- | :--- | :--- |
| **Linux (x86_64 / aarch64)** | Native, Docker, Podman | AWS Nitro Enclaves (`.eif`), Musl static library, Host daemon |
| **macOS (Apple Silicon)** | Native Host | Local simulation daemon (`AF_UNIX`), C-ABI FFI harness |
| **Windows 10 / 11** | **WSL2 (Ubuntu 22.04+)** | Full Linux toolchain parity (hermetic container for Verus; native requires Ubuntu 24.04+ / glibc >= 2.39) |

> **Note:** Run all build, test, and simulation commands within the same environment (Linux native, macOS terminal, or WSL2 shell). For example, a simulation daemon launched inside WSL2 cannot receive IPC connections from a native Windows PowerShell client.

---

### 5.3 Windows & WSL2 Audit Operational Guidance

When validating or reproducing the build harness under Windows 10/11, strict adherence to the virtualization and filesystem boundaries is required:

#### 1. Native Virtual Filesystem Isolation
* **Do NOT clone into `/mnt/c/` (DrvFs):** The cross-OS translation layer degrades I/O throughput, alters POSIX permission masks (`0755` -> `0777`), and prevents proper `AF_UNIX` inter-process domain socket binding.
* **Workspace Path:** Always clone directly inside the WSL2 native ext4 virtual disk (e.g., `~/nona` or `/home/<user>/nona`).
* **Line Ending Integrity:** Never checkout using host Windows Git (`core.autocrlf = true`). Line endings must remain strictly `LF`. Run all Git commands inside the WSL2 shell or ensure `git config core.autocrlf input` is active.

#### 2. Rootless Podman & Docker Capabilities (Sanitizer Execution)
* **Shadow Memory Allocation:** Dynamic instrumentation gates (Gate 2 ASan/UBSan) allocate substantial shadow memory and invoke `process_vm_readv` / `ptrace`.
* **Automated Runner:** Use the repository verification wrapper, which automatically injects required engine flags:
  ```bash
  ./tools/run_container_verification.sh
  ```
* **Manual Container Invocation:** If executing raw container commands under Podman or Docker, provide explicit capabilities to avoid runtime sanitizer initialization panics:
  ```bash
  podman run --rm -it \
    --cap-add SYS_PTRACE \
    --security-opt seccomp=unconfined \
    -v "$(pwd)":/workspace:Z \
    nona-verifier:latest
  ```

#### 3. Microarchitectural Timing Calibration (Gate 5)
* **Hyper-V Virtualization Jitter:** WSL2 runs atop the Hyper-V hypervisor. Thread preemption and vCPU scheduling introduce non-deterministic clock jitter into Gate 5 timing variance assertions (`test_timing_boundaries`).
* **Execution Profile:** Gate 5 assertions are calibrated for bare-metal x86_64 hardware and optimized binaries. When running inside WSL2:
  * Always run with `--release` flags to avoid unoptimized frame overhead.
  * In resource-constrained or heavily loaded host environments, run timing verification with single-threaded execution to minimize vCPU co-scheduling variance:
    ```bash
    cargo test --release --test test_timing_boundaries -- --test-threads=1
    ```

#### 4. Rootless Podman Cgroup Management (WSL2 Init Boundary)
Default WSL2 distributions do not initialize an active systemd user session bus (`/run/user/<UID>/bus`), causing OCI runtimes (`crun`) to fail during container process instantiation (`RUN` steps) with:
```text
error from /usr/bin/crun creating container: sd-bus call: Permission denied
```

To configure rootless Podman globally on WSL2 hosts, enforce `cgroupfs` management:

```bash
mkdir -p ~/.config/containers
cat << 'CONFIG_EOF' > ~/.config/containers/containers.conf
[engine]
cgroup_manager = "cgroupfs"
events_logger = "file"
CONFIG_EOF
```

Verify active configuration:
```bash
podman info --format '{{.Host.CgroupManager}}'
# Expected output: cgroupfs
```


## 6. AWS Nitro Enclave Deployment & Upstream Wire Mock Harness

Nona operates under two operational boundaries with distinct security expectations:
- **Production (AWS EC2 Nitro Enclave):** True hardware isolation enforced by the Nitro hypervisor (zero host storage, zero external networking, isolated memory carve-out). Communication occurs exclusively over `AF_VSOCK:5005`, and cryptographic attestation documents are signed directly by the physical Nitro Security Module (`/dev/nsm`).
- **Upstream Development (Workstation Wire Mock):** An IPC protocol mock over `AF_UNIX` (`/tmp/nona.sock`). An unprivileged workstation **cannot** simulate hardware NSM certificates or hypervisor encryption. This upstream harness exercises wire-protocol framing, state transitions, and client-side manifest parsing prior to hardware deployment.

> **Note on Cargo Flags:** Because the core engine is pure `#![no_std]` by default, host CLI tools require `--features std`.

### Step 1: Launch Daemon
Auto-detects AWS Nitro Enclave hardware versus local workstation mock mode:
```bash
./deploy/run_nitro.sh start --cpu-count 2 --cid 16
```

### Step 2: Verify Protocol Connectivity
Verify zero-copy wire frame roundtrip via developer CLI ping:
```bash
cargo run --bin nona --features std -- ping
```

### Step 3: Hardware Attestation vs. Mock Manifest Verification
In production on AWS EC2 Nitro instances (verifies hardware `/dev/nsm` signature):
```bash
cargo run --bin nona --features std -- attest --manifest manifests/enclave_manifest.json
```

On local development workstations (verifies client parsing against reference measurements):
```bash
cargo run --bin nona --features std -- attest --dev-simulation --manifest manifests/enclave_manifest.json
```

### Step 4: Terminate Daemon
Cleanly terminate the background daemon:
```bash
./deploy/run_nitro.sh stop
```

---

## 7. License & Governance

### Licensing
The Nona Core Engine is dual-licensed under:
- **Apache License, Version 2.0**: ([LICENSE-APACHE](LICENSE-APACHE))
- **MIT License**: ([LICENSE-MIT](LICENSE-MIT))

You may choose to use either license at your option.

### Security & Coordinated Disclosure
For vulnerability reporting, threat model definitions (AWS Nitro Enclave isolation, memory remanence, and untrusted host boundaries), and coordinated vulnerability disclosure protocols, refer to [SECURITY.md](SECURITY.md).

---

## 8. Governance & Project Maintenance

Nona is an open-source, high-assurance cryptographic substrate engineered for confidential computing and privacy-preserving computation within hardware-enforced enclaves.

- **Lead Architect & Maintainer:** Jose Guillermo Rodriguez ([@jose-guillermo-rodriguez](https://github.com/jose-guillermo-rodriguez))
- **Security Disclosures:** For vulnerability reporting and coordinated disclosures, refer to [`SECURITY.md`](SECURITY.md).
- **Technical Inquiries & Collaboration:** For questions regarding formal verification contracts, enclave deployment, or technical collaboration, open an issue or start a thread in GitHub Discussions.
