# Changelog

All notable changes to Nona Core Engine are documented in this file.

## [1.0.1] - 2026-11-13

### Security & Formal Verification (Hardening Pass 1)
- Verified all 146 Verus SMT targets (50 ghost lemmas and 96 executable/boundary contracts) with 0 errors and a bounded 7-site axiomatic TCB (`docs/TCB.md`).
- Hardened `nona_phase1_blind` and `nona_phase2_reblind` C-ABI entry points with strict byte-length, alignment, and pointer-aliasing validation (`src/psi.rs`, `src/ffi.rs`).
- Enforced fail-closed `/dev/nsm` hardware entropy generation (`fill_nsm_entropy_or_abort`) using a spinlock-guarded `.bss` scratch buffer with constant-time `Drop` zeroization (`src/attestation.rs`), preserving the `<= 4096 B` machine stack frame ceiling (`libnona_core.a` peak frame: `3648 B`).
- Implemented offline COSE_Sign1 P-384 X.509 certificate chain verification against the embedded AWS Nitro root CA and isolated cryptographic validation from untrusted hypervisor wall-clock timestamps (`src/attestation.rs`).

### Enclave & Build Infrastructure
- Validated live AWS Nitro Enclave attestation and `GetRandom` IOCTLs (`NSM_IOCTL_RAW` / `NSM_IOCTL_RAW_AL2`) on `aarch64` (`m6g` / Graviton), pinning live SHA-384 `PCR0`/`PCR1`/`PCR2` measurements in `manifests/enclave_manifest.json` and `manifests/enclave_manifest_aarch64.json`.
- Enforced bit-for-bit reproducible musl static library and `.eif` builds (`tools/build_nitro_eif.sh`, `tools/verify_stack_sizes.sh`).
- Expanded integration, fuzzing, sanitizer, and `dudect` timing-neutrality (`|t| < 4.5`) verification gates (`tests/`).

## [1.0.0] - 2026-11-09
- Initial public open-source release implementing `SPECIFICATION.md` `1.0.0-RELEASE` (`6d369a7`, initial import tag `v0.1.0`).
