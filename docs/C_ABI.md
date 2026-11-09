# Nona C-ABI Static Linkage Guide

Copyright (c) 2026 Jose Guillermo Rodriguez <jose-guillermo-rodriguez@users.noreply.github.com>
SPDX-License-Identifier: MIT OR Apache-2.0

---

## 1. Static Linkage Semantics & Self-Contained Boundary

`libnona_core.a` is a `#![no_std]` Rust static archive that exports a pure, self-contained C ABI conforming to standard platform calling conventions.

Under `#![no_std]` with `panic = "abort"`, unwinding runtime mechanisms are not utilized. To guarantee seamless static integration into downstream C/C++ projects without requiring downstream shims or undocumented linker flags, `libnona_core` provides an internal language personality definition (`rust_eh_personality`).

Both Mach-O (`ld64` on Apple Darwin) and ELF (`ld.bfd`, `ld.gold`, `lld` on Linux) linkers resolve all internal symbols directly from the archive.

---

## 2. Standard C/C++ Compilation & Linkage

Downstream integrators link directly against `libnona_core.a` using standard compiler invocations:

### macOS / iOS (Clang / Apple ld64)
```bash
clang -std=c99 -O3 -Iinclude main.c target/release/libnona_core.a -lpthread -ldl -o app
```

### Linux glibc / musl (GCC or Clang / GNU ld or LLD)
```bash
gcc -std=c99 -O3 -Iinclude main.c target/release/libnona_core.a -lpthread -ldl -lm -o app
```

---

## 3. Platform Linker Flag Matrix

| Platform | Object Format | Required Consumer Flags |
| :--- | :--- | :--- |
| **Apple macOS / iOS** | Mach-O | `-lpthread -ldl` |
| **Linux (glibc / musl)** | ELF | `-lpthread -ldl -lm` |
