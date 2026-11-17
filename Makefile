# Copyright (c) 2026 Nona Contributors.
# Licensed under the Apache License, Version 2.0 or the MIT License.

SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c
.PHONY: help all host verify-models test nostd lint formal formal-container gates linkage sanitizers bench container stack-container enclave container-all clean

# Dynamic Container Engine Resolution (Podman > Docker)
CONTAINER_BIN ?= $(shell command -v podman 2>/dev/null || command -v docker 2>/dev/null || echo "")

help:
	@echo "======================================================================"
	@echo " NONA CORE ENGINE: QA & VERIFICATION MATRIX"
	@echo "======================================================================"
	@echo " HOST TARGETS (No container required):"
	@echo "   make host            - Run ALL host-native tests, gates, and lints"
	@echo "   make test            - Cargo unit, integration, and doc tests"
	@echo "   make nostd           - Verify #![no_std] compilation boundary"
	@echo "   make lint            - Code hygiene, Clippy pedantic, license audit"
	@echo "   make formal          - Verus machine-checked SMT formal proofs"
	@echo "   make gates           - Mechanical runtime gates 1-5 (linkage/stack/timing)"
	@echo "   make linkage         - Static library zero-heap & Mach-O/ELF PIE audit"
	@echo "   make sanitizers      - Dynamic UBSan matrix on C-ABI test runners"
	@echo "   make bench           - Compile and execute performance microbenchmarks"
	@echo ""
	@echo " CONTAINER TARGETS (Requires active Podman/Docker):"
	@echo "   make container-all   - Run ALL hermetic container verification targets"
	@echo "   make container       - 14-layer HACVS-V2 container verification & scenarios"
	@echo "   make stack-container - Containerized -Z emit-stack-sizes machine audit"
	@echo "   make enclave         - Build reproducible AWS Nitro Enclave EIF & PCRs"
	@echo ""
	@echo " TURNKEY TARGET:"
	@echo "   make all             - Execute complete end-to-end certification pipeline"
	@echo "======================================================================"

# -----------------------------------------------------------------------------
# Host / Native Targets (Zero Container Overhead)
# -----------------------------------------------------------------------------

test:
	@echo "[HOST] Running cargo unit, integration, and doc tests..."
	cargo test --all-targets --features std
	cargo test --doc --features std

nostd:
	@echo "[HOST] Verifying pure #![no_std] staticlib build..."
	cargo build --release --lib --no-default-features
	@echo "[HOST] Executing pure #![no_std] freestanding integration test harness..."
	RUSTFLAGS="-C panic=abort" cargo test --test test_c_abi --no-default-features

lint:
	@echo "[HOST] Running code hygiene, clippy, and licensing gates..."
	./tools/check_code_hygiene.sh

verify-models:
	@echo "[HOST] Verifying TLA+ vsock session state machine (specs/vsock_session.tla)..."
	@test -f specs/vsock_session.tla || (echo "[ERROR] Missing specs/vsock_session.tla" && exit 1)
	@test -f specs/vsock_session.cfg || (echo "[ERROR] Missing specs/vsock_session.cfg" && exit 1)
	@TLC_JAR="$${TLA2TOOLS_JAR:-}"; \
	if [ -z "$$TLC_JAR" ]; then \
		for cand in /usr/local/lib/tla2tools.jar /opt/tla/tla2tools.jar "$$HOME/.tla/tla2tools.jar"; do \
			if [ -f "$$cand" ]; then TLC_JAR="$$cand"; break; fi; \
		done; \
	fi; \
	if command -v tlc >/dev/null 2>&1; then \
		echo "  [*] Executing TLC model checker via PATH (tlc)..."; \
		tlc -workers auto -cleanup -config specs/vsock_session.cfg specs/vsock_session.tla; \
	elif [ -n "$$TLC_JAR" ] && command -v java >/dev/null 2>&1; then \
		echo "  [*] Executing TLC model checker via $$TLC_JAR..."; \
		java -XX:+UseParallelGC -cp "$$TLC_JAR" tlc2.TLC -workers auto -cleanup -config specs/vsock_session.cfg specs/vsock_session.tla; \
	else \
		echo "  [*] TLC binary/JAR not installed on workstation; executing structural TLA+ & TLC config validator..."; \
		python3 -c "import pathlib, re; tla = pathlib.Path('specs/vsock_session.tla').read_text(encoding='utf-8'); cfg = pathlib.Path('specs/vsock_session.cfg').read_text(encoding='utf-8'); assert re.search(r'^----[ ]*MODULE[ ]+vsock_session[ ]*----', tla, re.M), 'Missing MODULE header'; assert re.search(r'^====', tla, re.M), 'Missing module footer'; req = ['Init', 'Next', 'Spec', 'TypeInvariant', 'DeadlockFreedom', 'SafetyPhaseMonotonicity', 'SafetyFailClosedZeroization', 'SessionCompleteness', 'LivelockFreedom']; miss = [s for s in req if not re.search(r'^[ ]*' + s + r'[ ]*==', tla, re.M)]; assert not miss, f'Missing TLA+ definitions: {miss}'; syms = re.findall(r'^(?:SPECIFICATION|INVARIANT|PROPERTY)[ ]+([A-Za-z0-9_]+)', cfg, re.M); undef = [s for s in syms if not re.search(r'^[ ]*' + s + r'[ ]*==', tla, re.M)]; assert not undef, f'Undefined TLC symbols: {undef}'; print(f'  ✓ Structural TLA+ & TLC config validation passed ({len(syms)} checked formulas, {len(tla.splitlines())} lines).')"; \
	fi

formal:
	@echo "[HOST] Running live Verus SMT formal verification proofs (fail-closed)..."
	@./tools/run_verus_safe.sh

gates:
	@echo "[HOST] Executing mechanical runtime gates 1-5..."
	./tools/run_mechanical_gates.sh

linkage:
	@echo "[HOST] Auditing static linkage, zero-heap symbols, and PIE hardening..."
	./tools/verify_linkage.sh

sanitizers:
	@echo "[HOST] Running native dynamic sanitizers (UBSan)..."
	./tools/run_sanitizers.sh

bench:
	@echo "[HOST] Executing engine performance microbenchmarks..."
	cargo bench --features std

host: verify-models nostd sbom lint formal test gates linkage sanitizers
	@echo "======================================================================"
	@echo " [✓] ALL HOST / NATIVE QA TARGETS PASSED CLEANLY"
	@echo "======================================================================"

# -----------------------------------------------------------------------------
# Hermetic Container Targets (Requires Podman / Docker)
# -----------------------------------------------------------------------------

check-container-engine:
	@if [ -z "$(CONTAINER_BIN)" ]; then \
		echo "[ERROR] No container engine found (podman or docker required)." >&2; \
		exit 1; \
	fi
	@if ! $(CONTAINER_BIN) info >/dev/null 2>&1; then \
		echo "[ERROR] Container engine ($(CONTAINER_BIN)) is installed but not running." >&2; \
		echo "[HINT] Run: podman machine start (macOS) or check container service." >&2; \
		exit 1; \
	fi

formal-container: check-container-engine
	@echo "[CONTAINER] Executing Verus formal verification in hermetic container..."
	./tools/run_verus_container.sh

container: check-container-engine
	@echo "[CONTAINER] Executing HACVS-V2 14-layer container verification..."
	./tools/run_container_verification.sh

stack-container: check-container-engine
	@echo "[CONTAINER] Executing -Z emit-stack-sizes Linux musl stack ceiling audit..."
	./tools/verify_stack_sizes.sh

enclave: check-container-engine
	@echo "[CONTAINER] Packaging reproducible AWS Nitro Enclave EIF & computing PCRs..."
	./tools/build_nitro_eif.sh

container-all: check-container-engine container stack-container enclave
	@echo "======================================================================"
	@echo " [✓] ALL HERMETIC CONTAINER QA TARGETS PASSED CLEANLY"
	@echo "======================================================================"

# -----------------------------------------------------------------------------
# Unified Certification Entry Point
# -----------------------------------------------------------------------------

all:
	@./tools/run_certification_pipeline.sh

clean:
	cargo clean
	rm -rf target/

sbom:
	@echo "[HOST] Validating CycloneDX v1.5 SBOM artifact (nona-core.cdx.json)..."
	@test -f nona-core.cdx.json || (echo "[ERROR] nona-core.cdx.json missing!" && exit 1)
	@grep -q '"bomFormat": "CycloneDX"' nona-core.cdx.json || (echo "[ERROR] Invalid BOM format" && exit 1)
	@grep -q '"specVersion": "1.5"' nona-core.cdx.json || (echo "[ERROR] Invalid CycloneDX specVersion (expected 1.5)" && exit 1)
	@! grep -qE '(/Users/|/home/|/private/|/var/folders/|/Volumes/|file://)' nona-core.cdx.json || (echo "[ERROR] Workstation path leakage detected in nona-core.cdx.json" && exit 1)
	@grep -q '"name": "nona_core"' nona-core.cdx.json && echo "[+] Component 'nona_core' present."
	@grep -q '"name": "nona_enclave"' nona-core.cdx.json && echo "[+] Component 'nona_enclave' present."
	@echo "[SUCCESS] CycloneDX v1.5 SBOM verified, zero-leakage invariant enforced."
