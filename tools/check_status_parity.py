import re, sys

with open("include/nona.h", "r", encoding="utf-8") as f:
    header = f.read()
with open("src/gatekeeper.rs", "r", encoding="utf-8") as f:
    rust_gk = f.read()
with open("SPECIFICATION.md", "r", encoding="utf-8") as f:
    spec = f.read()

header_codes = dict(re.findall(r"(NONA_[A-Z0-9_]+)\s*=\s*(-?\d+)", header))
rust_codes = dict(re.findall(r"pub const (NONA_[A-Z0-9_]+):\s*i32\s*=\s*(-?\d+);", rust_gk))
rust_codes.pop("NONA_SUCCESS", None)
spec_codes = dict(re.findall(r"`(NONA_[A-Z0-9_]+)`\s*\|\s*`(-?\d+)`", spec))

mismatches = []
for k, v in header_codes.items():
    if k not in spec_codes:
        mismatches.append(f"Missing from SPECIFICATION.md: {k} = {v}")
    elif spec_codes[k] != v:
        mismatches.append(f"Spec mismatch for {k}: header={v}, spec={spec_codes[k]}")
    if k not in rust_codes:
        mismatches.append(f"Missing from src/gatekeeper.rs: {k} = {v}")
    elif rust_codes[k] != v:
        mismatches.append(f"Rust mismatch for {k}: header={v}, gatekeeper.rs={rust_codes[k]}")

for k, v in rust_codes.items():
    if k not in header_codes:
        mismatches.append(f"Extra code in src/gatekeeper.rs not in include/nona.h: {k} = {v}")

for k, v in spec_codes.items():
    if k not in header_codes:
        mismatches.append(f"Extra code in SPECIFICATION.md not in include/nona.h: {k} = {v}")

if mismatches:
    print("  [!] 3-way parity mismatch detected in C-ABI status codes:")
    for m in mismatches:
        print(f"    {m}")
    sys.exit(1)
else:
    print(f"  ✓ Clean: All {len(header_codes)} status codes match bijectively across include/nona.h, src/gatekeeper.rs, and SPECIFICATION.md.")
