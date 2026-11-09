import re, sys

with open("include/nona.h", "r") as f:
    header = f.read()
with open("SPECIFICATION.md", "r") as f:
    spec = f.read()

header_codes = dict(re.findall(r"(NONA_[A-Z0-9_]+)\s*=\s*(-?\d+)", header))
spec_codes = dict(re.findall(r"`(NONA_[A-Z0-9_]+)`\s*\|\s*`(-?\d+)`", spec))

mismatches = []
for k, v in header_codes.items():
    if k not in spec_codes:
        mismatches.append(f"Missing from SPECIFICATION.md: {k} = {v}")
    elif spec_codes[k] != v:
        mismatches.append(f"Mismatch for {k}: header={v}, spec={spec_codes[k]}")

if mismatches:
    print("  [!] Parity mismatch detected in C-ABI status codes:")
    for m in mismatches:
        print(f"    - {m}")
    sys.exit(1)
else:
    print(f"  ✓ Clean: All {len(header_codes)} status codes in include/nona.h match SPECIFICATION.md bijectively.")
