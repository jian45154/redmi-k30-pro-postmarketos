#!/usr/bin/env bash
set -euo pipefail

report=${LMI_ROLLBACK_REPORT:-/tmp/lmi-release-r6-bootmem-20260624/ROLLBACK_BOOT_CANDIDATES.txt}

search_roots=()
if [ "$#" -gt 0 ]; then
	search_roots=("$@")
else
	search_roots=(
		artifacts
		/tmp
		"/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lmi"
	)
fi

mkdir -p "$(dirname "$report")"

python3 - "$report" "${search_roots[@]}" <<'PY'
import hashlib
import os
import struct
import sys
from pathlib import Path

report = Path(sys.argv[1])
roots = [Path(x) for x in sys.argv[2:]]
max_boot_partition_size = 134_217_728

def iter_candidates(root: Path):
    if not root.exists():
        return
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in {".git", ".pmbootstrap", "node_modules", "__pycache__"}
        ]
        for name in filenames:
            lower = name.lower()
            if (
                lower == "boot.img"
                or lower.endswith("-boot.img")
                or lower.endswith("_boot.img")
                or "boot" in lower and lower.endswith(".img")
            ):
                yield Path(dirpath) / name

def inspect_boot(path: Path):
    try:
        st = path.stat()
        if st.st_size < 4096 or st.st_size > max_boot_partition_size:
            return None
        with path.open("rb") as f:
            head = f.read(4096 + 128)
        if head[:8] != b"ANDROID!":
            return None
        kernel_size = struct.unpack_from("<I", head, 8)[0]
        ramdisk_size = struct.unpack_from("<I", head, 16)[0]
        page_size = struct.unpack_from("<I", head, 8 + 7 * 4)[0]
        header_version = None
        if len(head) >= 8 + 10 * 4:
            header_version = struct.unpack_from("<I", head, 8 + 9 * 4)[0]
        data = path.read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        return {
            "path": str(path),
            "size": st.st_size,
            "sha256": sha,
            "kernel_size": kernel_size,
            "ramdisk_size": ramdisk_size,
            "page_size": page_size,
            "header_version_raw": header_version,
        }
    except (OSError, struct.error):
        return None

seen = set()
rows = []
for root in roots:
    for candidate in iter_candidates(root):
        try:
            real = str(candidate.resolve())
        except OSError:
            real = str(candidate)
        if real in seen:
            continue
        seen.add(real)
        result = inspect_boot(candidate)
        if result:
            rows.append(result)

rows.sort(key=lambda r: (r["path"].lower(), r["size"]))

lines = [
    "LMI rollback boot candidate scan",
    "",
    "This is a read-only scan. A candidate is not automatically safe to flash.",
    "A rollback boot image must still be matched to the exact device/ROM build.",
    "",
    f"Search roots: {', '.join(str(r) for r in roots)}",
    f"Max boot partition size: {max_boot_partition_size}",
    f"Candidates found: {len(rows)}",
    "",
]

for i, row in enumerate(rows, 1):
    lines.extend([
        f"[{i}] {row['path']}",
        f"    sha256={row['sha256']}",
        f"    size={row['size']}",
        f"    page_size={row['page_size']}",
        f"    kernel_size={row['kernel_size']}",
        f"    ramdisk_size={row['ramdisk_size']}",
        f"    header_version_raw={row['header_version_raw']}",
        "",
    ])

report.write_text("\n".join(lines))
print(f"rollback candidate report: {report}")
print(f"candidates found: {len(rows)}")
PY
