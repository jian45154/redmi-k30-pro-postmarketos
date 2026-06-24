#!/usr/bin/env bash
set -euo pipefail

out_dir=${OUT_DIR:-/tmp/lmi-copydown-r5-20260624}
manifest=${LMI_COPYDOWN_MANIFEST:-$out_dir/boot-linux-copydown-lmi.manifest}
boot_img=${LMI_COPYDOWN_BOOT_IMG:-$out_dir/boot-linux-copydown-lmi.img}

for path in "$manifest" "$boot_img"; do
	[ -f "$path" ] || {
		echo "missing file: $path" >&2
		exit 2
	}
done

python3 - "$manifest" "$boot_img" <<'PY'
import hashlib
import struct
import sys
from pathlib import Path

manifest = Path(sys.argv[1])
boot_img = Path(sys.argv[2])

values = {}
for raw_line in manifest.read_text().splitlines():
    if not raw_line or "=" not in raw_line:
        continue
    key, value = raw_line.split("=", 1)
    values[key] = value

required = {
    "stage": "M2j",
    "payload": "linux-copydown-shim-embedded-runtime-dtb",
    "x0": "embedded_runtime_dtb",
    "outer_text_offset": "0x80000",
    "outer_magic": "b'ARMd'",
    "outer_pe_offset_res5": "0x0",
    "linux_source_alignment_ok": "True",
    "copy_entry_outside_destination": "True",
    "copy_overlap_safe": "True",
    "linux_magic": "b'ARMd'",
    "linux_pe_offset_res5": "0x0",
    "boot_size_ok": "True",
}

errors = []
for key, expected in required.items():
    actual = values.get(key)
    if actual != expected:
        errors.append(f"{key}: expected {expected}, got {actual}")

for key in [
    "boot_img_sha256",
    "boot_img_size",
    "boot_partition_size",
    "runtime_dtb_sha256",
    "stock_header_dtb_sha256",
]:
    if key not in values:
        errors.append(f"missing manifest key: {key}")

data = boot_img.read_bytes()
actual_boot_sha = hashlib.sha256(data).hexdigest()
if values.get("boot_img_sha256") != actual_boot_sha:
    errors.append(
        f"boot_img_sha256 mismatch: manifest {values.get('boot_img_sha256')} actual {actual_boot_sha}"
    )

try:
    manifest_boot_size = int(values.get("boot_img_size", "-1"), 0)
    boot_partition_size = int(values.get("boot_partition_size", "-1"), 0)
except ValueError as exc:
    errors.append(f"invalid size value: {exc}")
    manifest_boot_size = -1
    boot_partition_size = -1

if manifest_boot_size != len(data):
    errors.append(f"boot_img_size mismatch: manifest {manifest_boot_size} actual {len(data)}")
if boot_partition_size > 0 and len(data) >= boot_partition_size:
    errors.append(f"boot image too large: {len(data)} >= {boot_partition_size}")

if len(data) < 4096 + 64:
    errors.append("boot image too small to inspect")
else:
    if data[:8] != b"ANDROID!":
        errors.append(f"android boot magic mismatch: {data[:8]!r}")
    kernel_size = struct.unpack_from("<I", data, 8)[0]
    ramdisk_size = struct.unpack_from("<I", data, 16)[0]
    page_size = struct.unpack_from("<I", data, 8 + 7 * 4)[0]
    if page_size != 4096:
        errors.append(f"page_size: expected 4096, got {page_size}")
    kernel = data[page_size:page_size + kernel_size]
    if len(kernel) < 64:
        errors.append("kernel payload too small to inspect")
    else:
        if kernel[:2] != b"\x1f\x8b":
            errors.append("kernel payload is not gzip-compressed copydown shim")
    if ramdisk_size <= 0:
        errors.append(f"ramdisk_size invalid: {ramdisk_size}")

if errors:
    print("copydown boot verification: FAIL")
    for error in errors:
        print(f"- {error}")
    raise SystemExit(1)

print("copydown boot verification: OK")
print(f"boot_img={boot_img}")
print(f"boot_img_sha256={actual_boot_sha}")
print(f"boot_img_size={len(data)}")
print(f"boot_partition_size={boot_partition_size}")
print(f"outer_text_offset={values['outer_text_offset']}")
print(f"runtime_dtb_sha256={values['runtime_dtb_sha256']}")
PY
