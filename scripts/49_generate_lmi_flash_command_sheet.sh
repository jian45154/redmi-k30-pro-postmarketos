#!/usr/bin/env bash
set -euo pipefail

bundle_dir=${LMI_RELEASE_BUNDLE_DIR:-/tmp/lmi-release-r6-bootmem-20260624}
output=${LMI_FLASH_COMMAND_SHEET:-$bundle_dir/APPROVAL_REQUIRED_COMMANDS.txt}
boot_img=${LMI_COPYDOWN_BOOT_IMG:-$bundle_dir/boot-linux-copydown-lmi-r6-bootmem.img}
manifest=${LMI_COPYDOWN_MANIFEST:-$bundle_dir/boot-linux-copydown-lmi-r6-bootmem.manifest}
rootfs_img=${LMI_ROOTFS_IMG:-$bundle_dir/xiaomi-lmi-r6-bootmem.img}
stock_boot=${LMI_ROLLBACK_BOOT_IMG:-}

for path in "$boot_img" "$manifest" "$rootfs_img"; do
	[ -f "$path" ] || {
		echo "missing file: $path" >&2
		exit 2
	}
done

if [ -n "$stock_boot" ] && [ ! -f "$stock_boot" ]; then
	echo "missing rollback boot image: $stock_boot" >&2
	exit 2
fi

sheet_dir=$(dirname "$output")
mkdir -p "$sheet_dir"

boot_sha=$(sha256sum "$boot_img" | awk '{print $1}')
manifest_sha=$(sha256sum "$manifest" | awk '{print $1}')
rootfs_sha=$(sha256sum "$rootfs_img" | awk '{print $1}')
boot_size=$(stat -c '%s' "$boot_img")
rootfs_size=$(stat -c '%s' "$rootfs_img")
rootfs_expanded_size=$(python3 - "$rootfs_img" <<'PY'
import struct
import sys
from pathlib import Path

p = Path(sys.argv[1])
data = p.read_bytes()[:28]
if len(data) < 28:
    print(p.stat().st_size)
    raise SystemExit
magic, major, minor, file_hdr_sz, chunk_hdr_sz, blk_sz, total_blks, total_chunks, checksum = struct.unpack("<IHHHHIIII", data)
if magic == 0xED26FF3A:
    print(blk_sz * total_blks)
else:
    print(p.stat().st_size)
PY
)

rollback_section="Rollback boot image: not provided.
Before any boot partition write, provide LMI_ROLLBACK_BOOT_IMG=/path/to/stock-or-known-good-boot.img and regenerate this sheet."

if [ -n "$stock_boot" ]; then
	stock_boot_sha=$(sha256sum "$stock_boot" | awk '{print $1}')
	stock_boot_size=$(stat -c '%s' "$stock_boot")
	rollback_section="Rollback boot image:
  path: $stock_boot
  sha256: $stock_boot_sha
  size: $stock_boot_size bytes

Rollback command that would also require fresh exact approval:
  fastboot flash boot $stock_boot"
fi

cat > "$output" <<EOF
Xiaomi lmi r6 bootmem approval-required command sheet

Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')

This file is not an approval. It is a command sheet for human review.
Do not run any command below unless the user gives fresh exact approval
immediately before execution.

Required state before any persistent write:
- Device must be in recovery fastbootd.
- fastboot getvar is-userspace must return yes.
- fastboot getvar product must return lmi.
- fastboot getvar unlocked must return yes.
- A known-good rollback boot image and ROM/recovery path must be available.
- Do not touch super, dtbo, vbmeta, persist, modem/EFS/calibration,
  vendor_boot, init_boot, or bootloader relock paths.

Candidate boot image:
  path: $boot_img
  sha256: $boot_sha
  size: $boot_size bytes

Copydown manifest:
  path: $manifest
  sha256: $manifest_sha

Candidate rootfs image:
  path: $rootfs_img
  sha256: $rootfs_sha
  sparse file size: $rootfs_size bytes
  expanded size: $rootfs_expanded_size bytes

$rollback_section

Read-only preflight command:
  LMI_COPYDOWN_BOOT_IMG=$boot_img \\
  LMI_COPYDOWN_MANIFEST=$manifest \\
  LMI_ROOTFS_IMG=$rootfs_img \\
  scripts/48_preflight_lmi_fastbootd.sh

Persistent write commands that require separate fresh exact approvals:
  fastboot flash boot $boot_img
  pmbootstrap flasher flash_rootfs --partition userdata

Suggested order if explicitly approved after preflight passes:
1. Flash rootfs to userdata if the user accepts userdata destruction.
2. Flash boot to boot using the copydown boot image.
3. Reboot and collect evidence by milestone.

No command in this sheet was executed by this script.
EOF

echo "command sheet: $output"
