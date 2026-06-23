#!/usr/bin/env bash
set -euo pipefail

copydown_dir=${OUT_DIR:-/tmp/lmi-copydown-r6-bootmem-20260624}
boot_img=${LMI_COPYDOWN_BOOT_IMG:-$copydown_dir/boot-linux-copydown-lmi.img}
manifest=${LMI_COPYDOWN_MANIFEST:-$copydown_dir/boot-linux-copydown-lmi.manifest}
rootfs_img=${LMI_ROOTFS_IMG:-/tmp/postmarketOS-export/xiaomi-lmi.img}
fastboot_bin=${FASTBOOT:-fastboot}

for path in "$boot_img" "$manifest" "$rootfs_img"; do
	[ -f "$path" ] || {
		echo "missing file: $path" >&2
		exit 2
	}
done

out_dir=$(dirname "$boot_img")
OUT_DIR="$out_dir" LMI_COPYDOWN_BOOT_IMG="$boot_img" LMI_COPYDOWN_MANIFEST="$manifest" \
	"$(dirname "$0")/46_verify_lmi_copydown_boot.sh"

getvar() {
	local key=$1
	local output
	set +e
	output=$("$fastboot_bin" getvar "$key" 2>&1)
	local status=$?
	set -e
	printf '%s\n' "$output" | sed -n "s/^$key: //p" | tail -n 1
	return "$status"
}

echo "fastboot device list:"
"$fastboot_bin" devices

product=$(getvar product || true)
unlocked=$(getvar unlocked || true)
is_userspace=$(getvar is-userspace || true)
boot_size_hex=$(getvar partition-size:boot || true)
boot_type=$(getvar partition-type:boot || true)
userdata_size_hex=$(getvar partition-size:userdata || true)
userdata_type=$(getvar partition-type:userdata || true)
current_slot=$(getvar current-slot || true)

boot_img_size=$(stat -c '%s' "$boot_img")
rootfs_img_size=$(stat -c '%s' "$rootfs_img")
boot_img_sha=$(sha256sum "$boot_img" | awk '{print $1}')
rootfs_img_sha=$(sha256sum "$rootfs_img" | awk '{print $1}')
rootfs_expanded_size=$(python3 - "$rootfs_img" <<'PY'
import struct
import sys
from pathlib import Path

data = Path(sys.argv[1]).read_bytes()[:28]
if len(data) < 28:
    raise SystemExit("0")
magic, major, minor, file_hdr_sz, chunk_hdr_sz, blk_sz, total_blks, total_chunks, checksum = struct.unpack("<IHHHHIIII", data)
if magic != 0xED26FF3A:
    print(Path(sys.argv[1]).stat().st_size)
else:
    print(blk_sz * total_blks)
PY
)

errors=()

if [ "$product" != "lmi" ]; then
	errors+=("product must be lmi, got '${product:-<empty>}'")
fi
if [ "$unlocked" != "yes" ]; then
	errors+=("unlocked must be yes, got '${unlocked:-<empty>}'")
fi
if [ "$is_userspace" != "yes" ]; then
	errors+=("is-userspace must be yes for recovery fastbootd, got '${is_userspace:-<empty>}'")
fi
if [ -z "$boot_size_hex" ]; then
	errors+=("missing partition-size:boot")
else
	boot_size_dec=$((boot_size_hex))
	if [ "$boot_img_size" -ge "$boot_size_dec" ]; then
		errors+=("boot image too large for boot partition: $boot_img_size >= $boot_size_dec")
	fi
fi
if [ -z "$userdata_size_hex" ]; then
	errors+=("missing partition-size:userdata")
else
	userdata_size_dec=$((userdata_size_hex))
	if [ "$rootfs_expanded_size" -ge "$userdata_size_dec" ]; then
		errors+=("rootfs expanded size too large for userdata: $rootfs_expanded_size >= $userdata_size_dec")
	fi
fi

cat <<EOF

preflight summary:
product=${product:-}
unlocked=${unlocked:-}
is-userspace=${is_userspace:-}
current-slot=${current_slot:-}
partition-type:boot=${boot_type:-}
partition-size:boot=${boot_size_hex:-}
partition-type:userdata=${userdata_type:-}
partition-size:userdata=${userdata_size_hex:-}
boot_img=$boot_img
boot_img_sha256=$boot_img_sha
boot_img_size=$boot_img_size
rootfs_img=$rootfs_img
rootfs_img_sha256=$rootfs_img_sha
rootfs_img_size=$rootfs_img_size
rootfs_expanded_size=$rootfs_expanded_size
EOF

if [ "${#errors[@]}" -ne 0 ]; then
	echo
	echo "preflight: FAIL"
	for error in "${errors[@]}"; do
		echo "- $error"
	done
	exit 1
fi

cat <<EOF

preflight: OK

No write command was executed.
Exact commands still require fresh approval immediately before use:
  fastboot flash boot $boot_img
  pmbootstrap flasher flash_rootfs --partition userdata

Do not proceed without a known-good rollback boot image and recovery path.
EOF
