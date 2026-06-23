#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=${REPO:-$(dirname "$script_dir")}
tag=${TAG:-20260623}

source_boot=${SOURCE_BOOT:-$repo/artifacts/images/pmos-lmi-normalboot-v28-hwtools-$tag.img}
out_boot=${OUT_BOOT:-$repo/artifacts/images/pmos-lmi-v28-kernel-currentroot-$tag.img}
out_manifest=${OUT_MANIFEST:-$repo/artifacts/images/pmos-lmi-v28-kernel-currentroot-$tag.manifest}
unpack_bootimg=${UNPACK_BOOTIMG:-/mnt/c/Users/microstar/Latest\ ADB\ Fastboot\ Tool/lmi/sm8250-xiaomi-lmi-boot/tools/ubuntu-mkbootimg/unpack_bootimg}
mkbootimg=${MKBOOTIMG:-/mnt/c/Users/microstar/Latest\ ADB\ Fastboot\ Tool/lmi/sm8250-xiaomi-lmi-boot/tools/ubuntu-mkbootimg/mkbootimg}

current_boot_uuid=${CURRENT_BOOT_UUID:?set CURRENT_BOOT_UUID from the running rootfs}
current_root_uuid=${CURRENT_ROOT_UUID:?set CURRENT_ROOT_UUID from the running rootfs}

for file in "$source_boot" "$unpack_bootimg" "$mkbootimg"; do
	[ -f "$file" ] || { echo "missing input: $file" >&2; exit 1; }
done

work=$(mktemp -d /tmp/lmi-pmos-v28-currentroot.XXXXXX)
cleanup() {
	rm -rf -- "$work"
}
trap cleanup EXIT

mkdir -p "$work/unpack"
python3 "$unpack_bootimg" --boot_img "$source_boot" --out "$work/unpack" >"$work/unpack.log"

cmdline="$(sed -n 's/^command line args: //p' "$work/unpack.log")"
[ -n "$cmdline" ] || { echo "missing boot cmdline" >&2; exit 1; }

cmdline="$(printf '%s' "$cmdline" \
	| sed -E "s/pmos_boot_uuid=[^ ]+/pmos_boot_uuid=$current_boot_uuid/" \
	| sed -E "s/pmos_root_uuid=[^ ]+/pmos_root_uuid=$current_root_uuid/")"

python3 "$mkbootimg" \
	--header_version 2 \
	--kernel "$work/unpack/kernel" \
	--ramdisk "$work/unpack/ramdisk" \
	--dtb "$work/unpack/dtb" \
	--pagesize 0x00001000 \
	--base 0x00000000 \
	--kernel_offset 0x00008000 \
	--ramdisk_offset 0x01000000 \
	--second_offset 0x00000000 \
	--tags_offset 0x00000100 \
	--dtb_offset 0x0000000001f00000 \
	--cmdline "$cmdline" \
	--output "$out_boot"

{
	echo "artifact_boot=$(basename "$out_boot")"
	echo "source_boot=$source_boot"
	echo "source_boot_sha256=$(sha256sum "$source_boot" | cut -d' ' -f1)"
	echo "source_kernel_sha256=$(sha256sum "$work/unpack/kernel" | cut -d' ' -f1)"
	echo "source_dtb_sha256=$(sha256sum "$work/unpack/dtb" | cut -d' ' -f1)"
	echo "source_ramdisk_sha256=$(sha256sum "$work/unpack/ramdisk" | cut -d' ' -f1)"
	echo "artifact_boot_sha256=$(sha256sum "$out_boot" | cut -d' ' -f1)"
	echo "artifact_boot_size=$(stat -c %s "$out_boot")"
	echo "current_boot_uuid=$current_boot_uuid"
	echo "current_root_uuid=$current_root_uuid"
	echo "purpose=v28 kernel and ramdisk against current v27 rootfs for RAM-only rmtfs_mem test"
	echo "cmdline=$cmdline"
} > "$out_manifest"

cat "$out_manifest"
