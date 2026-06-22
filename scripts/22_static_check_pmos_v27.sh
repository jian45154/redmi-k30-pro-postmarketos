#!/usr/bin/env bash
set -euo pipefail

repo=${REPO:-/mnt/c/Users/microstar/Documents/lmi_linx}
boot=${BOOT:-$repo/artifacts/images/pmos-lmi-normalboot-v27-rndis-usbid-loopdevfix-20260623.img}
userdata=${USERDATA:-$repo/artifacts/images/xiaomi-lmi-v27-rndis-usbid-userdata-20260623.img}
manifest=${MANIFEST:-$repo/artifacts/images/pmos-lmi-v27-rndis-usbid-full-20260623.manifest}
unpack_bootimg=${UNPACK_BOOTIMG:-/mnt/c/Users/microstar/Latest\ ADB\ Fastboot\ Tool/lmi/sm8250-xiaomi-lmi-boot/tools/ubuntu-mkbootimg/unpack_bootimg}

for file in "$boot" "$userdata" "$manifest" "$unpack_bootimg"; do
	[ -f "$file" ] || { echo "missing input: $file" >&2; exit 1; }
done

work=$(mktemp -d /tmp/lmi-pmos-v27-check.XXXXXX)
cleanup() {
	rm -rf -- "$work"
}
trap cleanup EXIT

echo "=== manifest ==="
cat "$manifest"

echo "=== file sizes ==="
stat -c '%n %s' "$boot" "$userdata"

echo "=== userdata fdisk 4096 ==="
fdisk -b 4096 -l "$userdata"

echo "=== userdata labels ==="
strings -a "$userdata" | grep -E 'pmOS_boot|pmOS_root' | sort -u

mkdir -p "$work/unpack" "$work/ramdisk"
python3 "$unpack_bootimg" --boot_img "$boot" --out "$work/unpack" >"$work/unpack.log"
(
	cd "$work/ramdisk"
	gzip -dc "$work/unpack/ramdisk" | cpio -idmu --quiet
)

echo "=== boot cmdline ==="
grep 'command line args' "$work/unpack.log"

echo "=== ramdisk deviceinfo ==="
grep -nE 'deviceinfo_rootfs_image_sector_size|deviceinfo_usb_' \
	"$work/ramdisk/usr/share/deviceinfo/device-xiaomi-lmi"

echo "=== loopdev fix markers ==="
grep -nE 'lmi_populate_block_devs|_lmi_fdisk_block_size|_lmi_loop_name|fdisk \$_lmi_fdisk_block_size' \
	"$work/ramdisk/init_functions.sh"

echo "=== sha256 ==="
sha256sum "$boot" "$userdata" "$manifest"
