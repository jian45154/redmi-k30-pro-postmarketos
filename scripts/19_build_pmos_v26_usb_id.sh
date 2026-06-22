#!/usr/bin/env bash
set -euo pipefail

repo=${REPO:-/mnt/c/Users/microstar/Documents/lmi_linx}
source_boot=${SOURCE_BOOT:-$repo/artifacts/images/pmos-lmi-normalboot-v25-rndis-loopdevfix-currentuserdata-20260623.img}
unpack_bootimg=${UNPACK_BOOTIMG:-/mnt/c/Users/microstar/Latest\ ADB\ Fastboot\ Tool/lmi/sm8250-xiaomi-lmi-boot/tools/ubuntu-mkbootimg/unpack_bootimg}
mkbootimg=${MKBOOTIMG:-/mnt/c/Users/microstar/Latest\ ADB\ Fastboot\ Tool/lmi/sm8250-xiaomi-lmi-boot/tools/ubuntu-mkbootimg/mkbootimg}
out_img=${OUT_IMG:-$repo/artifacts/images/pmos-lmi-normalboot-v26-rndis-usbid-currentuserdata-20260623.img}
out_manifest=${OUT_MANIFEST:-$repo/artifacts/images/pmos-lmi-normalboot-v26-rndis-usbid-currentuserdata-20260623.manifest}

for file in "$source_boot" "$unpack_bootimg" "$mkbootimg"; do
	[ -f "$file" ] || { echo "missing input: $file" >&2; exit 1; }
done

work=$(mktemp -d /tmp/lmi-pmos-v26-build.XXXXXX)
cleanup() {
	rm -rf -- "$work"
}
trap cleanup EXIT

mkdir -p "$work/unpack" "$work/ramdisk"
python3 "$unpack_bootimg" --boot_img "$source_boot" --out "$work/unpack" >"$work/unpack.log"
(
	cd "$work/ramdisk"
	gzip -dc "$work/unpack/ramdisk" | cpio -idmu --quiet
)

deviceinfo="$work/ramdisk/usr/share/deviceinfo/device-xiaomi-lmi"
grep -q '^deviceinfo_usb_network_function="rndis.usb0"$' "$deviceinfo"

for key in deviceinfo_usb_idVendor deviceinfo_usb_idProduct; do
	sed -i "/^$key=/d" "$deviceinfo"
done

cat >> "$deviceinfo" <<'EOF'
deviceinfo_usb_idVendor="0x0525"
deviceinfo_usb_idProduct="0xA4A2"
EOF

grep -q '^deviceinfo_usb_idVendor="0x0525"$' "$deviceinfo"
grep -q '^deviceinfo_usb_idProduct="0xA4A2"$' "$deviceinfo"
grep -q '^deviceinfo_usb_network_function="rndis.usb0"$' "$deviceinfo"
grep -q 'lmi_populate_block_devs() {' "$work/ramdisk/init_functions.sh"
grep -q '_lmi_fdisk_block_size' "$work/ramdisk/init_functions.sh"
grep -q '_lmi_loop_name' "$work/ramdisk/init_functions.sh"

(
	cd "$work/ramdisk"
	find . -exec touch -h -d '@0' {} +
	find . -print0 | LC_ALL=C sort -z | cpio --null -o --format=newc --owner=0:0 --reproducible --quiet | gzip -9 > "$work/v26-ramdisk.gz"
)

cmdline="$(sed -n 's/^command line args: //p' "$work/unpack.log")"
[ -n "$cmdline" ] || { echo "missing boot cmdline" >&2; exit 1; }

python3 "$mkbootimg" \
	--header_version 2 \
	--kernel "$work/unpack/kernel" \
	--ramdisk "$work/v26-ramdisk.gz" \
	--dtb "$work/unpack/dtb" \
	--pagesize 0x00001000 \
	--base 0x00000000 \
	--kernel_offset 0x00008000 \
	--ramdisk_offset 0x01000000 \
	--second_offset 0x00000000 \
	--tags_offset 0x00000100 \
	--dtb_offset 0x0000000001f00000 \
	--cmdline "$cmdline" \
	--output "$out_img"

{
	echo "artifact=$(basename "$out_img")"
	echo "source_boot=$source_boot"
	echo "source_boot_sha256=$(sha256sum "$source_boot" | cut -d' ' -f1)"
	echo "kernel_sha256=$(sha256sum "$work/unpack/kernel" | cut -d' ' -f1)"
	echo "dtb_sha256=$(sha256sum "$work/unpack/dtb" | cut -d' ' -f1)"
	echo "source_ramdisk_sha256=$(sha256sum "$work/unpack/ramdisk" | cut -d' ' -f1)"
	echo "v26_ramdisk_sha256=$(sha256sum "$work/v26-ramdisk.gz" | cut -d' ' -f1)"
	echo "artifact_sha256=$(sha256sum "$out_img" | cut -d' ' -f1)"
	echo "artifact_size=$(stat -c %s "$out_img")"
	echo "userdata_pairing=current-v22-userdata"
	echo "deviceinfo_usb_network_function=rndis.usb0"
	echo "deviceinfo_usb_idVendor=0x0525"
	echo "deviceinfo_usb_idProduct=0xA4A2"
	echo "cmdline=$cmdline"
} > "$out_manifest"

cat "$out_manifest"
