#!/usr/bin/env bash
set -euo pipefail

repo=${REPO:-/mnt/c/Users/microstar/Documents/lmi_linx}
unpack_bootimg=${UNPACK_BOOTIMG:-/mnt/c/Users/microstar/Latest\ ADB\ Fastboot\ Tool/lmi/sm8250-xiaomi-lmi-boot/tools/ubuntu-mkbootimg/unpack_bootimg}
v22=${V22_BOOT:-$repo/artifacts/images/pmos-lmi-normalboot-v22-loopdevfix-20260623.img}
v24=${V24_BOOT:-$repo/artifacts/images/pmos-lmi-normalboot-v24-devtmpfs-loopdevfix-currentuserdata-20260623.img}
out=${OUT:-$repo/logs/compare-v22-v24-usb-gadget-2026-06-23.txt}

for file in "$unpack_bootimg" "$v22" "$v24"; do
	[ -f "$file" ] || { echo "missing input: $file" >&2; exit 1; }
done

work=$(mktemp -d /tmp/lmi-usb-compare.XXXXXX)
cleanup() {
	rm -rf -- "$work"
}
trap cleanup EXIT

unpack_one() {
	local name=$1
	local img=$2
	mkdir -p "$work/$name/unpack" "$work/$name/ramdisk"
	python3 "$unpack_bootimg" --boot_img "$img" --out "$work/$name/unpack" \
		>"$work/$name/unpack.log"
	(
		cd "$work/$name/ramdisk"
		gzip -dc "$work/$name/unpack/ramdisk" | cpio -idmu --quiet
	)
}

collect_one() {
	local name=$1
	local root="$work/$name/ramdisk"
	echo "===== $name boot image ====="
	cat "$work/$name/unpack.log"
	echo
	echo "===== $name cmdline markers ====="
	grep -E 'command line args|additional command line args' "$work/$name/unpack.log" || true
	echo
	echo "===== $name USB/gadget matches ====="
	grep -RnsE 'gadget|configfs|rndis|RNDIS|ncm|NCM|ecm|ECM|acm|idVendor|idProduct|18[Dd]1|D001|d001|usb0|172\.16\.42|postmarketos|POSTMARKETOS' \
		"$root/init" "$root/init_2nd.sh" "$root/init_functions.sh" \
		"$root/usr" "$root/etc" "$root/lib" 2>/dev/null | head -240 || true
	echo
	echo "===== $name initramfs.load ====="
	for f in "$root/usr/lib/modules/initramfs.load" "$root/lib/modules/initramfs.load"; do
		[ -f "$f" ] && { echo "--- ${f#$root/}"; cat "$f"; }
	done
	echo
	echo "===== $name module filenames related to USB ====="
	find "$root" -type f \( -name '*usb*' -o -name '*gadget*' -o -name '*rndis*' -o -name '*ncm*' -o -name '*dwc3*' \) \
		-printf '%P\n' | sort | head -160
	echo
}

unpack_one v22 "$v22"
unpack_one v24 "$v24"

{
	echo "v22=$v22"
	echo "v24=$v24"
	echo "v22_sha256=$(sha256sum "$v22" | cut -d' ' -f1)"
	echo "v24_sha256=$(sha256sum "$v24" | cut -d' ' -f1)"
	echo
	collect_one v22
	collect_one v24
	echo "===== diff: init_functions USB/gadget lines ====="
	diff -u \
		<(grep -RnsE 'gadget|configfs|rndis|RNDIS|ncm|NCM|ecm|ECM|acm|idVendor|idProduct|usb0|172\.16\.42' "$work/v22/ramdisk/init_functions.sh" || true) \
		<(grep -RnsE 'gadget|configfs|rndis|RNDIS|ncm|NCM|ecm|ECM|acm|idVendor|idProduct|usb0|172\.16\.42' "$work/v24/ramdisk/init_functions.sh" || true) \
		|| true
} > "$out"

cat "$out"
