#!/usr/bin/env bash
set -euo pipefail

repo=${REPO:-/mnt/c/Users/microstar/Documents/lmi_linx}
v26=${V26:-$repo/artifacts/images/pmos-lmi-normalboot-v26-rndis-usbid-currentuserdata-20260623.img}
v27=${V27:-$repo/artifacts/images/pmos-lmi-normalboot-v27-rndis-usbid-loopdevfix-currentuserdata-20260623.img}
unpack_bootimg=${UNPACK_BOOTIMG:-/mnt/c/Users/microstar/Latest\ ADB\ Fastboot\ Tool/lmi/sm8250-xiaomi-lmi-boot/tools/ubuntu-mkbootimg/unpack_bootimg}

for file in "$v26" "$v27" "$unpack_bootimg"; do
	[ -f "$file" ] || { echo "missing input: $file" >&2; exit 1; }
done

work=$(mktemp -d /tmp/lmi-v26-v27-diff.XXXXXX)
cleanup() {
	rm -rf -- "$work"
}
trap cleanup EXIT

for version in v26 v27; do
	mkdir -p "$work/$version/u" "$work/$version/r"
done

python3 "$unpack_bootimg" --boot_img "$v26" --out "$work/v26/u" >"$work/v26/unpack.log"
python3 "$unpack_bootimg" --boot_img "$v27" --out "$work/v27/u" >"$work/v27/unpack.log"

(
	cd "$work/v26/r"
	gzip -dc "$work/v26/u/ramdisk" | cpio -idmu --quiet
)
(
	cd "$work/v27/r"
	gzip -dc "$work/v27/u/ramdisk" | cpio -idmu --quiet
)

echo "=== cmdline ==="
grep 'command line args' "$work/v26/unpack.log"
grep 'command line args' "$work/v27/unpack.log"

echo "=== deviceinfo diff ==="
diff -u "$work/v26/r/usr/share/deviceinfo/device-xiaomi-lmi" \
	"$work/v27/r/usr/share/deviceinfo/device-xiaomi-lmi" || true

echo "=== init_functions markers ==="
for version in v26 v27; do
	echo "--- $version"
	grep -nE 'mount_subpartitions|lmi_populate_block_devs|losetup|find_partition|PMOS_ROOT|PMOS_BOOT|debug_shell|telnet|udhcpd|usb' \
		"$work/$version/r/init_functions.sh" | head -140 || true
done

echo "=== file list diff maxdepth3 ==="
(
	cd "$work/v26/r"
	find . -maxdepth 3 -type f | sort
) >"$work/v26.files"
(
	cd "$work/v27/r"
	find . -maxdepth 3 -type f | sort
) >"$work/v27.files"
diff -u "$work/v26.files" "$work/v27.files" | sed -n '1,260p' || true

echo "=== key file sha256 ==="
for file in init init_functions.sh init.sh usr/share/deviceinfo/device-xiaomi-lmi; do
	echo "--- $file"
	sha256sum "$work/v26/r/$file" "$work/v27/r/$file" 2>/dev/null || true
done

echo "=== init_functions diff around mount_subpartitions ==="
diff -u "$work/v26/r/init_functions.sh" "$work/v27/r/init_functions.sh" | sed -n '1,260p' || true
